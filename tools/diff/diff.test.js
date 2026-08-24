import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { diffArrays, splitLines, diffLines, unifiedDiff, intraline } from "./diff.js";

// ---------- helpers ----------

// Apply an op script from diffArrays to reconstruct both sides.
function reconstruct(ops, a, b) {
  const outB = [], outA = [];
  for (const op of ops) {
    if (op.type === "equal") { outA.push(a[op.ai]); outB.push(a[op.ai]); }
    else if (op.type === "del") outA.push(a[op.ai]);
    else outB.push(b[op.bi]);
  }
  return { a: outA, b: outB };
}

// Classic DP LCS length — independent oracle for script minimality:
// a shortest edit script has exactly (a.length + b.length - 2*lcs) edits.
function lcsLength(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
  return dp[a.length][b.length];
}

// Deterministic PRNG so property tests are reproducible.
function lcg(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

// ---------- diffArrays ----------

test("diffArrays: Myers paper example is minimal", () => {
  const a = [..."ABCABBA"], b = [..."CBABAC"];
  const { ops, nonMinimal } = diffArrays(a, b);
  assert.equal(nonMinimal, false);
  const edits = ops.filter((o) => o.type !== "equal").length;
  assert.equal(edits, 5); // known shortest edit distance for this pair
  const r = reconstruct(ops, a, b);
  assert.deepEqual(r.a, a);
  assert.deepEqual(r.b, b);
});

test("diffArrays: identical, empty, and one-sided inputs", () => {
  for (const [a, b] of [
    [[], []],
    [["x"], ["x"]],
    [[], ["a", "b"]],
    [["a", "b"], []],
    [["a"], ["b"]],
  ]) {
    const { ops, nonMinimal } = diffArrays(a, b);
    assert.equal(nonMinimal, false);
    const r = reconstruct(ops, a, b);
    assert.deepEqual(r.a, a);
    assert.deepEqual(r.b, b);
    const edits = ops.filter((o) => o.type !== "equal").length;
    assert.equal(edits, a.length + b.length - 2 * lcsLength(a, b));
  }
});

test("diffArrays property: reconstructs both sides and is minimal (500 random pairs)", () => {
  const rnd = lcg(20260823);
  const alphabet = ["a", "b", "c", "d", "e"];
  for (let n = 0; n < 500; n++) {
    const len = () => Math.floor(rnd() * 13);
    const gen = () => Array.from({ length: len() }, () => alphabet[Math.floor(rnd() * alphabet.length)]);
    const a = gen(), b = gen();
    const { ops, nonMinimal } = diffArrays(a, b);
    assert.equal(nonMinimal, false);
    const r = reconstruct(ops, a, b);
    assert.deepEqual(r.a, a, `a mismatch at n=${n}`);
    assert.deepEqual(r.b, b, `b mismatch at n=${n}`);
    const edits = ops.filter((o) => o.type !== "equal").length;
    assert.equal(edits, a.length + b.length - 2 * lcsLength(a, b), `non-minimal at n=${n}`);
  }
});

test("diffArrays: ops are in order and indices consistent", () => {
  const a = [..."kitten"], b = [..."sitting"];
  const { ops } = diffArrays(a, b);
  let ai = 0, bi = 0;
  for (const op of ops) {
    if (op.type !== "ins") { assert.equal(op.ai, ai); ai++; }
    if (op.type !== "del") { assert.equal(op.bi, bi); bi++; }
  }
  assert.equal(ai, a.length);
  assert.equal(bi, b.length);
});

test("diffArrays: maxD cap falls back to block replace, still correct", () => {
  // Force the cap with completely different content and tiny maxD.
  const a = [..."abcdefghij"], b = [..."KLMNOPQRST"];
  const { ops, nonMinimal } = diffArrays(a, b, { maxD: 3 });
  assert.equal(nonMinimal, true);
  const r = reconstruct(ops, a, b);
  assert.deepEqual(r.a, a);
  assert.deepEqual(r.b, b);
});

test("diffArrays: common prefix/suffix trim keeps big same-ish inputs fast", () => {
  const a = Array.from({ length: 50000 }, (_, i) => `line ${i}`);
  const b = a.slice();
  b[25000] = "changed";
  const t0 = process.hrtime.bigint();
  const { ops, nonMinimal } = diffArrays(a, b);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.equal(nonMinimal, false);
  assert.equal(ops.filter((o) => o.type !== "equal").length, 2);
  assert.ok(ms < 2000, `took ${ms}ms`);
});

// ---------- splitLines ----------

test("splitLines: trailing-newline bookkeeping", () => {
  assert.deepEqual(splitLines(""), []);
  assert.deepEqual(splitLines("\n"), [{ t: "" }]);
  assert.deepEqual(splitLines("a\nb\n"), [{ t: "a" }, { t: "b" }]);
  assert.deepEqual(splitLines("a\nb"), [{ t: "a" }, { t: "b", noNl: true }]);
  assert.deepEqual(splitLines("a\n\n"), [{ t: "a" }, { t: "" }]);
});

// ---------- diffLines ----------

test("diffLines: basic change with line numbers and stats", () => {
  const { ops, stats } = diffLines("one\ntwo\nthree\n", "one\n2\nthree\n");
  assert.deepEqual(stats, { additions: 1, deletions: 1 });
  assert.deepEqual(ops, [
    { type: "equal", text: "one", noNl: false, aNum: 1, bNum: 1 },
    { type: "del", text: "two", noNl: false, aNum: 2, bNum: null },
    { type: "ins", text: "2", noNl: false, aNum: null, bNum: 2 },
    { type: "equal", text: "three", noNl: false, aNum: 3, bNum: 3 },
  ]);
});

test("diffLines: same text differing only in trailing newline IS a change", () => {
  const { ops, stats } = diffLines("x\ny", "x\ny\n");
  assert.deepEqual(stats, { additions: 1, deletions: 1 });
  assert.deepEqual(ops[1], { type: "del", text: "y", noNl: true, aNum: 2, bNum: null });
  assert.deepEqual(ops[2], { type: "ins", text: "y", noNl: false, aNum: null, bNum: 2 });
});

test("diffLines: identical texts produce only equal ops", () => {
  const { ops, stats } = diffLines("a\nb\n", "a\nb\n");
  assert.deepEqual(stats, { additions: 0, deletions: 0 });
  assert.ok(ops.every((o) => o.type === "equal"));
});

// ---------- unifiedDiff ----------

test("unifiedDiff: identical texts give empty string", () => {
  assert.equal(unifiedDiff("a\nb\n", "a\nb\n"), "");
});

test("unifiedDiff: pinned simple case", () => {
  const out = unifiedDiff("one\ntwo\nthree\n", "one\n2\nthree\n", { aLabel: "a/f", bLabel: "b/f" });
  assert.equal(out,
    "--- a/f\n" +
    "+++ b/f\n" +
    "@@ -1,3 +1,3 @@\n" +
    " one\n" +
    "-two\n" +
    "+2\n" +
    " three\n");
});

test("unifiedDiff: count of 1 omits the comma part; empty side reports 0", () => {
  const out = unifiedDiff("", "hello\n", { aLabel: "a/f", bLabel: "b/f" });
  assert.equal(out, "--- a/f\n+++ b/f\n@@ -0,0 +1 @@\n+hello\n");
});

test("unifiedDiff: no-newline markers on both sides", () => {
  const out = unifiedDiff("x\ny", "x\ny\n", { aLabel: "a/f", bLabel: "b/f" });
  assert.equal(out,
    "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n x\n-y\n" +
    "\\ No newline at end of file\n+y\n");
});

test("unifiedDiff: distant changes produce two hunks; near changes merge", () => {
  const mk = (arr) => arr.join("\n") + "\n";
  const base = Array.from({ length: 30 }, (_, i) => `l${i + 1}`);
  const far = base.slice(); far[0] = "X"; far[29] = "Y";
  const outFar = unifiedDiff(mk(base), mk(far));
  assert.equal((outFar.match(/^@@ /gm) || []).length, 2);
  const near = base.slice(); near[10] = "X"; near[14] = "Y";
  const outNear = unifiedDiff(mk(base), mk(near));
  assert.equal((outNear.match(/^@@ /gm) || []).length, 1);
});

// The real oracle: git apply must accept our patches and produce exactly B.
test("unifiedDiff: git apply reproduces B (pinned + random cases)", () => {
  const dir = mkdtempSync(join(tmpdir(), "unsent-diff-"));
  try {
    const gitApply = (aText, bText) => {
      const patch = unifiedDiff(aText, bText, { aLabel: "a/f", bLabel: "b/f" });
      writeFileSync(join(dir, "f"), aText);
      if (patch === "") { assert.equal(aText, bText); return; }
      writeFileSync(join(dir, "p.patch"), patch);
      execFileSync("git", ["apply", "-p1", "p.patch"], { cwd: dir });
      assert.equal(readFileSync(join(dir, "f"), "utf8"), bText);
    };

    gitApply("one\ntwo\nthree\n", "one\n2\nthree\n");
    gitApply("", "created\ncontent\n");
    gitApply("gone\n", "");
    gitApply("x\ny", "x\ny\n");        // gains trailing newline
    gitApply("x\ny\n", "x\ny");        // loses trailing newline
    gitApply("a\nb", "c\nd");          // both sides lack trailing newline
    gitApply("same\n", "same\n");

    const rnd = lcg(424242);
    const vocab = ["alpha", "bravo", "charlie", "delta", "", "  indented", "tabs\there"];
    for (let n = 0; n < 60; n++) {
      const gen = () => {
        const k = Math.floor(rnd() * 25);
        let t = Array.from({ length: k }, () => vocab[Math.floor(rnd() * vocab.length)]).join("\n");
        if (k > 0 && rnd() < 0.8) t += "\n";
        return t;
      };
      gitApply(gen(), gen());
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- intraline ----------

test("intraline: highlights the changed span, merges segments", () => {
  const r = intraline("const port = 8080;", "const port = 9090;");
  assert.ok(r);
  assert.equal(r.a.map((s) => s.text).join(""), "const port = 8080;");
  assert.equal(r.b.map((s) => s.text).join(""), "const port = 9090;");
  // minimal diff of 8080 -> 9090 changes each '8' to '9' (LCS is "00")
  assert.deepEqual(r.a.filter((s) => s.changed).map((s) => s.text), ["8", "8"]);
  assert.deepEqual(r.b.filter((s) => s.changed).map((s) => s.text), ["9", "9"]);
});

test("intraline: dissimilar lines return null", () => {
  assert.equal(intraline("completely different text", "zzzz qqqq wwww"), null);
});

test("intraline: astral characters stay intact", () => {
  const r = intraline("say 🎉 now", "say 🎊 now");
  assert.ok(r);
  assert.equal(r.a.map((s) => s.text).join(""), "say 🎉 now");
  assert.equal(r.b.map((s) => s.text).join(""), "say 🎊 now");
  assert.deepEqual(r.a.filter((s) => s.changed).map((s) => s.text), ["🎉"]);
});
