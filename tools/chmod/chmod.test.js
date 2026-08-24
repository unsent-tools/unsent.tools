import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, statSync, rmSync, mkdirSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  parseOctal, formatOctal, parseSymbolic, formatSymbolic,
  applySymbolic, describe, warnings,
} from "./chmod.js";

test("octal parse/format basics and errors", () => {
  assert.equal(parseOctal("755"), 0o755);
  assert.equal(parseOctal("0644"), 0o644);
  assert.equal(parseOctal("4755"), 0o4755);
  assert.equal(formatOctal(0o755), "755");
  assert.equal(formatOctal(0o4755), "4755");
  assert.equal(formatOctal(0o7), "007");
  assert.throws(() => parseOctal("758"), /0–7/);
  assert.throws(() => parseOctal("77777"), /1–4 digits/);
  assert.throws(() => parseOctal(""), /1–4 digits/);
});

test("symbolic formatting: pinned ls -l examples", () => {
  assert.equal(formatSymbolic(0o755), "rwxr-xr-x");
  assert.equal(formatSymbolic(0o644), "rw-r--r--");
  assert.equal(formatSymbolic(0o4755), "rwsr-xr-x");
  assert.equal(formatSymbolic(0o4655), "rwSr-xr-x"); // setuid without exec = S
  assert.equal(formatSymbolic(0o2755), "rwxr-sr-x");
  assert.equal(formatSymbolic(0o2745), "rwxr-Sr-x");
  assert.equal(formatSymbolic(0o1777), "rwxrwxrwt");
  assert.equal(formatSymbolic(0o1776), "rwxrwxrwT"); // sticky without exec = T
  assert.equal(formatSymbolic(0), "---------");
});

test("symbolic parse: accepts ls -l 10-char form, rejects junk", () => {
  assert.equal(parseSymbolic("rwxr-xr-x"), 0o755);
  assert.equal(parseSymbolic("-rwxr-xr-x"), 0o755); // pasted ls -l line
  assert.equal(parseSymbolic("drwxrwxrwt"), 0o1777);
  assert.equal(parseSymbolic("rwxr-xr-t"), 0o1755); // t valid in the other slot
  assert.throws(() => parseSymbolic("rwxr-tr-x"), /Position 6/); // ...but not group
  assert.throws(() => parseSymbolic("rwtr-xr-x"), /Position 3/);
  assert.throws(() => parseSymbolic("rwx"), /9 characters/);
  assert.throws(() => parseSymbolic("rxwr-xr-x"), /Position 2/);
});

test("symbolic round-trips for every mode 0..7777", () => {
  for (let mode = 0; mode <= 0o7777; mode++) {
    assert.equal(parseSymbolic(formatSymbolic(mode)), mode, formatOctal(mode));
  }
});

test("applySymbolic: unit cases", () => {
  assert.equal(applySymbolic("u+x", 0o644), 0o744);
  assert.equal(applySymbolic("go-r", 0o644), 0o600);
  assert.equal(applySymbolic("a=r", 0o777), 0o444);
  assert.equal(applySymbolic("u=rwx,go=rx", 0), 0o755);
  assert.equal(applySymbolic("ug+rw", 0), 0o660);
  assert.equal(applySymbolic("o=", 0o777), 0o770); // empty = clears
  assert.equal(applySymbolic("u+r-w", 0o200), 0o400); // multiple ops per clause
  assert.equal(applySymbolic("u+s", 0o755), 0o4755);
  assert.equal(applySymbolic("g+s", 0o755), 0o2755);
  assert.equal(applySymbolic("o+t", 0o777), 0o1777);
  assert.equal(applySymbolic("a-x", 0o4755), 0o4644); // special bits survive -x
  assert.throws(() => applySymbolic("q+x", 0o644), /Can't read clause/);
  assert.throws(() => applySymbolic("", 0o644), /Empty/);
});

test("applySymbolic: X only grants execute when dir or something executable", () => {
  assert.equal(applySymbolic("a+X", 0o644), 0o644);
  assert.equal(applySymbolic("a+X", 0o644, { isDir: true }), 0o755);
  assert.equal(applySymbolic("a+X", 0o744), 0o755); // owner exec already set
});

test("applySymbolic: omitted who honors umask for + and -", () => {
  // GNU chmod: "+x" with umask 022 doesn't grant x to group/other... it does
  // grant where umask allows: umask 022 masks w for group/other, x passes.
  assert.equal(applySymbolic("+w", 0o444, { umask: 0o022 }), 0o644);
  assert.equal(applySymbolic("+x", 0o644, { umask: 0o011 }), 0o744);
  // explicit who ignores umask
  assert.equal(applySymbolic("a+w", 0o444, { umask: 0o022 }), 0o666);
});

test("describe: pinned plain-English output", () => {
  const d = describe(0o640);
  assert.deepEqual(d.lines, [
    "Owner can read and write.",
    "Group members can read.",
    "Everyone else can nothing.",
  ]);
  assert.equal(d.octal, "640");
  assert.equal(d.symbolic, "rw-r-----");
  assert.equal(describe(0o777).lines[0], "Owner can read, write and execute.");
  // special-bit notes
  assert.match(describe(0o4755).special[0], /Setuid: runs with the file owner's/);
  assert.match(describe(0o4655).special[0], /no effect .*capital S/);
  assert.match(describe(0o1777, { isDir: true }).special[0], /standard for \/tmp/);
  assert.match(describe(0o1644).special[0], /ignored on Linux/);
  assert.match(describe(0o2755, { isDir: true }).special[0], /inherit this directory's group/);
});

test("warnings: world-writable, setuid, others-exceed-owner", () => {
  assert.match(warnings(0o666)[0], /World-writable/);
  assert.match(warnings(0o777, { isDir: true })[0], /sticky/);
  assert.equal(warnings(0o1777, { isDir: true }).length, 0);
  assert.match(warnings(0o4755)[0], /privilege-escalation/);
  assert.match(warnings(0o455)[0], /owner lacks/);
  assert.equal(warnings(0o644).length, 0);
});

// Differential test: applySymbolic against the system's real chmod(1).
// GNU semantics are what we implement; skip elsewhere (e.g. BSD/macOS).
const isGnuChmod = (() => {
  try { return execFileSync("chmod", ["--version"]).toString().includes("GNU"); }
  catch { return false; }
})();

test("differential: applySymbolic matches real GNU chmod", { skip: !isGnuChmod }, () => {
  const dir = mkdtempSync(join(tmpdir(), "chmodtest-"));
  try {
    const file = join(dir, "f"), sub = join(dir, "d");
    writeFileSync(file, "");
    mkdirSync(sub);
    const exprs = [
      "u+x", "go-w", "a=r", "u=rwx,go=rx", "ug+rw", "o=", "a+X", "u+s",
      "g+s", "o+t", "a-x", "u+r-w", "=r", "a=", "ugo=rwx", "u-s", "+w", "-x", "=x",
    ];
    const starts = [0, 0o644, 0o755, 0o4755, 0o2645, 0o1777, 0o600, 0o777];
    for (const target of [file, sub]) {
      const isDir = target === sub;
      for (const start of starts) {
        for (const expr of exprs) {
          chmodSync(target, start); // syscall: exact, no CLI numeric-mode quirks
          execFileSync("chmod", [expr, target]);
          const real = statSync(target).mode & 0o7777;
          // real chmod applies the process umask for omitted-who clauses
          const mine = applySymbolic(expr, start, { isDir, umask: process.umask() });
          assert.equal(mine, real,
            `expr "${expr}" on ${isDir ? "dir" : "file"} ${start.toString(8)}: mine ${mine.toString(8)} real ${real.toString(8)}`);
        }
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
