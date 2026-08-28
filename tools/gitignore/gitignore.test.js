// Tests for gitignore.js. Differential oracle: git itself —
// `git check-ignore -v -n -z --no-index --stdin` in a throwaway repo, with
// global/system config neutralized and core.ignorecase=false. The oracle
// reports the deciding pattern AND its line number for every path (negated
// deciders too, for paths that end up not ignored), so the differential
// pins verdict, decider text, and decider line all at once.
// Calibration probes (before implementation) established: matching is
// byte-based ("caf?" does not match "café"); ancestor exclusion is checked
// shallowest-first and its pattern is reported as the decider regardless
// of rule order; "a/**" and "a/*" match the directory "a/" itself; "**"
// not bounded by slashes degrades to "*"; POSIX classes work.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseGitignore, checkPath, lintNegations, patternMatches } from "./gitignore.js";

function rng(seed) {
  let s = seed >>> 0;
  return () => (s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32;
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];

// Run git check-ignore over many (gitignoreText, paths[]) cases in one
// throwaway repo. Returns per case an array of {pattern, line} | null.
function gitOracle(cases) {
  const dir = mkdtempSync(join(tmpdir(), "gi-test-"));
  try {
    execFileSync("git", ["init", "-q", dir]);
    const env = {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
    };
    const results = [];
    for (const c of cases) {
      writeFileSync(join(dir, ".gitignore"), c.text);
      let stdout;
      try {
        stdout = execFileSync(
          "git",
          ["-C", dir, "-c", "core.ignorecase=false", "check-ignore",
           "-v", "-n", "-z", "--no-index", "--stdin"],
          { input: c.paths.join("\0") + "\0", env, maxBuffer: 1 << 24 }
        );
      } catch (e) {
        // exit code 1 just means "no path was ignored"; output is still good
        if (e.status !== 1) throw e;
        stdout = e.stdout;
      }
      const out = stdout.toString("utf8");
      // -z output: source NUL linenum NUL pattern NUL path NUL, repeated
      const f = out.split("\0");
      const res = [];
      for (let i = 0; i + 3 < f.length; i += 4) {
        res.push(f[0 + i] === "" ? null : { pattern: f[i + 2], line: Number(f[i + 1]) });
      }
      assert.equal(res.length, c.paths.length, "oracle output count");
      results.push(res);
    }
    return results;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Our answer in the oracle's terms.
function ours(text, path) {
  const v = checkPath(parseGitignore(text), path);
  if (v.decider === null) return null;
  return { pattern: v.decider.display, line: v.decider.line, ignored: v.ignored };
}

const ignored = (text, path) => checkPath(parseGitignore(text), path).ignored;

// ---------------------------------------------------------------------------

test("pinned semantics from the gitignore(5) man page", () => {
  // the documentation's own foo/bar example
  const doc = "/*\n!/foo\n/foo/*\n!/foo/bar\n";
  assert.equal(ignored(doc, "foo/bar"), false);
  assert.equal(ignored(doc, "foo/baz"), true);
  assert.equal(ignored(doc, "other"), true);
  // "It is not possible to re-include a file if a parent directory of that
  // file is excluded."
  const trap = "sub/\n!sub/keep.txt\n";
  const v = checkPath(parseGitignore(trap), "sub/keep.txt");
  assert.equal(v.ignored, true);
  assert.equal(v.decider.line, 1);
  assert.equal(v.via, "sub");
  assert.equal(v.ineffective.length, 1);
  assert.equal(v.ineffective[0].line, 2);
  // hash and bang escapes
  assert.equal(ignored("\\#lit\n", "#lit"), true);
  assert.equal(ignored("\\!bang\n", "!bang"), true);
  assert.equal(ignored("# comment\n", "# comment"), false);
  // trailing spaces stripped unless escaped
  assert.equal(ignored("trail \n", "trail"), true);
  assert.equal(ignored("sp\\ ace \n", "sp ace"), true);
  // dir-only, anchoring
  assert.equal(ignored("build/\n", "build/"), true);
  assert.equal(ignored("build/\n", "build"), false);
  assert.equal(ignored("build/\n", "src/build/"), true);
  assert.equal(ignored("a/b\n", "a/b"), true);
  assert.equal(ignored("a/b\n", "x/a/b"), false);
  assert.equal(ignored("b\n", "a/b"), true);
  assert.equal(ignored("/c\n", "c"), true);
  assert.equal(ignored("/c\n", "a/c"), false);
});

test("wildcards: *, ?, classes, ** in all positions", () => {
  assert.equal(ignored("a*b\n", "axyb"), true);
  assert.equal(ignored("a*b\n", "a/b"), false);       // * stops at /
  assert.equal(ignored("do?.md\n", "doc.md"), true);
  assert.equal(ignored("do?.md\n", "do/.md"), false); // ? stops at /
  assert.equal(ignored("[a-c].txt\n", "a.txt"), true);
  assert.equal(ignored("[!a-c].txt\n", "a.txt"), false);
  assert.equal(ignored("[!a-c].txt\n", "d.txt"), true);
  assert.equal(ignored("[[:alpha:]].txt\n", "a.txt"), true);
  assert.equal(ignored("[[:alpha:]].txt\n", "1.txt"), false);
  // ** bounded by slashes crosses directories
  assert.equal(ignored("**/foo\n", "a/b/foo"), true);
  assert.equal(ignored("a/**\n", "a/x/y"), true);
  assert.equal(ignored("a/**\n", "a"), false);
  assert.equal(ignored("a/**\n", "a/"), true);        // matches the dir itself
  assert.equal(ignored("a/**/b\n", "a/b"), true);     // zero directories
  assert.equal(ignored("a/**/b\n", "a/x/y/b"), true);
  // unbounded ** degrades to *
  assert.equal(ignored("a**b\n", "axb"), true);
  assert.equal(ignored("a**b\n", "ax/yb"), false);
  // escaped wildcard is literal
  assert.equal(ignored("a\\*b\n", "a*b"), true);
  assert.equal(ignored("a\\*b\n", "axb"), false);
});

test("matching is byte-based, exactly like git", () => {
  // é is two bytes in UTF-8: one ? must not match it, two must
  assert.equal(ignored("caf?\n", "café"), false);
  assert.equal(ignored("caf??\n", "café"), true);
  assert.equal(ignored("caf*\n", "café"), true);
});

test("last match wins; negation; ancestor exclusion walk", () => {
  assert.equal(ignored("*.log\n!keep.log\n", "keep.log"), false);
  assert.equal(ignored("*.log\n!keep.log\n", "a/keep.log"), false);
  assert.equal(ignored("!keep.log\n*.log\n", "keep.log"), true); // order matters
  // negated decider is still reported (as git check-ignore does)
  const nv = ours("*.log\n!keep.log\n", "keep.log");
  assert.deepEqual(nv, { pattern: "!keep.log", line: 2, ignored: false });
  // ancestor decides, shallowest first, regardless of rule order
  assert.deepEqual(ours("*.log\nsub/\n", "sub/x.log"), { pattern: "sub/", line: 2, ignored: true });
  assert.deepEqual(ours("sub/\n*.log\n", "sub/x.log"), { pattern: "sub/", line: 1, ignored: true });
  // un-ignoring the dir re-opens the walk; own rules then decide
  const t = "sub/\n!sub/\n*.log\n";
  assert.deepEqual(ours(t, "sub/x.log"), { pattern: "*.log", line: 3, ignored: true });
  assert.equal(ignored(t, "sub/y.txt"), false);
  // a/* leaves grandchildren alone when the child dir is re-included
  const u = "a/*\n!a/keep\n";
  assert.equal(ignored(u, "a/keep/z"), false);
  assert.equal(ignored(u, "a/d/z"), true);
});

test("directory queries: git's two-stage semantics, pinned by probes", () => {
  // Stage 1: a dir query's own name is the last step of the exclusion
  // walk — normal last-match semantics, so "!sub/" un-ignores it…
  assert.deepEqual(ours("sub/\n!sub/\n*\n", "sub/"), { pattern: "*", line: 3, ignored: true });
  // …with normal last-match semantics inside the walk: a later positive
  // basename pattern re-excludes the dir ("sub" on line 3 wins).
  assert.deepEqual(ours("sub/\n!sub/\nsub\n", "sub/"), { pattern: "sub", line: 3, ignored: true });
  // Stage 2 matches the RAW string "sub/", where basename patterns see an
  // empty basename ("*" matches it) and dir-only patterns are skipped.
  assert.deepEqual(ours("!*/\n", "a/"), null);
  // An anchored pattern can match the trailing-slash string directly,
  // and a negated one is reported just like for files.
  assert.deepEqual(ours("!/a/*\n", "a/"), { pattern: "!/a/*", line: 1, ignored: false });
  assert.deepEqual(ours("/a/\n!/a/\n", "a/"), null);
  // "*/" excludes every directory via the walk
  assert.deepEqual(ours("*/\n", "a/"), { pattern: "*/", line: 1, ignored: true });
  // basename pattern reaches deep dirs through the walk
  assert.equal(ignored("a\n", "b/a/"), true);
  // A bare "!" is a negation with an empty stem. In the self-scan of a
  // directory query the basename is "", which an empty stem matches — so
  // it really overrides earlier positive matches there (git-verified;
  // found by a randomized sweep, not by reading the docs).
  assert.deepEqual(ours("**/a/**\n!\n", "z9/b/a/"), { pattern: "!", line: 2, ignored: false });
  assert.equal(ignored("**/a/**\n!\n", "z9/a/x"), true); // files: basename non-empty
});

test("path input handling", () => {
  const parsed = parseGitignore("build/\n/abs\n");
  const dot = checkPath(parsed, "./build/");
  assert.equal(dot.ignored, true);
  assert.ok(dot.notes.some((s) => s.includes("./")));
  const abs = checkPath(parsed, "/abs");
  assert.equal(abs.ignored, true);
  assert.ok(abs.notes.some((s) => s.includes("relative")));
  assert.equal(checkPath(parsed, "").ignored, null);
});

test("parse warnings and lint", () => {
  const p = parseGitignore("trail  \nnode_modules\nnode_modules\na\\bc\n!\n");
  const codes = p.warnings.map((w) => w.code);
  assert.ok(codes.includes("trailing-space"));
  assert.ok(codes.includes("duplicate"));
  assert.ok(codes.includes("backslash"));
  assert.ok(codes.includes("empty-pattern"));
  // dead negation lint (no test paths needed)
  const lint = lintNegations(parseGitignore("sub/\n!sub/keep.txt\n"));
  assert.equal(lint.length, 1);
  assert.equal(lint[0].line, 2);
  // ...not flagged when the parent was re-included in between
  const ok = lintNegations(parseGitignore("sub/\n!sub/\n!sub/keep.txt\n"));
  assert.equal(ok.length, 0);
  // comments and blanks are inert
  assert.equal(parseGitignore("# c\n\nx\n").patterns.length, 1);
});

test("differential vs git check-ignore: generated corpus", () => {
  const r = rng(20260828);
  const names = ["a", "b", "foo", "bar", "keep", "café", "x.log", "y.txt", "sp ace", "READ-me"];
  const pats = [
    "a", "b", "foo", "bar", "/a", "/foo", "a/b", "a/", "foo/", "b/",
    "*.log", "*.txt", "x.*", "?.log", "[a-f]oo", "[!a-f]oo", "[[:digit:]].txt",
    "**/foo", "a/**", "a/**/b", "foo/**", "a*b", "caf?", "caf??", "caf*",
    "sp\\ ace ", "\\#lit", "READ-me", "/a/b", "b/keep", "*", "*/",
    "/a/*", "a/*", "**/b/", "/*", "**/a/**", "!", "?", "[a-z]/",
  ];
  const cases = [];
  for (let i = 0; i < 120; i++) {
    let text = "";
    const nPat = 1 + Math.floor(r() * 6);
    for (let k = 0; k < nPat; k++) {
      const neg = r() < 0.3 ? "!" : "";
      text += neg + pick(r, pats) + "\n";
      if (r() < 0.15) text += "# comment\n";
      if (r() < 0.1) text += "\n";
    }
    const paths = [];
    for (let k = 0; k < 6; k++) {
      const depth = 1 + Math.floor(r() * 3);
      const segs = [];
      for (let d = 0; d < depth; d++) segs.push(pick(r, names));
      paths.push(segs.join("/") + (r() < 0.3 ? "/" : ""));
    }
    cases.push({ text, paths });
  }
  const oracle = gitOracle(cases);
  let checked = 0;
  cases.forEach((c, i) => {
    const parsed = parseGitignore(c.text);
    c.paths.forEach((path, k) => {
      const want = oracle[i][k];
      const v = checkPath(parsed, path);
      const label = `case ${i} path ${JSON.stringify(path)}\n${c.text}`;
      if (want === null) {
        assert.equal(v.decider, null, label);
        assert.equal(v.ignored, false, label);
      } else {
        assert.ok(v.decider !== null, label);
        assert.equal(v.decider.display, want.pattern, label);
        assert.equal(v.decider.line, want.line, label);
        assert.equal(v.ignored, !want.pattern.startsWith("!"), label);
      }
      checked++;
    });
  });
  assert.equal(checked, 720);
});

test("differential vs git: hand-picked nasty structures", () => {
  const cases = [
    { text: "/*\n!/foo\n/foo/*\n!/foo/bar\n", paths: ["foo/", "foo/bar", "foo/bar/x", "foo/baz", "other", "foo/baz/deep"] },
    { text: "a/\n!a/b/\nc\n", paths: ["a/b/x", "a/c", "c", "x/c/"] },
    { text: "**/node_modules/\n!important/\n", paths: ["node_modules/", "a/node_modules/", "a/node_modules/pkg/index.js", "important/"] },
    { text: "*.log \n!debug.log\nlogs/**\n", paths: ["x.log", "debug.log", "logs/", "logs/debug.log", "logs/a/b"] },
    { text: "[[:upper:]]*\ncaf??\nsp\\ ace\n", paths: ["Readme", "readme", "café", "sp ace", "sp"] },
    { text: "doc/frotz/\nfrotz/\n", paths: ["doc/frotz/", "a/doc/frotz/", "frotz/", "a/frotz/"] },
  ];
  const oracle = gitOracle(cases);
  cases.forEach((c, i) => {
    const parsed = parseGitignore(c.text);
    c.paths.forEach((path, k) => {
      const want = oracle[i][k];
      const v = checkPath(parsed, path);
      const label = `fixture ${i} path ${path}`;
      if (want === null) {
        assert.equal(v.decider, null, label);
        assert.equal(v.ignored, false, label);
      } else {
        assert.equal(v.decider.display, want.pattern, label);
        assert.equal(v.decider.line, want.line, label);
        assert.equal(v.ignored, !want.pattern.startsWith("!"), label);
      }
    });
  });
});
