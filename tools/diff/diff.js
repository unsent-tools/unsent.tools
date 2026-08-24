// diff.js — text diff logic for unsent.tools. Pure ES module, no dependencies.
//
// Myers O(ND) shortest-edit-script diff on arbitrary arrays, plus line-level
// diffing (with correct handling of files that lack a trailing newline),
// intraline character highlighting, and unified-diff output that `git apply`
// accepts.
//
// The Myers search is capped: beyond `maxD` edit steps the middle section is
// emitted as one whole-block replacement (still a correct diff, just not
// minimal) and the result is flagged `nonMinimal`. This bounds memory to
// O(maxD^2) regardless of input size.

const defaultEq = (x, y) => x === y;

// Core Myers greedy forward search with trace, on the slice a[a0..a1) vs
// b[b0..b1). Returns an array of ops {type: "equal"|"del"|"ins", ai, bi}
// (indices into the ORIGINAL arrays), or null if no script with at most maxD
// edits exists.
function myers(a, a0, a1, b, b0, b1, eq, maxD) {
  const N = a1 - a0, M = b1 - b0;
  if (N === 0 && M === 0) return [];
  const limit = Math.min(N + M, maxD);
  const offset = limit;
  const v = new Int32Array(2 * limit + 1);
  const snapshots = [];
  let found = false, foundD = 0;

  for (let d = 0; d <= limit; d++) {
    for (let k = -d; k <= d; k += 2) {
      let x;
      if (k === -d || (k !== d && v[offset + k - 1] < v[offset + k + 1])) {
        x = v[offset + k + 1]; // step down: insertion
      } else {
        x = v[offset + k - 1] + 1; // step right: deletion
      }
      let y = x - k;
      while (x < N && y < M && eq(a[a0 + x], b[b0 + y])) { x++; y++; }
      v[offset + k] = x;
      if (x >= N && y >= M) { found = true; foundD = d; break; }
    }
    // ks -d..d of this round, index k + d
    snapshots.push(v.slice(offset - d, offset + d + 1));
    if (found) break;
  }
  if (!found) return null;

  // Backtrack from (N, M).
  const ops = [];
  let x = N, y = M;
  for (let d = foundD; d > 0; d--) {
    const vprev = snapshots[d - 1];
    const get = (k) => vprev[k + (d - 1)];
    const k = x - y;
    let prevK;
    if (k === -d || (k !== d && get(k - 1) < get(k + 1))) prevK = k + 1;
    else prevK = k - 1;
    const prevX = get(prevK);
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) {
      ops.push({ type: "equal", ai: a0 + x - 1, bi: b0 + y - 1 });
      x--; y--;
    }
    if (prevK === k + 1) { ops.push({ type: "ins", ai: -1, bi: b0 + y - 1 }); y--; }
    else { ops.push({ type: "del", ai: a0 + x - 1, bi: -1 }); x--; }
  }
  while (x > 0 && y > 0) {
    ops.push({ type: "equal", ai: a0 + x - 1, bi: b0 + y - 1 });
    x--; y--;
  }
  ops.reverse();
  return ops;
}

// Diff two arrays. Returns { ops, nonMinimal } where ops is a list of
// {type: "equal"|"del"|"ins", ai, bi} referring to indices in a and b.
// Applying the script reconstructs b from a exactly; when nonMinimal is
// false the script is a shortest one.
export function diffArrays(a, b, { eq = defaultEq, maxD = 1500 } = {}) {
  // Trim common prefix/suffix first — cheap, and keeps Myers' D small.
  let p = 0;
  const nMax = Math.min(a.length, b.length);
  while (p < nMax && eq(a[p], b[p])) p++;
  let s = 0;
  while (s < nMax - p && eq(a[a.length - 1 - s], b[b.length - 1 - s])) s++;

  const ops = [];
  for (let i = 0; i < p; i++) ops.push({ type: "equal", ai: i, bi: i });

  const middle = myers(a, p, a.length - s, b, p, b.length - s, eq, maxD);
  let nonMinimal = false;
  if (middle) {
    ops.push(...middle);
  } else {
    nonMinimal = true;
    for (let i = p; i < a.length - s; i++) ops.push({ type: "del", ai: i, bi: -1 });
    for (let i = p; i < b.length - s; i++) ops.push({ type: "ins", ai: -1, bi: i });
  }

  for (let i = s; i > 0; i--) {
    ops.push({ type: "equal", ai: a.length - i, bi: b.length - i });
  }
  return { ops, nonMinimal };
}

// Split text into line records. A line is {t: text} and, for the final line
// of a file with no trailing newline, {t, noNl: true}. Distinguishing that
// case in the record itself makes "same text, different trailing newline"
// compare as a change — which it is.
export function splitLines(text) {
  if (text === "") return [];
  const parts = text.split("\n");
  const lines = [];
  const last = parts.length - 1;
  if (parts[last] === "") {
    for (let i = 0; i < last; i++) lines.push({ t: parts[i] });
  } else {
    for (let i = 0; i < last; i++) lines.push({ t: parts[i] });
    lines.push({ t: parts[last], noNl: true });
  }
  return lines;
}

const lineEq = (x, y) => x.t === y.t && !x.noNl === !y.noNl;

// Line-level diff of two texts. Returns:
//   { ops, stats: {additions, deletions}, nonMinimal }
// ops: {type, text, noNl, aNum, bNum} — aNum/bNum are 1-based line numbers
// (null on the side an ins/del doesn't touch).
export function diffLines(aText, bText, opts = {}) {
  const aL = splitLines(aText);
  const bL = splitLines(bText);
  const { ops: raw, nonMinimal } = diffArrays(aL, bL, { eq: lineEq, ...opts });
  const ops = [];
  let additions = 0, deletions = 0;
  for (const op of raw) {
    if (op.type === "equal") {
      ops.push({ type: "equal", text: aL[op.ai].t, noNl: !!aL[op.ai].noNl,
                 aNum: op.ai + 1, bNum: op.bi + 1 });
    } else if (op.type === "del") {
      deletions++;
      ops.push({ type: "del", text: aL[op.ai].t, noNl: !!aL[op.ai].noNl,
                 aNum: op.ai + 1, bNum: null });
    } else {
      additions++;
      ops.push({ type: "ins", text: bL[op.bi].t, noNl: !!bL[op.bi].noNl,
                 aNum: null, bNum: op.bi + 1 });
    }
  }
  return { ops, stats: { additions, deletions }, nonMinimal };
}

// Unified-diff output for two texts, in the format `git apply` accepts,
// including "\ No newline at end of file" markers. Returns "" when the texts
// are identical.
export function unifiedDiff(aText, bText, { context = 3, aLabel = "a", bLabel = "b", maxD = 1500 } = {}) {
  const { ops } = diffLines(aText, bText, { maxD });
  if (!ops.some((o) => o.type !== "equal")) return "";
  if (context < 0) context = 0;

  // Group ops into hunks: each hunk spans from `context` lines before the
  // first change to `context` lines after the last, and hunks separated by
  // at most 2*context equal lines merge.
  const changeIdx = [];
  for (let i = 0; i < ops.length; i++) if (ops[i].type !== "equal") changeIdx.push(i);
  const hunks = [];
  let start = Math.max(0, changeIdx[0] - context);
  let end = Math.min(ops.length, changeIdx[0] + context + 1);
  for (let c = 1; c < changeIdx.length; c++) {
    const i = changeIdx[c];
    if (i - context <= end) {
      end = Math.min(ops.length, i + context + 1);
    } else {
      hunks.push([start, end]);
      start = i - context;
      end = Math.min(ops.length, i + context + 1);
    }
  }
  hunks.push([start, end]);

  const lines = [`--- ${aLabel}`, `+++ ${bLabel}`];
  const marker = "\\ No newline at end of file";
  for (const [s, e] of hunks) {
    let aStart = null, bStart = null, aCount = 0, bCount = 0;
    for (let i = s; i < e; i++) {
      const op = ops[i];
      if (op.aNum !== null) { aCount++; if (aStart === null) aStart = op.aNum; }
      if (op.bNum !== null) { bCount++; if (bStart === null) bStart = op.bNum; }
    }
    // A side with zero lines reports the line number *before* the hunk.
    if (aStart === null) {
      let prev = 0;
      for (let i = s - 1; i >= 0; i--) if (ops[i].aNum !== null) { prev = ops[i].aNum; break; }
      aStart = prev;
    }
    if (bStart === null) {
      let prev = 0;
      for (let i = s - 1; i >= 0; i--) if (ops[i].bNum !== null) { prev = ops[i].bNum; break; }
      bStart = prev;
    }
    const aPart = aCount === 1 ? `${aStart}` : `${aStart},${aCount}`;
    const bPart = bCount === 1 ? `${bStart}` : `${bStart},${bCount}`;
    lines.push(`@@ -${aPart} +${bPart} @@`);
    for (let i = s; i < e; i++) {
      const op = ops[i];
      const sign = op.type === "equal" ? " " : op.type === "del" ? "-" : "+";
      lines.push(sign + op.text);
      if (op.noNl) lines.push(marker);
    }
  }
  return lines.join("\n") + "\n";
}

// Intraline highlighting for a replaced line pair. Returns
//   { a: [{text, changed}], b: [{text, changed}] }
// with adjacent same-kind segments merged, or null when the lines are too
// dissimilar for highlights to help (fraction of common characters below
// `threshold`).
export function intraline(aLine, bLine, { threshold = 0.35, maxD = 300 } = {}) {
  const a = Array.from(aLine);
  const b = Array.from(bLine);
  const { ops, nonMinimal } = diffArrays(a, b, { maxD });
  if (nonMinimal) return null;
  let common = 0;
  for (const op of ops) if (op.type === "equal") common++;
  if (a.length + b.length > 0 && (2 * common) / (a.length + b.length) < threshold) return null;

  const segs = (side, key) => {
    const out = [];
    for (const op of ops) {
      let ch, changed;
      if (op.type === "equal") { ch = side[op[key]]; changed = false; }
      else if (op.type === "del" && key === "ai") { ch = side[op.ai]; changed = true; }
      else if (op.type === "ins" && key === "bi") { ch = side[op.bi]; changed = true; }
      else continue;
      const last = out[out.length - 1];
      if (last && last.changed === changed) last.text += ch;
      else out.push({ text: ch, changed });
    }
    return out;
  };
  return { a: segs(a, "ai"), b: segs(b, "bi") };
}
