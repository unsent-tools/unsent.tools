// qr.js — QR code generator, ISO/IEC 18004. Model 2 symbols, versions 1–40,
// error correction levels L/M/Q/H, numeric / alphanumeric / byte (UTF-8)
// modes, automatic mask selection by the standard's four penalty rules.
// Pure functions, no DOM: encode() returns the module matrix; toSvg()
// renders one. Kanji mode and Micro QR are out of scope.

import { EC_BLOCKS, ALIGN_POS } from "./tables.js";

export { EC_BLOCKS, ALIGN_POS };

export class QrError extends Error {}
const fail = (msg) => { throw new QrError(msg); };

export const LEVELS = ["L", "M", "Q", "H"];
// Format-info bit patterns for the levels (ISO 18004 §8.9): L=01 M=00 Q=11 H=10.
const LEVEL_BITS = { L: 1, M: 0, Q: 3, H: 2 };

// ------------------------------------------------------------ GF(256)
// Arithmetic over GF(2^8) with the QR polynomial x^8+x^4+x^3+x^2+1 (0x11d).

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}

const gfMul = (a, b) => (a === 0 || b === 0) ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]];

// Reed-Solomon generator polynomial for `degree` EC codewords:
// (x−α^0)(x−α^1)…(x−α^(degree−1)), returned as coefficient array, leading 1 first.
export function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j]; // poly · x
      next[j + 1] ^= gfMul(poly[j], GF_EXP[i]); // poly · α^i
    }
    poly = next;
  }
  return poly;
}

// Remainder of message·x^degree divided by the generator polynomial —
// the EC codewords for one block.
export function rsRemainder(data, generator) {
  const degree = generator.length - 1;
  const rem = new Uint8Array(degree);
  for (const byte of data) {
    const factor = byte ^ rem[0];
    rem.copyWithin(0, 1);
    rem[degree - 1] = 0;
    for (let i = 0; i < degree; i++) {
      rem[i] ^= gfMul(generator[i + 1], factor);
    }
  }
  return rem;
}

// ------------------------------------------------------------ segments

const ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

// Cheapest single mode that can represent the whole input.
export function chooseMode(text) {
  if (/^[0-9]+$/.test(text)) return "numeric";
  let alnum = text.length > 0;
  for (const ch of text) if (ALNUM.indexOf(ch) < 0) { alnum = false; break; }
  return alnum ? "alphanumeric" : "byte";
}

const MODE_INDICATOR = { numeric: 1, alphanumeric: 2, byte: 4 };

// Character-count indicator width for a mode in a version range (§8.4).
export function countBits(mode, version) {
  const idx = version <= 9 ? 0 : version <= 26 ? 1 : 2;
  return { numeric: [10, 12, 14], alphanumeric: [9, 11, 13], byte: [8, 16, 16] }[mode][idx];
}

class BitBuffer {
  constructor() { this.bits = []; }
  push(value, width) {
    for (let i = width - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }
  get length() { return this.bits.length; }
}

function payloadBits(mode, text, bytes) {
  const buf = new BitBuffer();
  if (mode === "numeric") {
    for (let i = 0; i < text.length; i += 3) {
      const chunk = text.slice(i, i + 3);
      buf.push(parseInt(chunk, 10), chunk.length * 3 + 1);
    }
  } else if (mode === "alphanumeric") {
    for (let i = 0; i + 1 < text.length; i += 2) {
      buf.push(ALNUM.indexOf(text[i]) * 45 + ALNUM.indexOf(text[i + 1]), 11);
    }
    if (text.length % 2) buf.push(ALNUM.indexOf(text[text.length - 1]), 6);
  } else {
    for (const b of bytes) buf.push(b, 8);
  }
  return buf;
}

// Number of "character units" the count indicator holds for a mode.
const charCount = (mode, text, bytes) => mode === "byte" ? bytes.length : text.length;

// Data-codeword capacity in bits for a version + level.
export function capacityBits(version, level) {
  const [, groups] = EC_BLOCKS[version][LEVELS.indexOf(level)];
  let words = 0;
  for (const [n, data] of groups) words += n * data;
  return words * 8;
}

// Total bits a single-segment encoding of the input needs at some version.
function neededBits(mode, text, bytes, version) {
  const payload = payloadBits(mode, text, bytes).length;
  return 4 + countBits(mode, version) + payload;
}

// ------------------------------------------------------------ matrix

function makeMatrix(size) {
  const rows = [];
  for (let i = 0; i < size; i++) rows.push(new Uint8Array(size));
  return rows;
}

// Place the fixed patterns and reservations. Returns {modules, reserved}
// where reserved marks every function-pattern module (data never goes there).
function functionPatterns(version) {
  const size = version * 4 + 17;
  const modules = makeMatrix(size);
  const reserved = makeMatrix(size);

  const set = (row, col, dark) => {
    modules[row][col] = dark ? 1 : 0;
    reserved[row][col] = 1;
  };

  // Finder patterns with separators at three corners.
  for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = r0 + dr, c = c0 + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const dist = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
        set(r, c, dist !== 2 && dist !== 4);
      }
    }
  }

  // Timing patterns.
  for (let i = 8; i < size - 8; i++) {
    if (!reserved[6][i]) set(6, i, i % 2 === 0);
    if (!reserved[i][6]) set(i, 6, i % 2 === 0);
  }

  // Alignment patterns (skip the three that would overlap finders).
  const centres = ALIGN_POS[version];
  for (const r of centres) {
    for (const c of centres) {
      if ((r <= 8 && c <= 8) || (r <= 8 && c >= size - 9) || (r >= size - 9 && c <= 8)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  // Reserve format info areas (drawn later, per mask) and the dark module.
  for (let i = 0; i <= 8; i++) {
    if (!reserved[8][i]) set(8, i, 0);
    if (!reserved[i][8]) set(i, 8, 0);
  }
  for (let i = 0; i < 8; i++) {
    set(8, size - 1 - i, 0);
    set(size - 1 - i, 8, 0);
  }
  set(size - 8, 8, 0); // dark module — reserved now, set dark in assembly

  // Reserve the version-information areas, symbols of version 7 and up.
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const a = size - 11 + (i % 3), b = Math.floor(i / 3);
      set(b, a, 0);
      set(a, b, 0);
    }
  }

  return { modules, reserved, size };
}

// Version information blocks near the top-right and bottom-left finders (§8.10).
function drawVersionInfo(modules, size, version) {
  if (version < 7) return;
  const bits = versionInfoBits(version);
  for (let i = 0; i < 18; i++) {
    const bit = (bits >>> i) & 1;
    const a = size - 11 + (i % 3), b = Math.floor(i / 3);
    modules[b][a] = bit;
    modules[a][b] = bit;
  }
}

// BCH(15,5)-protected format info, XOR-masked with 0x5412 (§8.9).
export function formatInfoBits(level, mask) {
  const data = (LEVEL_BITS[level] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

// BCH(18,6)-protected version info (§8.10).
export function versionInfoBits(version) {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | rem;
}

function drawFormatInfo(modules, size, level, mask) {
  const bits = formatInfoBits(level, mask);
  const bit = (i) => (bits >>> i) & 1;
  // First copy, around the top-left finder.
  for (let i = 0; i <= 5; i++) modules[i][8] = bit(i);
  modules[7][8] = bit(6);
  modules[8][8] = bit(7);
  modules[8][7] = bit(8);
  for (let i = 9; i < 15; i++) modules[8][14 - i] = bit(i);
  // Second copy, split along the right and bottom edges.
  for (let i = 0; i < 8; i++) modules[8][size - 1 - i] = bit(i);
  for (let i = 8; i < 15; i++) modules[size - 15 + i][8] = bit(i);
}

const MASK_FN = [
  (r, c) => (r + c) % 2 === 0,
  (r, c) => r % 2 === 0,
  (r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

// Zigzag placement of the final codeword bit stream (§8.7.3).
function placeData(modules, reserved, size, codewords) {
  let i = 0;
  const total = codewords.length * 8;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let vert = 0; vert < size; vert++) {
      const r = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        if (!reserved[r][c]) {
          // Remainder bits past the last codeword stay light.
          modules[r][c] = i < total ? (codewords[i >>> 3] >>> (7 - (i & 7))) & 1 : 0;
          i++;
        }
      }
    }
  }
}

// ------------------------------------------------------------ penalty

// The four penalty rules of §8.8.2. Lower is better.
export function penalty(modules) {
  const size = modules.length;
  let score = 0;

  // Rule 1: runs of same colour, length 5+, in rows and columns.
  for (let axis = 0; axis < 2; axis++) {
    for (let i = 0; i < size; i++) {
      let run = 1;
      let prev = axis ? modules[0][i] : modules[i][0];
      for (let j = 1; j < size; j++) {
        const cur = axis ? modules[j][i] : modules[i][j];
        if (cur === prev) {
          run++;
          if (j === size - 1 && run >= 5) score += run - 2;
        } else {
          if (run >= 5) score += run - 2;
          run = 1;
          prev = cur;
        }
      }
    }
  }

  // Rule 2: 2×2 blocks of a single colour.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = modules[r][c];
      if (v === modules[r][c + 1] && v === modules[r + 1][c] && v === modules[r + 1][c + 1]) {
        score += 3;
      }
    }
  }

  // Rule 3: 1:1:3:1:1 finder-like pattern (1011101) preceded or followed by
  // a light area 4 modules wide. The symbol's quiet zone is light, so a
  // pattern touching the edge qualifies; a light window clipped by the edge
  // still counts as light. 40 points per occurrence, scanning each line
  // left to right (a counted pattern is skipped over; an uncounted one may
  // still overlap the next candidate).
  const CORE = [1, 0, 1, 1, 1, 0, 1];
  const n3Line = (at) => {
    let sub = 0;
    let idx = 0;
    outer: while (idx + 7 <= size) {
      for (let k = 0; k < 7; k++) {
        if (at(idx + k) !== CORE[k]) { idx++; continue outer; }
      }
      let lightBefore = true, lightAfter = true;
      for (let k = Math.max(idx - 4, 0); k < idx; k++) if (at(k)) lightBefore = false;
      for (let k = idx + 7; k < Math.min(idx + 11, size); k++) if (at(k)) lightAfter = false;
      if (idx === 0 || idx === size - 7 || lightBefore || lightAfter) {
        sub += 40;
        idx += 7;
      } else {
        idx += 4;
      }
    }
    return sub;
  };
  for (let i = 0; i < size; i++) {
    score += n3Line((j) => modules[i][j]);
    score += n3Line((j) => modules[j][i]);
  }

  // Rule 4: deviation of the dark-module proportion from 50%, in 5% steps.
  let dark = 0;
  for (const row of modules) for (const v of row) dark += v;
  score += 10 * Math.floor(Math.abs((dark * 100) / (size * size) - 50) / 5);

  return score;
}

// ------------------------------------------------------------ encode

// encode(text, {level, version, minVersion, mask}) → {
//   matrix, size, version, level, mask, mode,
//   counts: {dataCodewords, ecCodewords, totalCodewords, dataBitsUsed}
// }
// level defaults to "M"; version/mask default to automatic selection.
export function encode(text, opts = {}) {
  const level = opts.level ?? "M";
  if (!LEVELS.includes(level)) fail(`Unknown error-correction level "${level}".`);
  text = String(text);
  if (text.length === 0) fail("Enter something to encode.");

  const mode = chooseMode(text);
  const bytes = mode === "byte" ? new TextEncoder().encode(text) : null;

  // Smallest version whose data capacity fits the encoding.
  let version = null;
  const minVersion = opts.version ?? opts.minVersion ?? 1;
  if (opts.version != null && (opts.version < 1 || opts.version > 40)) {
    fail("Version must be 1–40.");
  }
  for (let v = minVersion; v <= 40; v++) {
    if (neededBits(mode, text, bytes, v) <= capacityBits(v, level)) { version = v; break; }
    if (opts.version != null) break; // fixed version that doesn't fit
  }
  if (version == null) {
    const where = opts.version != null ? `version ${opts.version}` : "version 40";
    fail(`Too long: this input does not fit ${where} at level ${level} (${mode} mode).`);
  }

  // Bit stream: mode, count, payload, terminator, byte padding, pad codewords.
  const buf = new BitBuffer();
  buf.push(MODE_INDICATOR[mode], 4);
  buf.push(charCount(mode, text, bytes), countBits(mode, version));
  const payload = payloadBits(mode, text, bytes);
  buf.bits.push(...payload.bits);
  const capacity = capacityBits(version, level);
  const dataBitsUsed = buf.length;
  buf.push(0, Math.min(4, capacity - buf.length));
  if (buf.length % 8) buf.push(0, 8 - (buf.length % 8));
  const dataWords = [];
  for (let i = 0; i < buf.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | buf.bits[i + j];
    dataWords.push(b);
  }
  for (let pad = 0xec; dataWords.length < capacity / 8; pad ^= 0xfd) dataWords.push(pad);

  // Split into blocks, compute EC per block, interleave (§8.6).
  const [ecPerBlock, groups] = EC_BLOCKS[version][LEVELS.indexOf(level)];
  const gen = rsGeneratorPoly(ecPerBlock);
  const blocks = [];
  let off = 0;
  for (const [n, dataLen] of groups) {
    for (let b = 0; b < n; b++) {
      const data = dataWords.slice(off, off + dataLen);
      off += dataLen;
      blocks.push({ data, ec: rsRemainder(data, gen) });
    }
  }
  const codewords = [];
  const maxData = Math.max(...blocks.map((b) => b.data.length));
  for (let i = 0; i < maxData; i++) {
    for (const b of blocks) if (i < b.data.length) codewords.push(b.data[i]);
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const b of blocks) codewords.push(b.ec[i]);
  }

  // Build the matrix and choose the mask (forced, or best of the 8 penalties).
  const { modules, reserved, size } = functionPatterns(version);
  placeData(modules, reserved, size, codewords);

  // Mask selection (§7.8.3): score each masked matrix before format /
  // version info and the dark module are drawn (the 2015 edition's note on
  // p. 50 excludes them from evaluation); ties go to the lowest pattern.
  const candidates = opts.mask != null ? [opts.mask] : [0, 1, 2, 3, 4, 5, 6, 7];
  if (opts.mask != null && !(opts.mask >= 0 && opts.mask <= 7)) fail("Mask must be 0–7.");
  let best = null;
  for (const m of candidates) {
    const trial = modules.map((row) => row.slice());
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (!reserved[r][c] && MASK_FN[m](r, c)) trial[r][c] ^= 1;
      }
    }
    const score = candidates.length > 1 ? penalty(trial) : 0;
    if (best == null || score < best.score) best = { mask: m, matrix: trial, score };
  }
  drawFormatInfo(best.matrix, size, level, best.mask);
  drawVersionInfo(best.matrix, size, version);
  best.matrix[size - 8][8] = 1; // the dark module (§7.9.1)

  const ecTotal = ecPerBlock * blocks.length;
  return {
    matrix: best.matrix,
    size,
    version,
    level,
    mask: best.mask,
    mode,
    counts: {
      dataCodewords: capacity / 8,
      ecCodewords: ecTotal,
      totalCodewords: capacity / 8 + ecTotal,
      dataBitsUsed,
    },
  };
}

// ------------------------------------------------------------ rendering

// SVG with one path for all dark modules (horizontal runs merged), sized in
// module units and scaled by the viewer; border = quiet zone in modules.
export function toSvg(matrix, opts = {}) {
  const border = opts.border ?? 4;
  const scale = opts.scale ?? 8;
  const dark = opts.dark ?? "#000000";
  const light = opts.light ?? "#ffffff";
  const size = matrix.length;
  const dim = size + border * 2;
  const parts = [];
  for (let r = 0; r < size; r++) {
    let c = 0;
    while (c < size) {
      if (!matrix[r][c]) { c++; continue; }
      let run = 0;
      while (c + run < size && matrix[r][c + run]) run++;
      parts.push(`M${c + border} ${r + border}h${run}v1h-${run}z`);
      c += run;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" ` +
    `width="${dim * scale}" height="${dim * scale}" shape-rendering="crispEdges">` +
    `<rect width="${dim}" height="${dim}" fill="${light}"/>` +
    `<path d="${parts.join("")}" fill="${dark}"/></svg>`;
}

// Plain-text form used by tests and copy-as-text: '#' dark, '.' light.
export function toText(matrix) {
  return matrix.map((row) => Array.from(row, (v) => (v ? "#" : ".")).join("")).join("\n");
}
