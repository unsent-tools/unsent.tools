import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parse, parseHex, convert, NAMED,
  rgbToHsl, hslToRgb, rgbToHwb, hwbToRgb,
  rgbToOklab, oklabToRgb, oklabToOklch, oklchToOklab,
  inGamut, clampToGamut, luminance, contrastRatio,
  formatHex, formatRgb, formatHsl, formatOklch,
} from "./color.js";

// deterministic PRNG so failures reproduce
function makeRand(seed) {
  return () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
}

const near = (a, b, eps = 1e-6) =>
  assert.ok(Math.abs(a - b) <= eps, `expected ${a} ≈ ${b} (eps ${eps})`);
const rgbNear = (a, b, eps = 1e-6) => {
  near(a.r, b.r, eps); near(a.g, b.g, eps); near(a.b, b.b, eps);
};

// ---------------------------------------------------------------- parsing

test("hex parsing: 3/4/6/8 digits, case, shorthand expansion", () => {
  assert.deepEqual(parseHex("#663399"), { r: 0x66 / 255, g: 0x33 / 255, b: 0x99 / 255, alpha: 1 });
  rgbNear(parseHex("#639"), parseHex("#663399"));
  near(parseHex("#6639"). alpha, 0x99 / 255);
  near(parseHex("#66339980").alpha, 0x80 / 255);
  assert.equal(parseHex("#FFFFFF").r, 1);
  assert.throws(() => parseHex("#12345"), /3, 4, 6, or 8/);
  assert.throws(() => parseHex("#xyz"), /Not a hex/);
});

test("bare hex without # is accepted (common paste)", () => {
  rgbNear(parse("663399"), parse("#663399"));
  // ...but only for unambiguous lengths; 4-digit bare could be anything
  assert.throws(() => parse("6639"));
});

test("named colors: full table present, spot-checked values", () => {
  assert.equal(NAMED.size, 148);
  assert.equal(parse("rebeccapurple").kind, "named");
  rgbNear(parse("rebeccapurple"), parse("#663399"));
  rgbNear(parse("Tomato"), parse("#ff6347"));
  rgbNear(parse("aliceblue"), parse("#f0f8ff"));
  assert.equal(parse("transparent").alpha, 0);
  assert.throws(() => parse("nonsensecolor"), /Not a recognized color/);
});

test("rgb(): legacy commas, modern spaces, percentages, alpha forms", () => {
  rgbNear(parse("rgb(255, 128, 0)"), { r: 1, g: 128 / 255, b: 0 });
  rgbNear(parse("rgb(255 128 0)"), { r: 1, g: 128 / 255, b: 0 });
  rgbNear(parse("rgb(100% 50% 0%)"), { r: 1, g: 0.5, b: 0 });
  near(parse("rgb(255 0 0 / 50%)").alpha, 0.5);
  near(parse("rgba(255, 0, 0, 0.25)").alpha, 0.25);
  near(parse("rgb(0 0 0 / none)").alpha, 0);
  assert.throws(() => parse("rgb(255 0)"), /needs 3 components/);
  assert.throws(() => parse("rgb(a b c)"), /Can't read/);
});

test("hsl(): angle units, negative hue wraps, clamping", () => {
  rgbNear(parse("hsl(0 100% 50%)"), { r: 1, g: 0, b: 0 });
  rgbNear(parse("hsl(120deg 100% 50%)"), { r: 0, g: 1, b: 0 });
  rgbNear(parse("hsl(0.5turn 100% 50%)"), parse("hsl(180 100% 50%)"));
  rgbNear(parse("hsl(200grad 100% 50%)"), parse("hsl(180 100% 50%)"));
  rgbNear(parse("hsl(-120 100% 50%)"), parse("hsl(240 100% 50%)"));
  rgbNear(parse("hsl(240, 100%, 50%)"), { r: 0, g: 0, b: 1 });
});

test("hwb(): basics and w+b > 100% normalization (CSS Color 4)", () => {
  rgbNear(parse("hwb(0 0% 0%)"), { r: 1, g: 0, b: 0 });
  // w+b >= 1 is achromatic gray at w/(w+b)
  rgbNear(parse("hwb(120 60% 60%)"), { r: 0.5, g: 0.5, b: 0.5 });
  rgbNear(parse("hwb(0 100% 0%)"), { r: 1, g: 1, b: 1 });
});

test("oklch()/oklab(): number and percent scaling per CSS Color 4", () => {
  // 100% chroma = 0.4; 100% lightness = 1.0
  rgbNear(parse("oklch(70% 25% 150)"), parse("oklch(0.7 0.1 150)"));
  rgbNear(parse("oklab(50% 25% -25%)"), parse("oklab(0.5 0.1 -0.1)"));
  assert.throws(() => parse("oklch(0.7 -0.1 30)"), /Chroma/);
});

// ------------------------------------------------- conversion correctness

// Pinned OKLab/OKLCH reference values, verified this session against culori
// (worst |difference| across 2000 random colors: 3.7e-8). Eps 1e-6 leaves
// room for that plus rounding differences.
test("OKLab pinned reference vectors (differential-verified vs culori)", () => {
  const cases = [
    [{ r: 1, g: 0, b: 0 }, { L: 0.6279554, a: 0.2248631, b: 0.1258463 }],
    [{ r: 0, g: 1, b: 0 }, { L: 0.8664396, a: -0.2338876, b: 0.1794985 }],
    [{ r: 0, g: 0, b: 1 }, { L: 0.4520137, a: -0.0324570, b: -0.3115281 }],
    [{ r: 1, g: 1, b: 1 }, { L: 1, a: 0, b: 0 }],
    [{ r: 0x66 / 255, g: 0x33 / 255, b: 0x99 / 255 }, { L: 0.4402718, a: 0.0881768, b: -0.1338643 }],
  ];
  for (const [rgb, ref] of cases) {
    const got = rgbToOklab(rgb);
    near(got.L, ref.L, 1e-6); near(got.a, ref.a, 1e-6); near(got.b, ref.b, 1e-6);
  }
  // OKLCH of rebeccapurple, same source
  const lch = oklabToOklch(rgbToOklab({ r: 0x66 / 255, g: 0x33 / 255, b: 0x99 / 255 }));
  near(lch.C, 0.1602960, 1e-6); near(lch.h, 303.37299, 1e-4);
});

test("achromatic colors get hue 0 in OKLCH, not float noise", () => {
  for (const g of [0, 0.25, 0.5, 1]) {
    assert.equal(oklabToOklch(rgbToOklab({ r: g, g, b: g })).h, 0);
  }
});

test("round-trip properties over seeded random colors", () => {
  const rand = makeRand(42);
  for (let i = 0; i < 500; i++) {
    const c = { r: rand(), g: rand(), b: rand() };
    rgbNear(oklabToRgb(rgbToOklab(c)), c, 1e-5);
    rgbNear(hslToRgb(rgbToHsl(c)), c, 1e-9);
    rgbNear(hwbToRgb(rgbToHwb(c)), c, 1e-9);
    const lab = rgbToOklab(c);
    const back = oklchToOklab(oklabToOklch(lab));
    near(back.a, lab.a, 1e-9); near(back.b, lab.b, 1e-9);
  }
});

test("HSL known values", () => {
  const hsl = rgbToHsl({ r: 0x80 / 255, g: 0x80 / 255, b: 0x80 / 255 });
  assert.equal(hsl.h, 0); assert.equal(hsl.s, 0); near(hsl.l, 0x80 / 255);
  const navy = rgbToHsl(parse("navy"));
  near(navy.h, 240); near(navy.s, 1); near(navy.l, 64 / 255);
});

// ------------------------------------------------------------------ gamut

test("gamut: detection and chroma-preserving clamp", () => {
  assert.ok(inGamut({ r: 0, g: 0.5, b: 1 }));
  const hot = parse("oklch(0.7 0.4 30)"); // far outside sRGB
  assert.ok(!inGamut(hot));
  const clamped = clampToGamut(hot);
  assert.ok(inGamut(clamped));
  // clamp keeps lightness and hue, reduces chroma
  const lch = oklabToOklch(rgbToOklab(clamped));
  near(lch.L, 0.7, 1e-3);
  near(lch.h, 30, 0.1);
  assert.ok(lch.C < 0.4);
  // and is maximal: a touch more chroma leaves gamut
  assert.ok(!inGamut(oklabToRgb(oklchToOklab({ L: lch.L, C: lch.C + 1e-3, h: lch.h }))));
  // in-gamut input passes through unchanged
  rgbNear(clampToGamut({ r: 0.2, g: 0.4, b: 0.6 }), { r: 0.2, g: 0.4, b: 0.6 });
});

test("gamut: extreme lightness snaps to white/black", () => {
  rgbNear(clampToGamut(parse("oklch(1.5 0.2 100)")), { r: 1, g: 1, b: 1 });
  rgbNear(clampToGamut(parse("oklch(-0.2 0.2 100)")), { r: 0, g: 0, b: 0 });
});

// ------------------------------------------------------- contrast (WCAG 2)

test("WCAG contrast: known anchor values", () => {
  const white = { r: 1, g: 1, b: 1 }, black = { r: 0, g: 0, b: 0 };
  near(contrastRatio(white, black), 21);
  near(contrastRatio(white, white), 1);
  assert.equal(contrastRatio(black, white), contrastRatio(white, black));
  // #767676 on white is the canonical "just passes AA (4.5:1)" gray
  const gray = parseHex("#767676");
  const ratio = contrastRatio(gray, white);
  assert.ok(ratio > 4.5 && ratio < 4.6, `got ${ratio}`);
  near(luminance(white), 1);
  near(luminance(black), 0);
});

// -------------------------------------------------------------- formatting

test("format functions produce canonical modern CSS", () => {
  assert.equal(formatHex({ r: 0x66 / 255, g: 0x33 / 255, b: 0x99 / 255 }), "#663399");
  assert.equal(formatHex({ r: 1, g: 0, b: 0 }, 0.5), "#ff000080");
  assert.equal(formatRgb({ r: 1, g: 0.5019607843137255, b: 0 }), "rgb(255 128 0)");
  assert.equal(formatRgb({ r: 1, g: 0, b: 0 }, 0.5), "rgb(255 0 0 / 50%)");
  assert.equal(formatHsl({ h: 120, s: 1, l: 0.25 }), "hsl(120 100% 25%)");
  assert.equal(formatOklch({ L: 0.7, C: 0.1, h: 150 }), "oklch(0.7 0.1 150)");
});

test("format/parse round-trip: strings re-parse to the same color", () => {
  const rand = makeRand(7);
  for (let i = 0; i < 200; i++) {
    const c = { r: rand(), g: rand(), b: rand() };
    const out = convert(formatHex(c)).formats;
    for (const s of [out.rgb, out.hsl, out.hwb, out.oklch, out.oklab]) {
      // hex quantizes to 8 bits; formatted decimals add up to ~0.5/255 more
      rgbNear(parse(s), parse(formatHex(c)), 4e-3);
    }
  }
});

// ---------------------------------------------------------------- convert

test("convert(): end-to-end shape and consistency", () => {
  const r = convert("rebeccapurple");
  assert.equal(r.kind, "named");
  assert.equal(r.formats.hex, "#663399");
  assert.equal(r.inGamut, true);
  assert.equal(r.alpha, 1);
  assert.ok(r.contrastBlack > 1 && r.contrastWhite > 1);
  near(r.contrastWhite * (r.luminance + 0.05), 1.05, 1e-9);

  const out = convert("oklch(0.7 0.4 30)");
  assert.equal(out.inGamut, false);
  assert.ok(inGamut(out.rgb)); // reported rgb is the clamped fallback

  assert.throws(() => convert(""), /Empty input/);
});
