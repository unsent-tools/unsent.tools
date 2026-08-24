// color.js — parse, convert, and inspect CSS colors. Pure functions, no DOM.
//
// Internal representation: { r, g, b, alpha } with channels as floats where
// 0..1 is the sRGB gamut. Channels may fall OUTSIDE 0..1 when the input was an
// out-of-gamut oklch()/oklab() color; callers decide whether to clamp (see
// inGamut / clampToGamut). Alpha is always clamped to 0..1.
//
// OKLab conversion uses Björn Ottosson's published matrices (the same ones in
// the CSS Color 4 spec). Percent scaling for oklab/oklch components follows
// CSS Color 4: L 100% = 1.0, C 100% = 0.4, a/b 100% = 0.4.

const NAMED_COMPACT = "aliceblue:f0f8ff,antiquewhite:faebd7,aqua:00ffff,aquamarine:7fffd4,azure:f0ffff,beige:f5f5dc,bisque:ffe4c4,black:000000,blanchedalmond:ffebcd,blue:0000ff,blueviolet:8a2be2,brown:a52a2a,burlywood:deb887,cadetblue:5f9ea0,chartreuse:7fff00,chocolate:d2691e,coral:ff7f50,cornflowerblue:6495ed,cornsilk:fff8dc,crimson:dc143c,cyan:00ffff,darkblue:00008b,darkcyan:008b8b,darkgoldenrod:b8860b,darkgray:a9a9a9,darkgreen:006400,darkgrey:a9a9a9,darkkhaki:bdb76b,darkmagenta:8b008b,darkolivegreen:556b2f,darkorange:ff8c00,darkorchid:9932cc,darkred:8b0000,darksalmon:e9967a,darkseagreen:8fbc8f,darkslateblue:483d8b,darkslategray:2f4f4f,darkslategrey:2f4f4f,darkturquoise:00ced1,darkviolet:9400d3,deeppink:ff1493,deepskyblue:00bfff,dimgray:696969,dimgrey:696969,dodgerblue:1e90ff,firebrick:b22222,floralwhite:fffaf0,forestgreen:228b22,fuchsia:ff00ff,gainsboro:dcdcdc,ghostwhite:f8f8ff,gold:ffd700,goldenrod:daa520,gray:808080,green:008000,greenyellow:adff2f,grey:808080,honeydew:f0fff0,hotpink:ff69b4,indianred:cd5c5c,indigo:4b0082,ivory:fffff0,khaki:f0e68c,lavender:e6e6fa,lavenderblush:fff0f5,lawngreen:7cfc00,lemonchiffon:fffacd,lightblue:add8e6,lightcoral:f08080,lightcyan:e0ffff,lightgoldenrodyellow:fafad2,lightgray:d3d3d3,lightgreen:90ee90,lightgrey:d3d3d3,lightpink:ffb6c1,lightsalmon:ffa07a,lightseagreen:20b2aa,lightskyblue:87cefa,lightslategray:778899,lightslategrey:778899,lightsteelblue:b0c4de,lightyellow:ffffe0,lime:00ff00,limegreen:32cd32,linen:faf0e6,magenta:ff00ff,maroon:800000,mediumaquamarine:66cdaa,mediumblue:0000cd,mediumorchid:ba55d3,mediumpurple:9370db,mediumseagreen:3cb371,mediumslateblue:7b68ee,mediumspringgreen:00fa9a,mediumturquoise:48d1cc,mediumvioletred:c71585,midnightblue:191970,mintcream:f5fffa,mistyrose:ffe4e1,moccasin:ffe4b5,navajowhite:ffdead,navy:000080,oldlace:fdf5e6,olive:808000,olivedrab:6b8e23,orange:ffa500,orangered:ff4500,orchid:da70d6,palegoldenrod:eee8aa,palegreen:98fb98,paleturquoise:afeeee,palevioletred:db7093,papayawhip:ffefd5,peachpuff:ffdab9,peru:cd853f,pink:ffc0cb,plum:dda0dd,powderblue:b0e0e6,purple:800080,rebeccapurple:663399,red:ff0000,rosybrown:bc8f8f,royalblue:4169e1,saddlebrown:8b4513,salmon:fa8072,sandybrown:f4a460,seagreen:2e8b57,seashell:fff5ee,sienna:a0522d,silver:c0c0c0,skyblue:87ceeb,slateblue:6a5acd,slategray:708090,slategrey:708090,snow:fffafa,springgreen:00ff7f,steelblue:4682b4,tan:d2b48c,teal:008080,thistle:d8bfd8,tomato:ff6347,turquoise:40e0d0,violet:ee82ee,wheat:f5deb3,white:ffffff,whitesmoke:f5f5f5,yellow:ffff00,yellowgreen:9acd32";

export const NAMED = new Map(
  NAMED_COMPACT.split(",").map((pair) => pair.split(":"))
);

export function hexForName(name) {
  const hex = NAMED.get(name.toLowerCase());
  return hex ? "#" + hex : null;
}

// ---------------------------------------------------------------- parsing

class ColorError extends Error {}
const fail = (msg) => { throw new ColorError(msg); };

// number possibly ending in %, "none" allowed (treated as 0 per CSS Color 4)
function num(token, { pctScale = null, scale = 1, name }) {
  token = token.trim();
  if (token === "none") return 0;
  const m = /^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?(%?)$/i.exec(token);
  if (!m) fail(`Can't read ${name} value "${token}".`);
  const v = parseFloat(token);
  if (m[3] === "%") {
    if (pctScale === null) fail(`A percentage isn't allowed for ${name} here.`);
    return (v / 100) * pctScale;
  }
  return v * scale;
}

// angle: unitless = deg; deg/grad/rad/turn accepted. Returns degrees.
function angle(token, name) {
  token = token.trim();
  if (token === "none") return 0;
  const m = /^([+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)(deg|grad|rad|turn)?$/i.exec(token);
  if (!m) fail(`Can't read ${name} angle "${token}".`);
  const v = parseFloat(m[1]);
  switch ((m[2] || "deg").toLowerCase()) {
    case "deg": return v;
    case "grad": return v * 0.9;
    case "rad": return (v * 180) / Math.PI;
    case "turn": return v * 360;
  }
}

const normHue = (h) => ((h % 360) + 360) % 360;
const clamp01 = (v) => Math.min(1, Math.max(0, v));

function parseAlpha(token) {
  if (token === undefined) return 1;
  return clamp01(num(token, { pctScale: 1, name: "alpha" }));
}

// Split a function body into component tokens + optional alpha, accepting
// both legacy comma syntax and modern space syntax with "/ alpha".
function components(body, fname, want) {
  body = body.trim();
  let parts, alpha;
  if (body.includes(",")) {
    parts = body.split(",").map((s) => s.trim());
    if (parts.some((p) => p === "")) fail(`Empty component in ${fname}().`);
    if (parts.length === want + 1) alpha = parts.pop();
    else if (parts.length !== want) fail(`${fname}() needs ${want} components, got ${parts.length}.`);
  } else {
    const slash = body.split("/");
    if (slash.length > 2) fail(`More than one "/" in ${fname}().`);
    if (slash.length === 2) alpha = slash[1].trim();
    parts = slash[0].trim().split(/\s+/);
    if (parts.length !== want) fail(`${fname}() needs ${want} components, got ${parts.length}.`);
  }
  return { parts, alpha };
}

export function parseHex(str) {
  const m = /^#([0-9a-f]{3,8})$/i.exec(str.trim());
  if (!m) fail("Not a hex color.");
  const h = m[1];
  if (![3, 4, 6, 8].includes(h.length)) {
    fail(`Hex colors have 3, 4, 6, or 8 digits, not ${h.length}.`);
  }
  const long = h.length >= 6 ? h : [...h].map((c) => c + c).join("");
  const byte = (i) => parseInt(long.slice(i, i + 2), 16) / 255;
  return {
    r: byte(0), g: byte(2), b: byte(4),
    alpha: long.length === 8 ? byte(6) : 1,
  };
}

export function parse(str) {
  str = String(str).trim();
  if (str === "") fail("Empty input.");

  if (str.startsWith("#")) return { ...parseHex(str), kind: "hex" };

  const lower = str.toLowerCase();
  if (lower === "transparent") return { r: 0, g: 0, b: 0, alpha: 0, kind: "named" };
  if (NAMED.has(lower)) return { ...parseHex("#" + NAMED.get(lower)), kind: "named" };

  const fn = /^([a-z]+)\s*\(\s*(.*?)\s*\)$/is.exec(str);
  if (!fn) {
    // bare hex without "#" is a common paste; be helpful
    if (/^[0-9a-f]{3}$|^[0-9a-f]{6}$|^[0-9a-f]{8}$/i.test(str)) {
      return { ...parseHex("#" + str), kind: "hex" };
    }
    fail(`Not a recognized color. Try hex (#663399), a name (tomato), or rgb() / hsl() / hwb() / oklch() / oklab().`);
  }
  const fname = fn[1].toLowerCase();
  const body = fn[2];

  switch (fname) {
    case "rgb": case "rgba": {
      const { parts, alpha } = components(body, fname, 3);
      const ch = (t, n) => num(t, { pctScale: 1, scale: 1 / 255, name: n });
      return { r: ch(parts[0], "red"), g: ch(parts[1], "green"), b: ch(parts[2], "blue"),
               alpha: parseAlpha(alpha), kind: "rgb" };
    }
    case "hsl": case "hsla": {
      const { parts, alpha } = components(body, fname, 3);
      const h = normHue(angle(parts[0], "hue"));
      const s = clamp01(num(parts[1], { pctScale: 1, scale: 0.01, name: "saturation" }));
      const l = clamp01(num(parts[2], { pctScale: 1, scale: 0.01, name: "lightness" }));
      return { ...hslToRgb({ h, s, l }), alpha: parseAlpha(alpha), kind: "hsl" };
    }
    case "hwb": {
      const { parts, alpha } = components(body, fname, 3);
      const h = normHue(angle(parts[0], "hue"));
      let w = clamp01(num(parts[1], { pctScale: 1, scale: 0.01, name: "whiteness" }));
      let bk = clamp01(num(parts[2], { pctScale: 1, scale: 0.01, name: "blackness" }));
      if (w + bk > 1) { const sum = w + bk; w /= sum; bk /= sum; } // CSS Color 4 normalization
      return { ...hwbToRgb({ h, w, b: bk }), alpha: parseAlpha(alpha), kind: "hwb" };
    }
    case "oklch": {
      const { parts, alpha } = components(body, fname, 3);
      const L = num(parts[0], { pctScale: 1, name: "lightness" });
      const C = num(parts[1], { pctScale: 0.4, name: "chroma" });
      const h = normHue(angle(parts[2], "hue"));
      if (C < 0) fail("Chroma can't be negative.");
      const rgb = oklabToRgb(oklchToOklab({ L, C, h }));
      return { ...rgb, alpha: parseAlpha(alpha), kind: "oklch" };
    }
    case "oklab": {
      const { parts, alpha } = components(body, fname, 3);
      const L = num(parts[0], { pctScale: 1, name: "lightness" });
      const a = num(parts[1], { pctScale: 0.4, name: "a" });
      const b = num(parts[2], { pctScale: 0.4, name: "b" });
      const rgb = oklabToRgb({ L, a, b });
      return { ...rgb, alpha: parseAlpha(alpha), kind: "oklab" };
    }
    default:
      fail(`Unsupported color function "${fname}()". Supported: rgb, hsl, hwb, oklch, oklab.`);
  }
}

// ------------------------------------------------------- HSL / HWB <-> RGB

export function rgbToHsl({ r, g, b }) {
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  const l = (max + min) / 2, d = max - min;
  let h = 0, s = 0;
  if (d > 1e-12) {
    s = d / (1 - Math.abs(2 * l - 1));
    if (max === r) h = ((g - b) / d) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h = normHue(h * 60);
  }
  return { h, s, l };
}

export function hslToRgb({ h, s, l }) {
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const hp = normHue(h) / 60;
  const x = c * (1 - Math.abs((hp % 2) - 1));
  const m = l - c / 2;
  const [r, g, b] =
    hp < 1 ? [c, x, 0] : hp < 2 ? [x, c, 0] : hp < 3 ? [0, c, x] :
    hp < 4 ? [0, x, c] : hp < 5 ? [x, 0, c] : [c, 0, x];
  return { r: r + m, g: g + m, b: b + m };
}

export function rgbToHwb(rgb) {
  const { h } = rgbToHsl(rgb);
  return { h, w: Math.min(rgb.r, rgb.g, rgb.b), b: 1 - Math.max(rgb.r, rgb.g, rgb.b) };
}

export function hwbToRgb({ h, w, b }) {
  if (w + b >= 1) { const gray = w / (w + b); return { r: gray, g: gray, b: gray }; }
  const pure = hslToRgb({ h, s: 1, l: 0.5 });
  const scale = 1 - w - b;
  return { r: pure.r * scale + w, g: pure.g * scale + w, b: pure.b * scale + w };
}

// ------------------------------------------------------------ OKLab / OKLCH

// Both transfer functions extend to out-of-range values symmetrically
// (mirror the curve through the origin, CSS Color 4 style) so that they stay
// exact inverses of each other even for out-of-gamut channels — clampToGamut
// depends on that to recover L and h faithfully.
const srgbToLinear = (c) =>
  Math.abs(c) <= 0.04045 ? c / 12.92 : Math.sign(c) * Math.pow((Math.abs(c) + 0.055) / 1.055, 2.4);
const linearToSrgb = (c) =>
  Math.abs(c) <= 0.0031308 ? c * 12.92 : Math.sign(c) * (1.055 * Math.pow(Math.abs(c), 1 / 2.4) - 0.055);

export function rgbToOklab({ r, g, b }) {
  const lr = srgbToLinear(r), lg = srgbToLinear(g), lb = srgbToLinear(b);
  const l = Math.cbrt(0.4122214708 * lr + 0.5363325363 * lg + 0.0514459929 * lb);
  const m = Math.cbrt(0.2119034982 * lr + 0.6806995451 * lg + 0.1073969566 * lb);
  const s = Math.cbrt(0.0883024619 * lr + 0.2817188376 * lg + 0.6299787005 * lb);
  return {
    L: 0.2104542553 * l + 0.793617785 * m - 0.0040720468 * s,
    a: 1.9779984951 * l - 2.428592205 * m + 0.4505937099 * s,
    b: 0.0259040371 * l + 0.7827717662 * m - 0.808675766 * s,
  };
}

export function oklabToRgb({ L, a, b }) {
  const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
  return {
    r: linearToSrgb(+4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s),
    g: linearToSrgb(-1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s),
    b: linearToSrgb(-0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s),
  };
}

export function oklabToOklch({ L, a, b }) {
  const C = Math.hypot(a, b);
  // Hue is meaningless at (near-)zero chroma; report 0 for stability. The
  // threshold is well below perceptible chroma but above the float noise that
  // pure grays pick up on the way through the matrices (~1e-8).
  const h = C < 1e-6 ? 0 : normHue((Math.atan2(b, a) * 180) / Math.PI);
  return { L, C, h };
}

export function oklchToOklab({ L, C, h }) {
  const rad = (h * Math.PI) / 180;
  return { L, a: C * Math.cos(rad), b: C * Math.sin(rad) };
}

// ------------------------------------------------------------------- gamut

const GAMUT_EPS = 1e-6;

export function inGamut({ r, g, b }, eps = GAMUT_EPS) {
  return [r, g, b].every((c) => c >= -eps && c <= 1 + eps);
}

// Bring an out-of-gamut color into sRGB the way CSS recommends: keep OKLCH
// lightness and hue, binary-search the largest chroma that fits, then clip
// the residual epsilon.
export function clampToGamut(rgb) {
  const clip = ({ r, g, b }) => ({ r: clamp01(r), g: clamp01(g), b: clamp01(b) });
  if (inGamut(rgb)) return clip(rgb);
  // rgbToOklab handles out-of-range channels (the transfer fn is sign-aware),
  // so take L and h from the ORIGINAL color, not a clipped version.
  const { L, C, h } = oklabToOklch(rgbToOklab(rgb));
  if (L >= 1) return { r: 1, g: 1, b: 1 };
  if (L <= 0) return { r: 0, g: 0, b: 0 };
  let lo = 0, hi = C;
  for (let i = 0; i < 40; i++) {
    const mid = (lo + hi) / 2;
    if (inGamut(oklabToRgb(oklchToOklab({ L, C: mid, h })))) lo = mid;
    else hi = mid;
  }
  return clip(oklabToRgb(oklchToOklab({ L, C: lo, h })));
}

// ------------------------------------------------------- luminance/contrast

// WCAG 2.x relative luminance (expects in-gamut sRGB; clamps to be safe)
export function luminance({ r, g, b }) {
  const lin = (c) => srgbToLinear(clamp01(c));
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

export function contrastRatio(rgb1, rgb2) {
  const l1 = luminance(rgb1), l2 = luminance(rgb2);
  const [hi, lo] = l1 >= l2 ? [l1, l2] : [l2, l1];
  return (hi + 0.05) / (lo + 0.05);
}

// -------------------------------------------------------------- formatting

const round = (v, places) => {
  const p = 10 ** places;
  const r = Math.round(v * p) / p;
  return Object.is(r, -0) ? 0 : r;
};

function alphaSuffix(alpha, sep = " / ") {
  return alpha >= 1 ? "" : `${sep}${round(alpha * 100, 1)}%`;
}

export function formatHex({ r, g, b }, alpha = 1) {
  const byte = (c) => Math.round(clamp01(c) * 255).toString(16).padStart(2, "0");
  return "#" + byte(r) + byte(g) + byte(b) + (alpha < 1 ? byte(alpha) : "");
}

export function formatRgb({ r, g, b }, alpha = 1) {
  const ch = (c) => Math.round(clamp01(c) * 255);
  return `rgb(${ch(r)} ${ch(g)} ${ch(b)}${alphaSuffix(alpha)})`;
}

export function formatHsl(hsl, alpha = 1) {
  return `hsl(${round(hsl.h, 1)} ${round(hsl.s * 100, 1)}% ${round(hsl.l * 100, 1)}%${alphaSuffix(alpha)})`;
}

export function formatHwb(hwb, alpha = 1) {
  return `hwb(${round(hwb.h, 1)} ${round(hwb.w * 100, 1)}% ${round(hwb.b * 100, 1)}%${alphaSuffix(alpha)})`;
}

export function formatOklch({ L, C, h }, alpha = 1) {
  return `oklch(${round(L, 4)} ${round(C, 4)} ${round(h, 2)}${alphaSuffix(alpha)})`;
}

export function formatOklab({ L, a, b }, alpha = 1) {
  return `oklab(${round(L, 4)} ${round(a, 4)} ${round(b, 4)}${alphaSuffix(alpha)})`;
}

// ------------------------------------------------------------- top level

const WHITE = { r: 1, g: 1, b: 1 }, BLACK = { r: 0, g: 0, b: 0 };

export function convert(str) {
  const parsed = parse(str);
  const { alpha, kind } = parsed;
  const raw = { r: parsed.r, g: parsed.g, b: parsed.b };
  const gamut = inGamut(raw);
  const rgb = clampToGamut(raw);
  const oklab = rgbToOklab(rgb);
  const oklch = oklabToOklch(oklab);
  return {
    kind,
    alpha,
    inGamut: gamut,
    rgb,
    luminance: luminance(rgb),
    contrastWhite: contrastRatio(rgb, WHITE),
    contrastBlack: contrastRatio(rgb, BLACK),
    formats: {
      hex: formatHex(rgb, alpha),
      rgb: formatRgb(rgb, alpha),
      hsl: formatHsl(rgbToHsl(rgb), alpha),
      hwb: formatHwb(rgbToHwb(rgb), alpha),
      oklch: formatOklch(oklch, alpha),
      oklab: formatOklab(oklab, alpha),
    },
  };
}
