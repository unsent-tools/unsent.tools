// User-Agent string inspector.
//
// Two independent layers:
//
// 1. Identification — an implementation of the ua-parser (uap) matching
//    algorithm over uap-core's regexes.yaml (see data.js, Apache-2.0),
//    mirroring the reference implementation's semantics exactly
//    (ua-parser/uap-python 1.x BasicResolver):
//      - rules tried in order, first regex that matches (unanchored,
//        case-sensitive unless the rule carries regex_flag 'i') wins;
//      - UA family: family_replacement with every literal "$1" replaced by
//        group 1, else group 1; versions: v1..v4_replacement used VERBATIM
//        (no $-templating, no trim) else groups 2..5; empty group -> null.
//      - OS/device fields: template "$1".."$9" -> group or "", then trim,
//        empty -> null. Defaults: os family/v1..v4 = $1..$5; device
//        family/model = $1, brand = null.
//    No match => family "Other" (per spec; fixtures encode it that way).
//
// 2. Structure — a tolerant RFC 9110 §10.1.5 product/comment tokenizer
//    (comments nest; quoted-pair inside comments), plus curated annotations
//    for the tokens' historical baggage and warnings for the places where
//    modern UAs are frozen or deliberately reduced and the string lies:
//    Chrome >=101 sends major.0.0.0; "Windows NT 10.0" covers Windows 11;
//    macOS is capped at 10_15_7 ("Intel" even on Apple Silicon); Chrome on
//    Android >=110 sends "Android 10; K". Sources: Chromium UA-reduction
//    docs and Apple/Mozilla release notes, each verified against real UAs.

import DATA from "./data.js";

// ---------------------------------------------------------------------------
// uap engine

function compile(rule) {
  if (!rule._re) rule._re = new RegExp(rule.r, rule.i ? "i" : "");
  return rule._re;
}

// group idx (1-based) -> string | null; out-of-range, non-participating and
// empty groups are all null (reference: `(m[idx] or None) if idx <= groups`).
function group(m, idx) {
  return idx >= 1 && idx < m.length ? (m[idx] || null) : null;
}

// OS/device replacement: substitute $1..$9, trim, empty -> null.
function template(repl, m) {
  if (!repl) return null;
  const s = repl.replace(/\$(\d)/g, (_, d) => group(m, +d) || "").trim();
  return s || null;
}

export function parseAgent(str) {
  for (const rule of DATA.user_agent_parsers) {
    const m = compile(rule).exec(str);
    if (!m) continue;
    // Python: family.replace("$1", m[1]) replaces ALL occurrences.
    const family = rule.f !== undefined
      ? (rule.f.includes("$1") ? rule.f.split("$1").join(m[1] ?? "") : rule.f)
      : (m[1] ?? null);
    return {
      family,
      major: rule.v1 ?? group(m, 2),
      minor: rule.v2 ?? group(m, 3),
      patch: rule.v3 ?? group(m, 4),
      patchMinor: rule.v4 ?? group(m, 5),
      rule,
    };
  }
  return null;
}

export function parseOs(str) {
  for (const rule of DATA.os_parsers) {
    const m = compile(rule).exec(str);
    if (!m) continue;
    return {
      family: template(rule.f ?? "$1", m),
      major: template(rule.v1 ?? "$2", m),
      minor: template(rule.v2 ?? "$3", m),
      patch: template(rule.v3 ?? "$4", m),
      patchMinor: template(rule.v4 ?? "$5", m),
      rule,
    };
  }
  return null;
}

export function parseDevice(str) {
  for (const rule of DATA.device_parsers) {
    const m = compile(rule).exec(str);
    if (!m) continue;
    return {
      family: template(rule.f ?? "$1", m),
      brand: template(rule.b ?? "", m),
      model: template(rule.m ?? "$1", m),
      rule,
    };
  }
  return null;
}

export function identify(str) {
  return { agent: parseAgent(str), os: parseOs(str), device: parseDevice(str) };
}

export function versionString(r) {
  if (!r) return null;
  const parts = [];
  for (const k of ["major", "minor", "patch", "patchMinor"]) {
    if (r[k] === null || r[k] === undefined) break;
    parts.push(r[k]);
  }
  return parts.length ? parts.join(".") : null;
}

// ---------------------------------------------------------------------------
// structural tokenizer (RFC 9110: product *( RWS ( product / comment ) ))

// Returns { parts, warnings } where parts is a list of
//   { kind: "product", text, name, version, start, end }
//   { kind: "comment", text, inner, segments, start, end, unterminated? }
//   { kind: "junk",    text, start, end }   (anything the grammar rejects)
// segments = top-level ';'-separated pieces of the comment, trimmed.
export function tokenize(str) {
  const parts = [];
  const warnings = [];
  let i = 0;
  const n = str.length;
  while (i < n) {
    const c = str[i];
    if (c === " " || c === "\t") { i++; continue; }
    if (c === "(") {
      const start = i;
      let depth = 0;
      let j = i;
      for (; j < n; j++) {
        const ch = str[j];
        if (ch === "\\" && j + 1 < n) { j++; continue; } // quoted-pair
        if (ch === "(") depth++;
        else if (ch === ")") { depth--; if (depth === 0) break; }
      }
      const unterminated = depth !== 0;
      const end = unterminated ? n : j + 1;
      const inner = str.slice(start + 1, unterminated ? n : j);
      // split top level on ';'
      const segments = [];
      let seg = "", d = 0;
      for (let k = 0; k < inner.length; k++) {
        const ch = inner[k];
        if (ch === "\\" && k + 1 < inner.length) { seg += ch + inner[++k]; continue; }
        if (ch === "(") d++;
        else if (ch === ")") d--;
        if (ch === ";" && d === 0) { segments.push(seg.trim()); seg = ""; }
        else seg += ch;
      }
      segments.push(seg.trim());
      parts.push({ kind: "comment", text: str.slice(start, end), inner,
                   segments: segments.filter((s) => s !== ""), start, end,
                   ...(unterminated && { unterminated: true }) });
      if (unterminated) warnings.push({ id: "unterminated-comment",
        message: "Unclosed '(' — the comment never ends; real parsers disagree on what to do with this." });
      i = end;
      continue;
    }
    if (c === ")") {
      parts.push({ kind: "junk", text: ")", start: i, end: i + 1 });
      warnings.push({ id: "stray-paren", message: "Stray ')' outside any comment." });
      i++;
      continue;
    }
    // product: run of non-space, non-paren chars; version after first '/'
    const start = i;
    while (i < n && str[i] !== " " && str[i] !== "\t" && str[i] !== "(" && str[i] !== ")") i++;
    const text = str.slice(start, i);
    const slash = text.indexOf("/");
    const name = slash === -1 ? text : text.slice(0, slash);
    const version = slash === -1 ? null : text.slice(slash + 1);
    // RFC 9110 token chars; UAs violate this all the time, so just note it
    const tokenOk = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name);
    parts.push({ kind: "product", text, name, version, start, end: i,
                 ...(tokenOk ? {} : { badToken: true }) });
  }
  return { parts, warnings };
}

// ---------------------------------------------------------------------------
// curated annotations — what the tokens actually mean, and where they lie

const PRODUCT_NOTES = [
  [/^Mozilla$/i, (v) => v === "5.0"
    ? "Compatibility fossil. Every major browser claims to be Mozilla/5.0 — a chain of mimicry that started when 1990s sites served better pages to Netscape ('Mozilla') than to Mosaic, and never ended. Carries no information."
    : "The Mozilla token — a 1990s compatibility fossil. Anything other than 5.0 here is itself unusual and marks a very old or hand-made agent."],
  [/^AppleWebKit$/, (v) => v === "537.36"
    ? "Frozen since 2013: 537.36 is the WebKit version at the moment Chrome forked WebKit into Blink. Chrome, Edge, Opera and friends have sent this exact number ever since. It does not mean the browser runs WebKit."
    : "The WebKit engine token; on Safari this still tracks a real (if coarse) WebKit build lineage."],
  [/^Safari$/, (v) => v === "537.36"
    ? "A Blink browser claiming Safari compatibility — frozen at 537.36 like the AppleWebKit token. Real Safari puts its version in the separate Version/x token."
    : "Safari's engine-lineage token. Real Safari's marketing version is in the Version/x token, not here."],
  [/^Version$/, () =>
    "The actual browser version on Safari (and some Android stock browsers) — the one token where Safari states its real version."],
  [/^Chrome$/, (v) => v && /^\d+\.0\.0\.0$/.test(v)
    ? `Reduced UA: only the major version (${v.split(".")[0]}) is real. Since Chrome 101, the rest is a hard-coded "0.0.0" placeholder — real build numbers moved to Client Hints (Sec-CH-UA-Full-Version-List).`
    : "The Chrome token with a full build number — either an older Chrome (<101) or software that chose to send full detail."],
  [/^(HeadlessChrome)$/, () =>
    "Headless (automated) Chrome — Puppeteer, Playwright, and CI browsers send this unless configured to hide it."],
  [/^Gecko$/, (v) => v === "20100101"
    ? "Frozen build-date token: desktop Firefox has sent Gecko/20100101 since 2011 to stop sites from sniffing build dates. The real version is in rv: inside the comment (and the Firefox/x token)."
    : "The Gecko engine token."],
  [/^Firefox$/, () => "Firefox's real version token (mirrors the rv: value in the comment)."],
  [/^(Edg|EdgA|EdgiOS)$/, () =>
    "Chromium-based Edge. Deliberately 'Edg' (not 'Edge') to escape years of sniffing rules written for the old EdgeHTML browser; EdgA = Android, EdgiOS = iOS."],
  [/^Edge$/, () => "Old EdgeHTML-based Microsoft Edge (pre-2020, now retired)."],
  [/^OPR$/, () => "Opera (Chromium-based). Renamed from Opera/ to escape old sniffing rules."],
  [/^(CriOS)$/, () =>
    "Chrome on iOS. Every iOS browser is (as of the App Store rules this string dates from) a shell over Apple's WebKit — CriOS renders with WebKit, not Blink."],
  [/^(FxiOS)$/, () => "Firefox on iOS — a shell over Apple's WebKit, not Gecko."],
  [/^Trident$/, () => "Internet Explorer's engine token (Trident/7.0 = IE 11; the IE version itself hides in rv: inside the comment)."],
  [/^Mobile$/, (v) => v
    ? `Safari's iOS build token (Mobile/${v}); 15E148 has been frozen since iOS 11.3 in many strings.`
    : "Bare 'Mobile' — in Chrome UAs this single word is what distinguishes phone from desktop."],
  [/^(Googlebot|Bingbot|DuckDuckBot|YandexBot|Baiduspider|Applebot)$/i,
    () => "A search-engine crawler token. Anyone can send this string — verify crawler identity by reverse-DNS, never by User-Agent."],
];

const SEGMENT_NOTES = [
  [/^KHTML, like Gecko$/, () =>
    "A two-layer compatibility lie, sent by every WebKit/Blink browser: WebKit began as a fork of KDE's KHTML engine, and 'like Gecko' was added so scripts sniffing for Mozilla's engine would serve the good pages. Firefox does not send it; Chrome and Safari always do."],
  [/^Windows NT 10\.0$/, () =>
    "Frozen platform token: Windows 11 also reports 'Windows NT 10.0' — the UA cannot tell 10 from 11 (browsers expose that only via Client Hints)."],
  [/^Windows NT (\d+\.\d+)$/, (m) => {
    const map = { "6.3": "Windows 8.1", "6.2": "Windows 8", "6.1": "Windows 7",
                  "6.0": "Windows Vista", "5.2": "Windows XP x64/Server 2003", "5.1": "Windows XP" };
    return map[m[1]] ? `Internal NT version — this is ${map[m[1]]}.` : null;
  }],
  [/^Intel Mac OS X 10[._]15[._]7$/, () =>
    "Frozen platform token: since Safari 10.15.7-era, macOS versions above 10.15.7 still report 10_15_7 (Chrome caps it too), and Apple Silicon Macs still say 'Intel'. This token stopped describing the machine in 2020."],
  [/^Intel Mac OS X /, () =>
    "macOS platform token. Note current browsers freeze this at 10_15_7, so a lower value suggests a genuinely old system; 'Intel' appears even on Apple Silicon."],
  [/^Android ([\d.]+)$/, () => null],
  [/^(X11|Win64|WOW64|x64|x86_64|aarch64|arm_64|Linux (x86_64|aarch64|i686))$/, () => null],
  [/^U$/, () =>
    "1990s crypto-strength flag: U meant 'US-grade' (strong) encryption, I international (weak), N none — from when browser exports were munitions-controlled. Modern browsers dropped it in 2010; seeing it marks an old or imitation UA."],
  [/^(I|N)$/, () => null],
  [/^rv:(.+)$/, (m) =>
    `Engine revision. In Firefox this is the real browser version (${m[1]}); IE 11 hid its version here (rv:11.0) after dropping the MSIE token to dodge sniffers.`],
  [/^compatible$/i, () =>
    "The 'compatible' token — historically how IE claimed Mozilla compatibility; today mostly seen in bots imitating that pattern."],
];

// Things worth calling out at the top level.
export function analyze(str) {
  const id = identify(str);
  const structure = tokenize(str);
  const notes = [];    // {target, note} — per token/segment explanations
  const warnings = []; // {id, message}

  for (const p of structure.parts) {
    if (p.kind === "product") {
      for (const [re, fn] of PRODUCT_NOTES) {
        if (re.test(p.name)) {
          const note = fn(p.version);
          if (note) notes.push({ target: p.text, note });
          break;
        }
      }
    } else if (p.kind === "comment") {
      // "Android 10; K" spans two ';'-separated segments — note it as a pair
      const ki = p.segments.findIndex((s, i) => s === "Android 10" && p.segments[i + 1] === "K");
      if (ki !== -1) notes.push({ target: "Android 10; K",
        note: "Reduced UA: since Chrome 110 on Android, every phone reports exactly 'Android 10; K' — the real Android version and device model moved to Client Hints. This phone is almost certainly not running Android 10, and its model is not 'K'." });
      for (const seg of p.segments) {
        if (seg === "K" && ki !== -1) continue;
        for (const [re, fn] of SEGMENT_NOTES) {
          const m = re.exec(seg);
          if (m) {
            const note = fn(m);
            if (note) notes.push({ target: seg, note });
            break;
          }
        }
      }
    }
  }
  warnings.push(...structure.warnings);

  const products = structure.parts.filter((p) => p.kind === "product");
  const comments = structure.parts.filter((p) => p.kind === "comment");
  const segs = comments.flatMap((c) => c.segments);

  // reduced/frozen honesty summary
  const reduced = [];
  const chrome = products.find((p) => /^(Chrome|CriOS)$/.test(p.name));
  if (chrome && chrome.version && /^\d+\.0\.0\.0$/.test(chrome.version))
    reduced.push("browser build (only the major version is real)");
  if (segs.some((s) => /^Windows NT 10\.0$/.test(s)))
    reduced.push("Windows version (10 and 11 both say NT 10.0)");
  if (segs.some((s) => /^Intel Mac OS X 10[._]15[._]7$/.test(s)))
    reduced.push("macOS version (capped at 10_15_7 since 2020) and CPU ('Intel' on Apple Silicon too)");
  if (segs.some((s, i) => s === "Android 10" && segs[i + 1] === "K"))
    reduced.push("Android version and device model ('Android 10; K' is a fixed placeholder)");
  if (reduced.length)
    warnings.push({ id: "reduced-ua",
      message: `Parts of this string are deliberately frozen or reduced and do not describe the real system: ${reduced.join("; ")}.` });

  if (products.some((p) => /^HeadlessChrome$/.test(p.name)))
    warnings.push({ id: "headless", message: "HeadlessChrome: this is an automated browser, not a person." });

  if (id.device && id.device.family === "Spider")
    warnings.push({ id: "bot",
      message: "Identified as a bot/crawler. The claim is unverifiable from the string alone — anyone can send any User-Agent." });

  if (str.length > 0 && !id.agent && !id.os && !id.device)
    warnings.push({ id: "unrecognized",
      message: "No detection rule recognized any part of this string." });

  return { id, structure, notes, warnings };
}
