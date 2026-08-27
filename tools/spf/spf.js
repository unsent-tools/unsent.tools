// Mail DNS policy records: SPF (RFC 7208), DMARC (RFC 9989, with legacy
// RFC 7489 tags), DKIM key records (RFC 6376, RFC 8463), MTA-STS (RFC 8461),
// TLSRPT (RFC 8460). Pure parsing and static analysis — no DNS queries, so
// anything that would need one (include contents, external-destination
// authorization) is reported as unverifiable rather than guessed.

import { parseIPv4 } from "../subnet/subnet.js";
import { parseIPv6 } from "../subnet/subnet6.js";
import { parseElement, content, readOid, readInteger, base64Decode } from "../cert/der.js";

export class RecordError extends Error {}

// ---------------------------------------------------------------------------
// Input normalization: accept a bare record, or dig/zone-file output with
// quoted character-strings (RFC 1035 escapes: \" \\ \DDD). A TXT record split
// into multiple quoted strings is concatenated with no separator (RFC 7208
// §3.3); each input line with quotes is one record.

function unquoteLine(line) {
  const parts = [];
  let i = 0, prefix = null;
  while (i < line.length) {
    if (line[i] === ";" ) break; // zone-file comment
    if (line[i] !== '"') { i++; continue; }
    if (prefix === null) prefix = line.slice(0, i);
    let s = "";
    i++;
    while (i < line.length && line[i] !== '"') {
      if (line[i] === "\\") {
        const m = /^\\(\d{1,3})/.exec(line.slice(i));
        if (m) { s += String.fromCharCode(Number(m[1]) & 0xff); i += m[0].length; continue; }
        i++;
        if (i < line.length) s += line[i++];
        continue;
      }
      s += line[i++];
    }
    if (i >= line.length) throw new RecordError("Unbalanced quote in input line.");
    i++; // closing quote
    parts.push(s);
  }
  if (!parts.length) return null;
  return { record: parts.join(""), strings: parts, prefix: prefix ?? "" };
}

// Owner name from a zone-file/dig prefix like "_dmarc.example.com. 3600 IN TXT".
function ownerFromPrefix(prefix) {
  const tok = prefix.trim().split(/\s+/)[0];
  if (!tok) return null;
  if (/^[A-Za-z0-9_*][A-Za-z0-9_.*-]*\.?$/.test(tok) && tok.includes(".")) {
    return tok.replace(/\.$/, "");
  }
  return null;
}

export function extractRecords(text) {
  const records = [];
  const lines = text.split(/\r?\n/);
  const anyQuotes = /"/.test(text);
  if (anyQuotes) {
    for (const line of lines) {
      if (!line.trim()) continue;
      const q = unquoteLine(line);
      if (q) records.push({ record: q.record, strings: q.strings, name: ownerFromPrefix(q.prefix) });
    }
    if (!records.length) throw new RecordError("Found quotes but no complete quoted string.");
  } else {
    const joined = lines.map((l) => l.trim()).filter(Boolean).join(" ").trim();
    if (joined) records.push({ record: joined, strings: null, name: null });
  }
  return records;
}

export function detectType(record, name) {
  const r = record.trim();
  if (/^v\s*=\s*spf1(\s|$)/i.test(r)) return "spf";
  if (/^spf2\.[0-9]\//i.test(r)) return "senderid";
  if (/^v\s*=\s*dmarc1\s*(;|$)/i.test(r)) return "dmarc";
  if (/^v\s*=\s*dkim1\s*(;|$)/i.test(r)) return "dkim";
  if (/^v\s*=\s*stsv1\s*(;|$)/i.test(r)) return "mtasts";
  if (/^v\s*=\s*tlsrptv1\s*(;|$)/i.test(r)) return "tlsrpt";
  if (name && /(^|\.)_domainkey\./i.test(name + ".")) return "dkim";
  if (name && /^_dmarc\./i.test(name)) return "dmarc";
  if (name && /^_mta-sts\./i.test(name)) return "mtasts";
  if (name && /^_smtp\._tls\./i.test(name)) return "tlsrpt";
  // Heuristic: a tag-list with a base64-ish p= tag is almost surely a DKIM key.
  if (/(^|;)\s*p\s*=\s*[A-Za-z0-9+/=\s]*(;|$)/.test(r) && /[;=]/.test(r) &&
      /(^|;)\s*(k|h|s|t|n|g)\s*=/.test(r)) return "dkim";
  return null;
}

// ---------------------------------------------------------------------------
// SPF (RFC 7208)

const MACRO_LETTERS = "slodiphv";     // valid in any domain-spec
const MACRO_EXP_ONLY = "crt";         // valid only in exp= explanation text

// Validate a macro-string (RFC 7208 §7.1). Returns {macros: bool} or throws.
export function checkMacroString(s, { expOnly = false } = {}) {
  let macros = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== "%") {
      // macro-literal: visible chars except %
      if (c < "!" || c > "~") throw new RecordError(`invalid character in "${s}"`);
      continue;
    }
    const n = s[i + 1];
    if (n === "%" || n === "_" || n === "-") { macros = true; i++; continue; }
    if (n !== "{") throw new RecordError(`"%" must be followed by {, %, _ or - in "${s}"`);
    const close = s.indexOf("}", i + 2);
    if (close === -1) throw new RecordError(`unterminated macro in "${s}"`);
    const body = s.slice(i + 2, close);
    const m = /^([a-zA-Z])(\d*)(r?)([.\-+,/_=]*)$/.exec(body);
    if (!m) throw new RecordError(`malformed macro "%{${body}}"`);
    const letter = m[1].toLowerCase();
    if (MACRO_EXP_ONLY.includes(letter)) {
      if (!expOnly) throw new RecordError(`macro %{${m[1]}} is allowed only in the exp= explanation text`);
    } else if (!MACRO_LETTERS.includes(letter)) {
      throw new RecordError(`unknown macro letter "%{${m[1]}}"`);
    }
    if (m[2] === "0") throw new RecordError(`macro digit transformer must be positive in "%{${body}}"`);
    macros = true;
    i = close;
  }
  return { macros };
}

const CIDR4_RE = /^(0|[1-9]\d?)$/;    // no leading zeros (RFC 7208 §12 ABNF)
const CIDR6_RE = /^(0|[1-9]\d{0,2})$/;

function parseCidr4(s, term) {
  if (!CIDR4_RE.test(s) || Number(s) > 32) throw new RecordError(`invalid IPv4 prefix length "/${s}" in "${term}"`);
  return Number(s);
}
function parseCidr6(s, term) {
  if (!CIDR6_RE.test(s) || Number(s) > 128) throw new RecordError(`invalid IPv6 prefix length "/${s}" in "${term}"`);
  return Number(s);
}

// Split trailing dual-cidr from a/mx/ptr domain-spec: dom[/n][//m]
function splitDualCidr(s, term) {
  let cidr4 = null, cidr6 = null, rest = s;
  const m6 = /\/\/(\d+)$/.exec(rest);
  if (m6) { cidr6 = parseCidr6(m6[1], term); rest = rest.slice(0, -m6[0].length); }
  const m4 = /\/(\d+)$/.exec(rest);
  if (m4) { cidr4 = parseCidr4(m4[1], term); rest = rest.slice(0, -m4[0].length); }
  // Any leftover "/" is an attempted-but-malformed CIDR: domains never
  // contain slashes, even though the macro-string ABNF technically allows one.
  if (rest.includes("/")) throw new RecordError(`malformed CIDR suffix in "${term}"`);
  return { rest, cidr4, cidr6 };
}

const QUALIFIERS = { "+": "pass", "-": "fail", "~": "softfail", "?": "neutral" };
export const LOOKUP_MECHS = new Set(["include", "a", "mx", "ptr", "exists"]);

export function parseSPFTerm(raw) {
  let s = raw, qualifier = "+";
  if ("+-~?".includes(s[0])) { qualifier = s[0]; s = s.slice(1); }
  const mm = /^(all|include|a|mx|ptr|ip4|ip6|exists)((?::|\/|$).*)$/is.exec(s);
  if (mm) {
    const name = mm[1].toLowerCase();
    let arg = mm[2];
    const t = { raw, kind: "mechanism", qualifier, result: QUALIFIERS[qualifier],
                name, domain: null, ip: null, cidr4: null, cidr6: null, macros: false };
    if (name === "all") {
      if (arg !== "") throw new RecordError(`"all" takes no argument: "${raw}"`);
      return t;
    }
    if (name === "ip4" || name === "ip6") {
      if (!arg.startsWith(":") || arg.length === 1) throw new RecordError(`"${name}" needs an address: "${raw}"`);
      arg = arg.slice(1);
      const slash = arg.indexOf("/");
      const addr = slash === -1 ? arg : arg.slice(0, slash);
      if (name === "ip4") {
        try { t.ip = { v: 4, value: parseIPv4(addr) }; }
        catch (e) { throw new RecordError(`invalid IPv4 address in "${raw}": ${e.message}`); }
        t.cidr4 = slash === -1 ? 32 : parseCidr4(arg.slice(slash + 1), raw);
      } else {
        let p;
        try { p = parseIPv6(addr); }
        catch (e) { throw new RecordError(`invalid IPv6 address in "${raw}": ${e.message}`); }
        if (p.zone !== null) throw new RecordError(`zone id not allowed in "${raw}"`);
        t.ip = { v: 6, value: p.value };
        t.cidr6 = slash === -1 ? 128 : parseCidr6(arg.slice(slash + 1), raw);
      }
      return t;
    }
    if (name === "include" || name === "exists") {
      if (!arg.startsWith(":") || arg.length === 1) throw new RecordError(`"${name}" needs a domain: "${raw}"`);
      const dom = arg.slice(1);
      if (/\/\d+$/.test(dom)) throw new RecordError(`CIDR length not allowed on "${name}": "${raw}"`);
      t.macros = checkMacroString(dom).macros;
      t.domain = dom;
      return t;
    }
    // a / mx / ptr: optional :domain, a/mx allow dual-cidr
    if (arg.startsWith(":")) {
      if (arg.length === 1) throw new RecordError(`empty domain in "${raw}"`);
      arg = arg.slice(1);
      const { rest, cidr4, cidr6 } = name === "ptr" ? { rest: arg, cidr4: null, cidr6: null } : splitDualCidr(arg, raw);
      if (!rest) throw new RecordError(`empty domain in "${raw}"`);
      t.macros = checkMacroString(rest).macros;
      t.domain = rest; t.cidr4 = cidr4 ?? (name === "ptr" ? null : 32); t.cidr6 = cidr6 ?? (name === "ptr" ? null : 128);
      return t;
    }
    if (arg === "") { t.cidr4 = name === "ptr" ? null : 32; t.cidr6 = name === "ptr" ? null : 128; return t; }
    if (name === "ptr") throw new RecordError(`malformed term "${raw}"`);
    const { rest, cidr4, cidr6 } = splitDualCidr(arg, raw);
    if (rest !== "") throw new RecordError(`malformed term "${raw}"`);
    t.cidr4 = cidr4 ?? 32; t.cidr6 = cidr6 ?? 128;
    return t;
  }
  const mod = /^([a-zA-Z][a-zA-Z0-9_.-]*)=(.*)$/s.exec(s);
  if (mod && qualifier === "+" && raw[0] !== "+") {
    const name = mod[1].toLowerCase();
    const t = { raw, kind: "modifier", name, value: mod[2], macros: false };
    if (name === "redirect" || name === "exp") {
      if (!mod[2]) throw new RecordError(`"${name}=" needs a domain: "${raw}"`);
      t.macros = checkMacroString(mod[2]).macros;
    } else {
      t.kind = "unknown-modifier";
      checkMacroString(mod[2], { expOnly: true }); // unknown-modifier value is a macro-string
    }
    return t;
  }
  throw new RecordError(`unknown term "${raw}" — not a mechanism or modifier`);
}

export function parseSPF(record, name = null) {
  const out = { type: "spf", terms: [], warnings: [], infos: [], error: null,
                lookups: 0, redirect: null, exp: null, hasAll: false };
  const own = name ? name.replace(/\.$/, "").toLowerCase() : null;
  const selfRef = (dom) => own && dom && dom.replace(/\.$/, "").toLowerCase() === own;
  const parts = record.trim().split(/[ \t]+/);
  if (!/^v=spf1$/i.test(parts[0])) {
    out.error = `SPF records must start with "v=spf1" (got "${parts[0]}").`;
    return out;
  }
  if (parts[0] !== "v=spf1") out.warnings.push(`The version tag should be lowercase "v=spf1"; most resolvers accept "${parts[0]}" but it is nonstandard.`);
  let afterAll = 0;
  for (const raw of parts.slice(1)) {
    if (!raw) continue;
    let t;
    try { t = parseSPFTerm(raw); }
    catch (e) {
      out.error = `${e.message}. Receivers treat this as a permanent error (permerror): the whole record is unusable and mail is evaluated as if it failed to validate.`;
      out.terms.push({ raw, kind: "invalid", error: e.message });
      return out;
    }
    if (t.kind === "mechanism") {
      if (out.hasAll) afterAll++;
      if (LOOKUP_MECHS.has(t.name)) out.lookups++;
      if (t.name === "all") out.hasAll = true;
      if (t.name === "ptr") out.warnings.push(`"${raw}": the ptr mechanism is deprecated (RFC 7208 §5.5) — it is slow, unreliable, and SHOULD NOT be published. Remove it.`);
      if (t.name === "include" && selfRef(t.domain)) out.warnings.push(`"${raw}" includes this record's own domain — evaluation recurses into itself until the 10-lookup limit and fails with a permanent error.`);
    } else if (t.name === "redirect") {
      if (out.redirect) { out.error = `duplicate "redirect=" modifier — a permanent error (permerror).`; return out; }
      out.redirect = t;
      out.lookups++;
      if (selfRef(t.value)) out.warnings.push(`"${t.raw}" redirects to this record's own domain — an evaluation loop that fails with a permanent error.`);
    } else if (t.name === "exp") {
      if (out.exp) { out.error = `duplicate "exp=" modifier — a permanent error (permerror).`; return out; }
      out.exp = t;
    }
    out.terms.push(t);
  }
  if (afterAll) out.warnings.push(`${afterAll} term${afterAll > 1 ? "s" : ""} listed after "all" — everything after "all" is never evaluated and is ignored.`);
  if (out.redirect && out.hasAll) out.warnings.push(`"redirect=" is ignored when the record contains an "all" mechanism (RFC 7208 §6.1) — one of the two is dead configuration.`);
  const allTerm = out.terms.find((t) => t.kind === "mechanism" && t.name === "all");
  if (allTerm) {
    if (allTerm.qualifier === "+") out.warnings.push(`"${allTerm.raw}" passes the entire internet: any server anywhere is authorized to send mail as this domain. This makes SPF useless and is a known spam-filter red flag.`);
    else if (allTerm.qualifier === "?") out.warnings.push(`"?all" ends the record with a neutral result — SPF then asserts nothing about unlisted senders. Use "~all" (softfail) or "-all" (fail) once you trust the list.`);
  } else if (!out.redirect) {
    out.warnings.push(`No "all" mechanism and no "redirect=": unlisted senders get a neutral result by default, which most receivers treat as "no opinion". End the record with "~all" or "-all".`);
  }
  if (out.lookups > 10) {
    out.warnings.push(`${out.lookups} DNS-querying terms (include, a, mx, ptr, exists, redirect) — over the hard limit of 10 (RFC 7208 §4.6.4). Receivers stop with a permanent error, so SPF fails for this domain.`);
  } else if (out.lookups > 0) {
    out.infos.push(`${out.lookups} of 10 permitted DNS-querying terms used directly. Every "include" and "redirect" also counts the lookups inside the referenced record, so the true total may be higher.`);
  }
  if (out.terms.some((t) => t.macros)) out.infos.push(`This record uses SPF macros (%{…}) — the domain is computed per message from the sender address, IP, or HELO name at evaluation time.`);
  return out;
}

// Evaluate an SPF record for a specific client IP, using only what is in the
// record: ip4/ip6/all are decided exactly; anything needing DNS stops the
// scan honestly.
export function evaluateSPF(parsed, ipStr) {
  if (parsed.error) return { result: "permerror", detail: "record is invalid" };
  let ip;
  try {
    ip = { v: 4, value: parseIPv4(ipStr) };
  } catch {
    try {
      const p = parseIPv6(ipStr);
      ip = { v: 6, value: p.value };
      // An IPv4-mapped IPv6 address is evaluated as its embedded IPv4 (RFC 7208 §4.6.4)
      if (ip.value >> 32n === 0xffffn) ip = { v: 4, value: Number(ip.value & 0xffffffffn) };
    } catch {
      return { result: null, detail: `"${ipStr}" is not a valid IPv4 or IPv6 address` };
    }
  }
  const steps = [];
  for (const t of parsed.terms) {
    if (t.kind !== "mechanism") { steps.push({ term: t.raw, outcome: "skip" }); continue; }
    if (t.name === "all") {
      steps.push({ term: t.raw, outcome: "match" });
      return { result: t.result, matched: t.raw, steps };
    }
    if (t.name === "ip4" || t.name === "ip6") {
      let match = false;
      if (t.ip.v === ip.v) {
        if (ip.v === 4) {
          const bits = 32 - t.cidr4;
          match = bits >= 32 || (ip.value >>> bits) === (t.ip.value >>> bits);
        } else {
          const bits = BigInt(128 - t.cidr6);
          match = (ip.value >> bits) === (t.ip.value >> bits);
        }
      }
      steps.push({ term: t.raw, outcome: match ? "match" : "no-match" });
      if (match) return { result: t.result, matched: t.raw, steps };
      continue;
    }
    steps.push({ term: t.raw, outcome: "needs-dns" });
    return { result: "needs-dns", matched: t.raw, steps,
             detail: `evaluation reaches "${t.raw}", which requires a DNS lookup — this tool does not make network requests, so the outcome depends on live DNS.` };
  }
  if (parsed.redirect) {
    steps.push({ term: parsed.redirect.raw, outcome: "needs-dns" });
    return { result: "needs-dns", matched: parsed.redirect.raw, steps,
             detail: `no mechanism matched, so evaluation continues at "${parsed.redirect.raw}" — a DNS lookup this tool does not make.` };
  }
  return { result: "neutral", matched: null, steps, detail: "no mechanism matched and there is no redirect — the default result is neutral." };
}

// ---------------------------------------------------------------------------
// Shared tag-list parsing (DMARC and DKIM are both "tag=value;" lists).

export function parseTagList(record, { lowerNames = false, strictEmpty = false } = {}) {
  const tags = [];
  const seen = new Set();
  const parts = record.split(";");
  for (const [i, part] of parts.entries()) {
    const s = part.trim();
    if (!s) {
      // RFC 6376 §3.2 allows an empty segment only from a trailing ";".
      if (strictEmpty && i !== parts.length - 1) throw new RecordError(`empty tag before ";" number ${i + 1}`);
      continue;
    }
    const m = /^([^=\s]+)\s*=\s*([\s\S]*)$/.exec(s);
    if (!m) throw new RecordError(`"${s}" is not a tag=value pair`);
    const name = lowerNames ? m[1].toLowerCase() : m[1];
    if (seen.has(name)) throw new RecordError(`duplicate tag "${name}"`);
    seen.add(name);
    tags.push({ name, value: m[2].trim() });
  }
  return tags;
}

// ---------------------------------------------------------------------------
// DMARC (RFC 9989; legacy tags from RFC 7489 noted as such)

const DMARC_POLICIES = ["none", "quarantine", "reject"];

function parseDmarcUriList(value) {
  return value.split(",").map((u) => {
    const s = u.trim();
    const m = /^(mailto):([^!]+)(?:!(\d+)([kmgt]?))?$/i.exec(s);
    if (m) return { uri: s, scheme: "mailto", address: m[2], sizeLimit: m[3] ? m[3] + (m[4] || "") : null };
    const g = /^([a-z][a-z0-9+.-]*):(.+)$/i.exec(s);
    if (g) return { uri: s, scheme: g[1].toLowerCase(), address: g[2], sizeLimit: null };
    throw new RecordError(`"${s}" is not a valid report URI`);
  });
}

function mailDomain(address) {
  const at = address.lastIndexOf("@");
  return at === -1 ? null : address.slice(at + 1).toLowerCase();
}

export function parseDMARC(record, name = null) {
  const out = { type: "dmarc", tags: [], warnings: [], infos: [], error: null,
                effective: null, rua: [], ruf: [] };
  // The record's organizational context, for external-destination detection.
  const domain = name ? name.replace(/^_dmarc\./i, "") : null;
  let list;
  try { list = parseTagList(record, { lowerNames: true }); }
  catch (e) { out.error = `${e.message}. Receivers that cannot parse the record ignore it entirely.`; return out; }
  if (!list.length || list[0].name !== "v" || !/^dmarc1$/i.test(list[0].value)) {
    out.error = `A DMARC record must start with "v=DMARC1" as its first tag.`;
    return out;
  }
  if (list[0].value !== "DMARC1") out.warnings.push(`The version value is case-sensitive in the grammar: write "v=DMARC1", not "v=${list[0].value}".`);
  const known = {
    v: null,
    p: { values: DMARC_POLICIES }, sp: { values: DMARC_POLICIES }, np: { values: DMARC_POLICIES },
    adkim: { values: ["r", "s"] }, aspf: { values: ["r", "s"] },
    psd: { values: ["y", "n", "u"] }, t: { values: ["y", "n"] },
    fo: { list: ":", values: ["0", "1", "d", "s"] },
    rua: { uris: true }, ruf: { uris: true },
    pct: { legacy: true }, ri: { legacy: true }, rf: { legacy: true },
  };
  const seen = {};
  for (const tag of list) {
    const spec = known[tag.name];
    const rec = { name: tag.name, value: tag.value, legacy: false, unknown: false };
    if (spec === undefined) {
      rec.unknown = true;
      out.warnings.push(`Unknown tag "${tag.name}=" — receivers ignore tags they do not recognize (it has no effect).`);
    } else if (spec) {
      if (spec.legacy) {
        rec.legacy = true;
        if (tag.name === "pct") {
          if (!/^\d{1,3}$/.test(tag.value) || Number(tag.value) > 100) { out.error = `pct must be an integer 0–100, not "${tag.value}".`; return out; }
          out.infos.push(`"pct=${tag.value}" is a legacy RFC 7489 tag removed in RFC 9989 — current receivers ignore it and apply the policy to 100% of mail. Older receivers apply the policy to only ${tag.value}% of failing messages.`);
          if (Number(tag.value) < 100) out.warnings.push(`On receivers that still honor pct, ${100 - Number(tag.value)}% of failing mail bypasses the policy — this record is not fully enforced everywhere.`);
        } else {
          out.infos.push(`"${tag.name}=" is a legacy RFC 7489 tag removed in RFC 9989 — current receivers ignore it.`);
          if (tag.name === "ri" && !/^\d+$/.test(tag.value)) { out.error = `ri must be an unsigned integer, not "${tag.value}".`; return out; }
        }
      } else if (spec.uris) {
        try { rec.uris = parseDmarcUriList(tag.value); }
        catch (e) { out.error = `${tag.name}=: ${e.message}.`; return out; }
        out[tag.name] = rec.uris;
      } else if (spec.list) {
        const vals = tag.value.split(spec.list).map((v) => v.trim().toLowerCase());
        const bad = vals.find((v) => !spec.values.includes(v));
        if (bad !== undefined) {
          rec.invalid = true;
          out.warnings.push(`"fo=${tag.value}": "${bad}" is not a valid option (${spec.values.join(", ")}, colon-separated) — receivers ignore the tag and use the default.`);
        } else rec.parsed = vals;
      } else {
        const v = tag.value.toLowerCase();
        if (!spec.values.includes(v)) {
          rec.invalid = true;
          // Invalid p/sp/np triggers RFC 9989's whole-record relaxation below;
          // an invalid minor tag is simply ignored in favor of its default.
          if (!["p", "sp", "np"].includes(tag.name)) out.warnings.push(`"${tag.name}=${tag.value}" is not a valid value (${spec.values.join(", ")}) — receivers ignore the tag and use the default.`);
        } else rec.parsed = v;
      }
    }
    seen[tag.name] = rec;
    out.tags.push(rec);
  }

  // Effective policy set (RFC 9989 defaults: sp ← p, np ← sp). A record with
  // no valid p, or an invalid sp or np, is processed as p=none when rua is
  // present and treated as nonexistent otherwise (RFC 9989 §4.7).
  const bad = ["p", "sp", "np"].find((k) => seen[k]?.invalid) ?? (!seen.p ? "p" : null);
  if (bad) {
    const what = seen[bad] ? `"${bad}=${seen[bad].value}" is not a valid policy (none, quarantine, reject)` : `There is no "p=" tag`;
    if (out.rua.length) {
      out.warnings.push(`${what}. Because a rua address is present, RFC 9989 receivers process the record as "p=none" (monitoring only); RFC 7489 receivers ignore it entirely.`);
      seen.p = { parsed: "none" }; seen.sp = null; seen.np = null;
    } else {
      out.error = `${what}, and there is no "rua=" address — receivers treat this as if no DMARC record exists.`;
      return out;
    }
  }
  const p = seen.p.parsed, sp = seen.sp?.parsed ?? p, np = seen.np?.parsed ?? sp;
  out.effective = {
    p, sp, np,
    adkim: seen.adkim?.parsed ?? "r",
    aspf: seen.aspf?.parsed ?? "r",
    fo: seen.fo?.parsed ?? ["0"],
    psd: seen.psd?.parsed ?? "u",
    testing: seen.t?.parsed === "y",
  };

  const rank = (pol) => DMARC_POLICIES.indexOf(pol);
  if (p === "none") out.warnings.push(`"p=none" asks receivers to take no action on failing mail — useful for monitoring, but the domain is not protected against spoofing until the policy is quarantine or reject.`);
  if (seen.sp && rank(sp) < rank(p)) out.warnings.push(`Subdomain policy "sp=${sp}" is weaker than "p=${p}" — mail spoofing any subdomain (e.g. anything.${domain ?? "example.com"}) is treated more leniently than the domain itself.`);
  if (seen.np && rank(np) < rank(sp)) out.warnings.push(`Non-existent-subdomain policy "np=${np}" is weaker than the subdomain policy — spoofing subdomains that do not exist in DNS gets the lenient treatment.`);
  if (out.effective.testing) out.warnings.push(`"t=y" puts the record in testing mode (RFC 9989): receivers evaluate and report but do not apply the policy. Equivalent in spirit to the old pct=0.`);
  if (!out.rua.length) out.warnings.push(`No "rua=" aggregate-report address: no feedback on who is sending as this domain, which makes it hard to move safely to an enforcing policy.`);
  if (out.ruf.length) out.infos.push(`"ruf=" requests per-message failure reports. Few large receivers send them, and they can contain message content — treat the destination mailbox accordingly.`);
  if (seen.fo && !out.ruf.length) out.warnings.push(`"fo=" configures failure reporting but there is no "ruf=" address to send failure reports to — it has no effect.`);
  for (const kind of ["rua", "ruf"]) {
    for (const u of out[kind]) {
      if (u.scheme !== "mailto") { out.warnings.push(`${kind}= URI "${u.uri}" is not a mailto: address — receivers only support mailto for DMARC reports.`); continue; }
      const dest = mailDomain(u.address);
      if (domain && dest && dest !== domain.toLowerCase() && !dest.endsWith("." + domain.toLowerCase())) {
        out.infos.push(`Reports for ${domain} go to ${dest} — an external domain. This only works if ${dest} publishes an authorization record at ${domain}._report._dmarc.${dest} (TXT "v=DMARC1"), which this tool cannot check without DNS.`);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// DKIM public-key record (RFC 6376 §3.6.1; ed25519 per RFC 8463)

function decodeBase64Loose(s) {
  return base64Decode(s.replace(/\s+/g, ""));
}

// Parse an RSA public key: SPKI (rsaEncryption OID wrapping a BIT STRING) or,
// as published by some old tooling, a bare RSAPublicKey. Returns modulus bits.
export function rsaKeyBits(der) {
  let node = parseElement(der, 0);
  if (node.tag !== 0x10) throw new RecordError("public key is not a DER SEQUENCE");
  let kids = node.children ?? [];
  let bare = false;
  if (kids.length === 2 && kids[0].tag === 0x10) {
    const oid = readOid(der, kids[0].children[0]);
    if (oid !== "1.2.840.113549.1.1.1") throw new RecordError(`key algorithm OID is ${oid}, not rsaEncryption`);
    if (kids[1].tag !== 0x03) throw new RecordError("SPKI missing BIT STRING");
    const bits = content(der, kids[1]);
    if (bits[0] !== 0) throw new RecordError("unexpected unused bits in key BIT STRING");
    const inner = parseElement(bits.subarray(1), 0);
    if (inner.tag !== 0x10) throw new RecordError("RSAPublicKey is not a SEQUENCE");
    return { bits: integerBits(bits.subarray(1), inner.children[0]), bare: false };
  }
  if (kids.length === 2 && kids[0].tag === 0x02 && kids[1].tag === 0x02) bare = true;
  if (!bare) throw new RecordError("public key is neither SPKI nor RSAPublicKey");
  return { bits: integerBits(der, kids[0]), bare: true };
}

function integerBits(bytes, node) {
  let c = content(bytes, node);
  let i = 0;
  while (i < c.length && c[i] === 0) i++;
  if (i === c.length) return 0;
  return (c.length - i - 1) * 8 + (32 - Math.clz32(c[i]));
}

export function parseDKIMKey(record, name = null) {
  const out = { type: "dkim", tags: [], warnings: [], infos: [], error: null,
                selector: null, domain: null, algorithm: null, keyBits: null,
                revoked: false, flags: [], hashes: null };
  if (name) {
    const m = /^(.+?)\._domainkey\.(.+)$/i.exec(name);
    if (m) { out.selector = m[1]; out.domain = m[2]; }
  }
  let list;
  try { list = parseTagList(record, { strictEmpty: true }); }
  catch (e) {
    out.error = `${e.message}. RFC 6376 §3.2: a tag-list with duplicate or malformed tags is invalid, so verifiers treat the key as unusable and signatures fail.`;
    return out;
  }
  const seen = {};
  for (const tag of list) {
    const rec = { name: tag.name, value: tag.value, unknown: false };
    if (!["v", "g", "h", "k", "n", "p", "s", "t"].includes(tag.name)) {
      rec.unknown = true;
      if (/^[VGHKNPST]$/.test(tag.name)) out.warnings.push(`Tag names are case-sensitive (RFC 6376 §3.2): "${tag.name}=" is not the same as "${tag.name.toLowerCase()}=" and is ignored.`);
      else out.infos.push(`Unrecognized tag "${tag.name}=" is ignored by verifiers.`);
    }
    seen[tag.name] = rec;
    out.tags.push(rec);
  }
  if (seen.v) {
    if (list[0].name !== "v") out.warnings.push(`When present, "v=DKIM1" must be the first tag (RFC 6376 §3.6.1); some verifiers reject the record otherwise.`);
    if (seen.v.value !== "DKIM1") { out.error = `"v=${seen.v.value}": the only defined version is DKIM1.`; return out; }
  }
  if (seen.g) out.warnings.push(`"g=" (granularity) was removed in RFC 6376 (2011). Modern verifiers ignore it${seen.g.value !== "*" ? `; legacy RFC 4871 verifiers would restrict this key to local-parts matching "${seen.g.value}"` : ""}.`);
  if (!seen.p) { out.error = `No "p=" tag — a DKIM key record must contain the public key. Verifiers treat this as a missing key.`; return out; }

  out.algorithm = seen.k ? seen.k.value : "rsa";
  if (seen.k && !["rsa", "ed25519"].includes(seen.k.value)) out.warnings.push(`Key type "k=${seen.k.value}" is not a registered DKIM key type (rsa, ed25519) — verifiers that do not recognize it treat the key as unusable.`);
  if (seen.h) {
    out.hashes = seen.h.value.split(":").map((h) => h.trim());
    for (const h of out.hashes) if (!["sha1", "sha256"].includes(h)) out.warnings.push(`"h=${h}" is not a registered hash algorithm (sha1, sha256).`);
    if (out.hashes.includes("sha1")) out.warnings.push(`"h=" allows sha1, which RFC 8301 forbids: verifiers MUST NOT validate rsa-sha1 signatures. Allow only sha256.`);
  }
  if (seen.s) {
    const svc = seen.s.value.split(":").map((x) => x.trim());
    for (const x of svc) if (!["*", "email"].includes(x)) out.warnings.push(`Service type "s=${x}" is not registered ("*" or "email") — if no listed type matches, verifiers ignore this key.`);
  }
  if (seen.t) {
    out.flags = seen.t.value.split(":").map((x) => x.trim());
    for (const f of out.flags) if (!["y", "s"].includes(f)) out.infos.push(`Unknown flag "t=${f}" is ignored.`);
    if (out.flags.includes("y")) out.warnings.push(`Flag "t=y": this domain is testing DKIM. Verifiers must treat signatures exactly as if unsigned mail — the signature carries no weight until the flag is removed.`);
    if (out.flags.includes("s")) out.infos.push(`Flag "t=s": the signing identity (i=) may not be a subdomain — strict domain match required.`);
  }

  const pVal = seen.p.value;
  if (pVal === "") {
    out.revoked = true;
    out.warnings.push(`"p=" is empty: this key has been revoked (RFC 6376 §3.6.1). Signatures referencing this selector fail verification.`);
    return out;
  }
  let key;
  try { key = decodeBase64Loose(pVal); }
  catch { out.error = `"p=" is not valid base64 — the key cannot be decoded, so all signatures using this selector fail.`; return out; }
  if (out.algorithm === "ed25519") {
    if (key.length === 32) { out.keyBits = 256; out.infos.push(`Ed25519 key: 32 raw bytes, as RFC 8463 requires.`); }
    else {
      try {
        const spki = rsaSpkiEd25519(key);
        if (spki) { out.error = `"p=" holds a DER/SPKI-wrapped Ed25519 key (${key.length} bytes). RFC 8463 requires the raw 32-byte public key — this is a common generator mistake and verifiers reject it.`; return out; }
      } catch { /* fall through */ }
      out.error = `"p=" decodes to ${key.length} bytes, but an Ed25519 public key is exactly 32 raw bytes (RFC 8463).`;
      return out;
    }
    return out;
  }
  try {
    const { bits, bare } = rsaKeyBits(key);
    out.keyBits = bits;
    if (bare) out.warnings.push(`The key is a bare RSAPublicKey, not the SubjectPublicKeyInfo form RFC 6376 specifies — many verifiers accept it, but not all.`);
    if (bits < 1024) out.warnings.push(`${bits}-bit RSA key: RFC 8301 says verifiers MUST NOT accept keys shorter than 1024 bits — and a key this small is factorable in practice. Replace it now.`);
    else if (bits < 2048) out.warnings.push(`${bits}-bit RSA key: acceptable to verifiers, but RFC 8301 recommends 2048 bits for new keys. 1024-bit RSA is within reach of well-funded attackers.`);
  } catch (e) {
    out.error = `"p=" is base64 but not a parseable RSA public key (${e.message}) — verifiers cannot use it.`;
  }
  return out;
}

// Detect an SPKI-wrapped ed25519 key (OID 1.3.101.112) to give a precise error.
function rsaSpkiEd25519(der) {
  const node = parseElement(der, 0);
  if (node.tag !== 0x10 || !node.children?.length) return false;
  const alg = node.children[0];
  if (alg.tag !== 0x10 || !alg.children?.length) return false;
  return readOid(der, alg.children[0]) === "1.3.101.112";
}

// ---------------------------------------------------------------------------
// MTA-STS (RFC 8461 §3.1) and TLSRPT (RFC 8460 §3)

export function parseMTASTS(record) {
  const out = { type: "mtasts", tags: [], warnings: [], infos: [], error: null, id: null };
  let list;
  try { list = parseTagList(record); }
  catch (e) { out.error = e.message + "."; return out; }
  if (!list.length || list[0].name !== "v" || list[0].value !== "STSv1") {
    out.error = `An MTA-STS record must start with "v=STSv1".`; return out;
  }
  for (const tag of list) {
    out.tags.push({ name: tag.name, value: tag.value, unknown: !["v", "id"].includes(tag.name) });
    if (tag.name === "id") {
      out.id = tag.value;
      if (!/^[A-Za-z0-9]{1,32}$/.test(tag.value)) out.error = `id= must be 1–32 letters or digits (got "${tag.value}").`;
    } else if (tag.name !== "v") out.infos.push(`Unrecognized field "${tag.name}=" is ignored.`);
  }
  if (!out.error && out.id === null) out.error = `Missing required "id=" field.`;
  if (!out.error) out.infos.push(`This record only signals that an MTA-STS policy exists (id "${out.id}" — senders re-fetch the policy when it changes). The policy itself is served at https://mta-sts.<domain>/.well-known/mta-sts.txt.`);
  return out;
}

export function parseTLSRPT(record) {
  const out = { type: "tlsrpt", tags: [], warnings: [], infos: [], error: null, rua: [] };
  let list;
  try { list = parseTagList(record); }
  catch (e) { out.error = e.message + "."; return out; }
  if (!list.length || list[0].name !== "v" || list[0].value !== "TLSRPTv1") {
    out.error = `A TLSRPT record must start with "v=TLSRPTv1".`; return out;
  }
  for (const tag of list) {
    out.tags.push({ name: tag.name, value: tag.value, unknown: !["v", "rua"].includes(tag.name) });
    if (tag.name === "rua") {
      for (const u of tag.value.split(",")) {
        const s = u.trim();
        if (/^mailto:.+$/i.test(s) || /^https:\/\/.+$/i.test(s)) out.rua.push(s);
        else { out.error = `rua= destinations must be mailto: or https: URIs (got "${s}").`; return out; }
      }
    } else if (tag.name !== "v") out.infos.push(`Unrecognized field "${tag.name}=" is ignored.`);
  }
  if (!out.rua.length && !out.error) out.error = `Missing required "rua=" field — there is nowhere to send TLS reports.`;
  return out;
}

// ---------------------------------------------------------------------------

const TYPE_LABELS = {
  spf: "SPF record", dmarc: "DMARC record", dkim: "DKIM public-key record",
  mtasts: "MTA-STS record", tlsrpt: "TLS reporting (TLSRPT) record",
  senderid: "Sender ID record",
};

export function analyzeOne({ record, strings, name }) {
  const type = detectType(record, name);
  let res;
  if (type === "spf") res = parseSPF(record, name);
  else if (type === "dmarc") res = parseDMARC(record, name);
  else if (type === "dkim") res = parseDKIMKey(record, name);
  else if (type === "mtasts") res = parseMTASTS(record);
  else if (type === "tlsrpt") res = parseTLSRPT(record);
  else if (type === "senderid") {
    res = { type, tags: [], warnings: [], infos: [], error: null };
    res.warnings.push(`This is a Sender ID record (spf2.0/…), a historic Microsoft variant that never became a standard and is ignored by modern receivers. Publish a v=spf1 record instead.`);
  } else return null;
  res.record = record;
  res.name = name;
  res.label = TYPE_LABELS[type];
  if (strings && strings.length > 1) res.infos.push(`The record is split into ${strings.length} quoted strings; receivers concatenate them without separators (shown joined here). DNS requires this for records over 255 bytes.`);
  if (record.length > 255 && (!strings || strings.length === 1)) res.warnings.push(`${record.length} characters: a single TXT character-string holds at most 255 bytes, so this record must be published as multiple quoted strings, which receivers concatenate.`);
  return res;
}

export function analyze(text) {
  if (!text.trim()) throw new RecordError("Nothing to analyze.");
  const extracted = extractRecords(text);
  const results = [], skipped = [];
  for (const r of extracted) {
    const res = analyzeOne(r);
    if (res) results.push(res); else skipped.push(r.record);
  }
  if (!results.length) {
    throw new RecordError(`No SPF, DMARC, DKIM, MTA-STS, or TLSRPT record recognized. SPF starts with "v=spf1", DMARC with "v=DMARC1", DKIM keys contain "p=<base64>".`);
  }
  const cross = [];
  const spfCount = results.filter((r) => r.type === "spf").length;
  if (spfCount > 1) cross.push(`${spfCount} SPF records: a domain must publish exactly one — receivers finding more than one return a permanent error and SPF fails entirely (RFC 7208 §4.5).`);
  const dmarcCount = results.filter((r) => r.type === "dmarc").length;
  if (dmarcCount > 1) cross.push(`${dmarcCount} DMARC records: receivers finding more than one at _dmarc.<domain> treat it as if none exists.`);
  return { results, skipped, cross };
}
