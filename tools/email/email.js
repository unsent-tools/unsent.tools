// email.js — raw email header analysis, pure functions, no DOM.
//
// Scope: RFC 5322 header syntax (unfolding, date-time incl. obsolete forms,
// address lists), RFC 2047 encoded-words, Received trace fields (RFC 5321
// time-stamp lines), Authentication-Results (RFC 8601), DKIM-Signature tag
// lists (RFC 6376). All time-dependent checks take `now` explicitly.

export class EmailError extends Error {}

// ---------------------------------------------------------------------------
// Header block splitting

// Split a raw message (or bare header block) into ordered headers.
// Mirrors Python email.parser behaviour: a line that neither contains a
// colon nor starts with whitespace ends the header block.
export function splitHeaders(raw) {
  const notes = [];
  let text = String(raw).replace(/^\uFEFF/, "");
  const lines = text.split(/\r\n|\r|\n/);
  let i = 0;
  if (lines[0] && lines[0].startsWith("From ")) {
    notes.push("Leading mbox “From ” separator line skipped.");
    i = 1;
  }
  const headers = [];
  let bodyPresent = false;
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (line === "") { // blank line: header block ends, body follows
      bodyPresent = lines.slice(i + 1).some((l) => l !== "");
      break;
    }
    if (/^[ \t]/.test(line)) { // folded continuation
      if (headers.length === 0) {
        notes.push("Continuation line before any header was ignored.");
        continue;
      }
      headers[headers.length - 1].raw += "\n" + line;
      continue;
    }
    const m = line.match(/^([!-9;-~]+):(.*)$/); // field-name = printable minus ":"
    if (!m) {
      notes.push(`Line ${i + 1} is not a valid header; treating it and the rest as body.`);
      bodyPresent = true;
      break;
    }
    headers.push({ name: m[1], value: "", raw: line });
  }
  for (const h of headers) {
    const rest = h.raw.slice(h.raw.indexOf(":") + 1);
    h.value = unfold(rest).replace(/^[ \t]+/, ""); // lstrip, like Python email
  }
  return { headers, bodyPresent, notes };
}

// Unfold: CRLF (here already normalized to \n) immediately followed by
// whitespace is removed; the whitespace itself stays (RFC 5322 §2.2.3).
export function unfold(value) {
  return String(value).replace(/\n(?=[ \t])/g, "").replace(/\n/g, "");
}

// ---------------------------------------------------------------------------
// CFWS helpers

// Strip RFC 5322 comments (nested parens, backslash escapes) from a string,
// returning { text, comments }. Quoted strings are respected.
export function stripComments(s) {
  let out = "", comments = [], depth = 0, cur = "", inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQuote) {
      out += c;
      if (c === "\\" && i + 1 < s.length) { out += s[++i]; continue; }
      if (c === '"') inQuote = false;
      continue;
    }
    if (depth > 0) {
      if (c === "\\" && i + 1 < s.length) { cur += s[++i]; continue; }
      if (c === "(") { depth++; cur += c; continue; }
      if (c === ")") { depth--; if (depth === 0) { comments.push(cur); cur = ""; } else cur += c; continue; }
      cur += c;
      continue;
    }
    if (c === '"') { inQuote = true; out += c; continue; }
    if (c === "(") { depth = 1; continue; }
    out += c;
  }
  if (depth > 0) comments.push(cur); // unterminated comment: keep what we saw
  return { text: out, comments };
}

// Split on a separator at top level (outside quoted strings and comments).
export function splitTopLevel(s, sep) {
  const parts = [];
  let cur = "", depth = 0, inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && (inQuote || depth > 0) && i + 1 < s.length) { cur += c + s[++i]; continue; }
    if (inQuote) { cur += c; if (c === '"') inQuote = false; continue; }
    if (c === '"' && depth === 0) { inQuote = true; cur += c; continue; }
    if (c === "(") { depth++; cur += c; continue; }
    if (c === ")") { if (depth > 0) depth--; cur += c; continue; }
    if (c === sep && depth === 0) { parts.push(cur); cur = ""; continue; }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

// ---------------------------------------------------------------------------
// RFC 5322 date-time (including obsolete zones and 2/3-digit years)

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5,
                 jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
// RFC 5322 §4.3 obsolete zone names with defined offsets. Military single
// letters and unknown names carry no reliable offset (treated as unknown).
const OBS_ZONES = { ut: 0, gmt: 0, z: 0, utc: 0,
                    est: -300, edt: -240, cst: -360, cdt: -300,
                    mst: -420, mdt: -360, pst: -480, pdt: -420 };

// Returns { epochMs, offsetMin } where offsetMin is null when the zone is
// unknown or explicitly "-0000" (RFC 5322: sender's zone unknown); epochMs
// then treats the time as UTC, matching Python's naive-datetime reading.
export function parseDate(input) {
  const { text } = stripComments(String(input));
  let s = text.trim().replace(/\s+/g, " ");
  s = s.replace(/^(mon|tue|wed|thu|fri|sat|sun)\s*,\s*/i, "");
  const m = s.match(
    /^(\d{1,2}) ([a-z]{3,}) (\d{2,4}) (\d{1,2}):(\d{2})(?::(\d{2}))?(?: (.*))?$/i);
  if (!m) throw new EmailError(`Unrecognized date: ${JSON.stringify(String(input).trim())}`);
  const day = Number(m[1]);
  const mon = MONTHS[m[2].slice(0, 3).toLowerCase()];
  if (mon === undefined) throw new EmailError(`Unknown month: ${m[2]}`);
  let year = Number(m[3]);
  if (m[3].length === 2) year += year < 50 ? 2000 : 1900; // RFC 5322 §4.3
  else if (m[3].length === 3) year += 1900;
  const hour = Number(m[4]), min = Number(m[5]), sec = Number(m[6] ?? 0);
  let offsetMin = null;
  const zone = (m[7] ?? "").trim();
  const num = zone.match(/^([+-])(\d{2})(\d{2})$/);
  if (num) {
    offsetMin = (Number(num[2]) * 60 + Number(num[3])) * (num[1] === "-" ? -1 : 1);
    if (zone === "-0000") offsetMin = null; // RFC 5322: unknown zone
  } else if (zone && OBS_ZONES[zone.toLowerCase()] !== undefined) {
    offsetMin = OBS_ZONES[zone.toLowerCase()];
  }
  if (hour > 23 || min > 59 || sec > 60) throw new EmailError(`Time out of range: ${zone ? s : input}`);
  const ms = Date.UTC(year, mon, day, hour, min, sec === 60 ? 59 : sec);
  if (new Date(ms).getUTCDate() !== day) throw new EmailError(`Impossible date: day ${day}`);
  return { epochMs: ms - (offsetMin ?? 0) * 60000, offsetMin };
}

// ---------------------------------------------------------------------------
// RFC 2047 encoded-words

const WORD_RE = /=\?([^?*]+)(?:\*[^?]*)?\?([bq])\?([^? ]*)\?=/gi;

function decodeCharset(bytes, charset) {
  try {
    return new TextDecoder(charset, { fatal: false }).decode(bytes);
  } catch {
    return null; // unknown charset
  }
}

// Decode RFC 2047 encoded-words in a header value for display. Whitespace
// between two adjacent encoded words is dropped (§6.2); anything undecodable
// is left as-is and reported.
export function decodeWords(value) {
  const problems = [];
  let last = 0, out = "", pendingGap = null;
  WORD_RE.lastIndex = 0;
  let m;
  while ((m = WORD_RE.exec(value)) !== null) {
    const between = value.slice(last, m.index);
    if (pendingGap !== null && /^[ \t]*$/.test(between)) {
      // whitespace between adjacent encoded words: drop it
    } else {
      out += between;
    }
    const [whole, charset, enc, payload] = m;
    let bytes = null;
    if (enc.toLowerCase() === "b") {
      try {
        const bin = atob(payload.replace(/\s+/g, ""));
        bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
      } catch {
        problems.push(`Invalid base64 in encoded-word: ${whole}`);
      }
    } else {
      const qs = payload.replace(/_/g, " ");
      const arr = [];
      let bad = false;
      for (let i = 0; i < qs.length; i++) {
        if (qs[i] === "=") {
          const hex = qs.slice(i + 1, i + 3);
          if (/^[0-9a-f]{2}$/i.test(hex)) { arr.push(parseInt(hex, 16)); i += 2; }
          else { bad = true; break; }
        } else arr.push(qs.charCodeAt(i));
      }
      if (bad) problems.push(`Invalid quoted-printable in encoded-word: ${whole}`);
      else bytes = Uint8Array.from(arr);
    }
    let text = bytes && decodeCharset(bytes, charset);
    if (bytes && text === null) {
      problems.push(`Unknown charset ${JSON.stringify(charset)}; left undecoded.`);
    }
    out += text ?? whole;
    pendingGap = text !== null && bytes !== null;
    last = m.index + whole.length;
  }
  out += value.slice(last);
  return { text: out, decoded: last > 0, problems };
}

// ---------------------------------------------------------------------------
// Address lists (RFC 5322 §3.4, tolerant)

// Parse a header value holding a list of mailboxes/groups into
// [{ display, address, comment }]. Groups are flattened (their members are
// returned); route addresses have the route dropped.
export function parseAddressList(value) {
  const result = [];
  for (const part of splitAddresses(String(value))) {
    const item = parseMailbox(part);
    if (item) result.push(...item);
  }
  return result;
}

// Split on top-level commas AND unquoted group syntax "phrase : ... ;".
function splitAddresses(s) {
  const parts = [];
  let cur = "", depth = 0, inQuote = false, inAngle = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && inQuote && i + 1 < s.length) { cur += c + s[++i]; continue; }
    if (inQuote) { cur += c; if (c === '"') inQuote = false; continue; }
    if (c === '"') { inQuote = true; cur += c; continue; }
    if (c === "(") { depth++; cur += c; continue; }
    if (c === ")") { if (depth > 0) depth--; cur += c; continue; }
    if (depth > 0) { cur += c; continue; }
    if (c === "<") inAngle = true;
    if (c === ">") inAngle = false;
    if (c === "," && !inAngle) { parts.push(cur); cur = ""; continue; }
    cur += c;
  }
  parts.push(cur);
  return parts.filter((p) => p.trim() !== "");
}

function unquoteDisplay(s) {
  s = s.trim();
  if (s.startsWith('"') && s.endsWith('"') && s.length >= 2) {
    return s.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  return s.replace(/\s+/g, " ");
}

function parseMailbox(part) {
  const { text, comments } = stripComments(part);
  const comment = comments.join("; ") || undefined;
  let s = text.trim();
  if (s === "") return comment ? [{ display: "", address: "", comment }] : [];
  // Group: phrase ":" members ";" — find an unquoted colon before any "<" or "@"
  const colon = findTopLevelColon(s);
  if (colon !== -1) {
    const members = s.slice(colon + 1).replace(/;\s*$/, "");
    const groupName = unquoteDisplay(s.slice(0, colon));
    const inner = parseAddressList(members);
    return inner.length ? inner
      : [{ display: groupName, address: "", comment: "empty group" }];
  }
  const angle = matchAngle(s);
  if (angle) {
    let addr = angle.inner.trim();
    const route = addr.match(/^@[^:]*:(.*)$/); // obs-route: drop it
    if (route) addr = route[1].trim();
    return [{ display: unquoteDisplay(angle.before), address: addr, comment }];
  }
  return [{ display: "", address: s.replace(/\s+/g, ""), comment }];
}

function findTopLevelColon(s) {
  let inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && inQuote) { i++; continue; }
    if (c === '"') { inQuote = !inQuote; continue; }
    if (inQuote) continue;
    if (c === "<" || c === "@") return -1;
    if (c === ":") return i;
  }
  return -1;
}

function matchAngle(s) {
  let inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && inQuote) { i++; continue; }
    if (c === '"') { inQuote = !inQuote; continue; }
    if (!inQuote && c === "<") {
      const end = s.indexOf(">", i);
      if (end === -1) return { before: s.slice(0, i), inner: s.slice(i + 1) };
      return { before: s.slice(0, i), inner: s.slice(i + 1, end) };
    }
  }
  return null;
}

export function addressDomain(addr) {
  const at = String(addr).lastIndexOf("@");
  return at === -1 ? null : addr.slice(at + 1).toLowerCase().replace(/\.$/, "");
}

// ---------------------------------------------------------------------------
// Received trace lines (RFC 5321 §4.4)

const RECEIVED_KEYWORDS = new Set(["from", "by", "via", "with", "id", "for"]);

// Parse one Received value into clauses + timestamp. The date follows the
// final top-level semicolon. Comments are attached to the clause they follow.
export function parseReceived(value) {
  const segs = splitTopLevel(String(value), ";");
  let dateText = null, date = null, dateError = null;
  let headText = String(value);
  if (segs.length > 1) {
    dateText = segs[segs.length - 1].trim();
    headText = segs.slice(0, -1).join(";");
    try { date = parseDate(dateText); }
    catch (e) { dateError = e.message; }
  }
  const clauses = {};
  const extra = [];
  // Tokenize: words, quoted strings and comments, in order.
  const tokens = [];
  const re = /\((?:[^()\\]|\\.|\([^()]*\))*\)|"(?:[^"\\]|\\.)*"|[^\s()"]+/g;
  let m;
  while ((m = re.exec(headText)) !== null) tokens.push(m[0]);
  let current = null;
  for (const tok of tokens) {
    const low = tok.toLowerCase();
    if (RECEIVED_KEYWORDS.has(low) && !(current && clauses[current] === "")) {
      current = low;
      if (!(low in clauses)) clauses[low] = "";
      continue;
    }
    if (current === null) { extra.push(tok); continue; }
    clauses[current] += (clauses[current] ? " " : "") + tok;
  }
  // Pull IPs out of from-clause comments/brackets for display.
  const ips = [];
  const fromText = clauses.from ?? "";
  const ipRe = /\[(?:IPv6:)?([0-9a-f:.]+)\]|\b((?:\d{1,3}\.){3}\d{1,3})\b/gi;
  while ((m = ipRe.exec(fromText)) !== null) {
    const ip = m[1] ?? m[2];
    if (!ips.includes(ip)) ips.push(ip);
  }
  return { clauses, extra, dateText, date, dateError, ips };
}

// Analyze the full Received chain: headers arrive top-first, but the
// bottom-most Received is chronologically first. Returns hops in
// chronological order with per-hop delay when both timestamps parse.
export function analyzeReceivedChain(receivedValues) {
  const hops = receivedValues.map((v) => parseReceived(v)).reverse();
  let prev = null;
  for (const hop of hops) {
    hop.delayMs = null;
    if (hop.date && prev && prev.date) hop.delayMs = hop.date.epochMs - prev.date.epochMs;
    if (hop.date) prev = hop;
  }
  const first = hops.find((h) => h.date);
  const last = [...hops].reverse().find((h) => h.date);
  return {
    hops,
    totalMs: first && last && first !== last ? last.date.epochMs - first.date.epochMs : null,
  };
}

// ---------------------------------------------------------------------------
// Authentication-Results (RFC 8601)

export function parseAuthResults(value) {
  const segs = splitTopLevel(String(value), ";").map((s) => stripComments(s).text.trim());
  const authserv = (segs[0] ?? "").split(/\s+/)[0] || null;
  const results = [];
  for (const seg of segs.slice(1)) {
    if (seg === "" ) continue;
    if (/^none$/i.test(seg)) { results.push({ method: "none", result: null, props: [] }); continue; }
    const tokens = seg.match(/[^\s"]*"(?:[^"\\]|\\.)*"|[^\s]+/g) ?? [];
    let method = null, result = null, reason = null;
    const props = [];
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i];
      const eq = t.indexOf("=");
      if (eq === -1) continue;
      const key = t.slice(0, eq), val = unquoteDisplay(t.slice(eq + 1));
      if (method === null) { method = key.split("/")[0].toLowerCase(); result = val.toLowerCase(); continue; }
      if (key.toLowerCase() === "reason") { reason = val; continue; }
      const dot = key.indexOf(".");
      props.push(dot === -1 ? { ptype: null, prop: key, value: val }
                            : { ptype: key.slice(0, dot), prop: key.slice(dot + 1), value: val });
    }
    if (method !== null) results.push({ method, result, reason, props });
  }
  return { authserv, results };
}

// ---------------------------------------------------------------------------
// DKIM-Signature (RFC 6376 tag list)

export function parseDkimSignature(value) {
  const tags = {};
  for (const part of String(value).split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    if (name === "") continue;
    tags[name] = part.slice(eq + 1).replace(/[\s]+/g, "");
  }
  const h = (tags.h ?? "").split(":").map((s) => s.toLowerCase()).filter(Boolean);
  return {
    tags,
    domain: tags.d ?? null,
    selector: tags.s ?? null,
    algorithm: tags.a ?? null,
    identity: tags.i ?? null,
    signedHeaders: h,
    signedAt: tags.t ? Number(tags.t) * 1000 : null,
    expiresAt: tags.x ? Number(tags.x) * 1000 : null,
    bodyLengthLimited: "l" in tags,
    fromSigned: h.includes("from"),
  };
}

// ---------------------------------------------------------------------------
// Whole-message analysis

const AUTH_FAILS = new Set(["fail", "softfail", "permerror", "temperror", "policy"]);

export function analyze(raw, now = 0) {
  const { headers, bodyPresent, notes } = splitHeaders(raw);
  if (headers.length === 0) throw new EmailError("No headers found. Paste the raw header block (or full raw message).");
  const get = (name) => headers.filter((h) => h.name.toLowerCase() === name.toLowerCase());
  const one = (name) => get(name)[0]?.value ?? null;

  const warnings = [], infos = [];

  // Subject / basic identity
  const subject = one("Subject") !== null ? decodeWords(one("Subject")) : null;
  if (subject) warnings.push(...subject.problems);

  const from = one("From") !== null ? parseAddressList(one("From")) : [];
  const replyTo = one("Reply-To") !== null ? parseAddressList(one("Reply-To")) : [];
  const to = one("To") !== null ? parseAddressList(one("To")) : [];

  if (get("From").length > 1) warnings.push("Multiple From headers — a classic spoofing trick; clients may show either one.");
  if (from.length && replyTo.length) {
    const fd = addressDomain(from[0].address), rd = addressDomain(replyTo[0].address);
    if (fd && rd && fd !== rd) {
      warnings.push(`Reply-To domain (${rd}) differs from From domain (${fd}) — replies go to ${replyTo[0].address}.`);
    }
  }
  for (const mb of from) {
    const disp = decodeWords(mb.display).text;
    const embedded = disp.match(/[\w.+-]+@[\w.-]+\.\w{2,}/);
    if (embedded && embedded[0].toLowerCase() !== mb.address.toLowerCase()) {
      warnings.push(`From display name contains “${embedded[0]}” but the actual address is ${mb.address} — display-name spoofing.`);
    }
  }

  // Date vs Received
  let dateHeader = null;
  if (one("Date") !== null) {
    try { dateHeader = parseDate(one("Date")); }
    catch (e) { warnings.push(`Date header did not parse: ${e.message}`); }
  } else warnings.push("No Date header.");
  if (one("Message-ID") === null) infos.push("No Message-ID header — unusual for mail from a real MTA.");

  const chain = analyzeReceivedChain(get("Received").map((h) => h.value));
  const lastHop = [...chain.hops].reverse().find((h) => h.date);
  if (dateHeader && lastHop) {
    const skew = lastHop.date.epochMs - dateHeader.epochMs;
    if (Math.abs(skew) > 30 * 60000) {
      warnings.push(`Date header is ${fmtDelay(Math.abs(skew))} ${skew > 0 ? "before" : "after"} final delivery — clock skew or a forged Date.`);
    }
  }
  for (const hop of chain.hops) {
    if (hop.delayMs !== null && hop.delayMs < -120000) {
      warnings.push(`A Received hop is timestamped ${fmtDelay(-hop.delayMs)} before the previous hop — clock skew between servers (or an inserted header).`);
    }
    if (hop.dateError) infos.push(`A Received timestamp did not parse: ${hop.dateError}`);
  }

  // Authentication
  const auth = get("Authentication-Results").map((h) => parseAuthResults(h.value));
  for (const a of auth) {
    for (const r of a.results) {
      if (r.result && AUTH_FAILS.has(r.result)) {
        warnings.push(`Authentication-Results${a.authserv ? ` (${a.authserv})` : ""}: ${r.method}=${r.result}${r.reason ? ` (${r.reason})` : ""}.`);
      }
    }
  }
  const spfHeader = one("Received-SPF");
  if (spfHeader) {
    const verdict = spfHeader.trim().split(/[\s(]/)[0].toLowerCase();
    if (["fail", "softfail", "permerror"].includes(verdict)) {
      warnings.push(`Received-SPF: ${verdict}.`);
    }
  }

  const dkim = get("DKIM-Signature").map((h) => parseDkimSignature(h.value));
  for (const d of dkim) {
    if (d.expiresAt !== null && now && d.expiresAt < now) {
      infos.push(`DKIM signature (d=${d.domain}) expired ${fmtDelay(now - d.expiresAt)} ago (x= tag).`);
    }
    if (d.bodyLengthLimited) warnings.push(`DKIM signature (d=${d.domain}) uses l= body-length limiting — content can be appended without breaking the signature.`);
    if (!d.fromSigned && d.signedHeaders.length) warnings.push(`DKIM signature (d=${d.domain}) does not sign the From header.`);
  }
  if (from.length && dkim.length) {
    const fd = addressDomain(from[0].address);
    if (fd && !dkim.some((d) => d.domain && (fd === d.domain.toLowerCase() || fd.endsWith("." + d.domain.toLowerCase())))) {
      infos.push(`No DKIM signature is aligned with the From domain (${fd}) — DMARC would need SPF alignment instead.`);
    }
  }

  return {
    headers, bodyPresent, notes, warnings, infos,
    subject, from, to, replyTo, dateHeader, chain, auth, dkim,
    messageId: one("Message-ID"),
    returnPath: one("Return-Path"),
  };
}

export function fmtDelay(ms) {
  if (ms < 0) return "-" + fmtDelay(-ms);
  const s = Math.round(ms / 1000);
  if (s < 1) return "under 1s";
  if (s < 120) return `${s}s`;
  if (s < 7200) return `${Math.floor(s / 60)}m ${s % 60 ? (s % 60) + "s" : ""}`.trim();
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.round((s % 86400) / 3600)}h`;
}
