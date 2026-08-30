// cookie.js — Set-Cookie / Cookie header parser, acceptance simulator, and
// send-matching, entirely client-side.
//
// The acceptance model is written to agree with real Chromium, calibrated by
// live differential tests (see cookie.test.js). Chrome-verified behaviors
// baked in:
//   - Any control byte (0x00-0x1F including TAB, or 0x7F) anywhere in the
//     line rejects the whole cookie.
//   - name+value combined > 4096 bytes rejects the cookie; an attribute
//     VALUE > 1024 bytes silently drops just that attribute.
//   - Cookie date tokens parse in any order (time / day / month-name /
//     year); numeric months don't exist; missing seconds means no time;
//     years 0-69 get +2000, 70-99 get +1900; year < 1601 fails.
//   - Expiry is capped at 400 days from now (Max-Age and Expires both).
//     Max-Age must be an optionally-signed integer; "1.5" is ignored.
//   - Duplicate attributes: the LAST occurrence wins.
//   - SameSite=None without Secure rejects the cookie; an unknown SameSite
//     value means default (Lax in Chrome).
//   - __Secure- requires Secure; __Host- requires Secure, no Domain, and
//     Path exactly "/". A rejected prefix rejects the whole cookie.
//   - A Domain attribute equal to a public suffix (or not a suffix of the
//     request host) rejects the cookie; a leading dot is stripped;
//     "localhost" counts as a public suffix in Chrome.
//   - A cookie line with no "=" is a value with an empty name; "=" alone
//     (empty name AND value) is rejected.

'use strict';

const CTRL_RE = /[\x00-\x1f\x7f]/;
const MAX_NAME_VALUE = 4096;
const MAX_ATTR_VALUE = 1024;
const CAP_SECONDS = 400 * 86400;

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

// A deliberately tiny public-suffix check: enough to catch the obvious
// mistakes (setting Domain to a bare TLD or to localhost) without shipping
// the full PSL. The UI says exactly this.
const TINY_PSL = new Set(['localhost', 'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
  'io', 'co', 'dev', 'app', 'uk', 'co.uk', 'org.uk', 'ac.uk', 'de', 'fr', 'jp', 'co.jp',
  'cn', 'com.cn', 'au', 'com.au', 'br', 'com.br', 'github.io', 'herokuapp.com',
  'cloudfront.net', 's3.amazonaws.com', 'pages.dev', 'netlify.app', 'vercel.app']);

// ---------------------------------------------------------------------------
// RFC 6265 §5.1.1 cookie-date parser (returns epoch SECONDS or null).
function parseCookieDate(str) {
  // delimiters: %x09, %x20-2F, %x3B-40, %x5B-60, %x7B-7E
  const tokens = String(str).split(/[\x09\x20-\x2f\x3b-\x40\x5b-\x60\x7b-\x7e]+/).filter(Boolean);
  let time = null, day = null, month = null, year = null;
  for (const t of tokens) {
    if (time === null) {
      const m = /^(\d{1,2}):(\d{1,2}):(\d{1,2})(?:\D.*)?$/.exec(t);
      if (m) { time = [+m[1], +m[2], +m[3]]; continue; }
    }
    if (day === null) {
      const m = /^(\d{1,2})(?:\D.*)?$/.exec(t);
      if (m) { day = +m[1]; continue; }
    }
    if (month === null) {
      const m = MONTHS[t.slice(0, 3).toLowerCase()];
      if (m !== undefined) { month = m; continue; }
    }
    if (year === null) {
      const m = /^(\d{2,4})(?:\D.*)?$/.exec(t);
      if (m) { year = +m[1]; continue; }
    }
  }
  if (time === null || day === null || month === null || year === null) return null;
  if (year >= 70 && year <= 99) year += 1900;
  else if (year >= 0 && year <= 69) year += 2000;
  if (year < 1601 || day < 1 || day > 31 || time[0] > 23 || time[1] > 59 || time[2] > 59) return null;
  const ms = Date.UTC(year, month, day, time[0], time[1], time[2]);
  // reject impossible dates like Feb 30 (Date.UTC would roll them over)
  const d = new Date(ms);
  if (d.getUTCDate() !== day || d.getUTCMonth() !== month) return null;
  return ms / 1000;
}

// ---------------------------------------------------------------------------
// Parsing

// Split pasted text into Set-Cookie lines (strips optional header names).
// Never splits on commas — browsers don't either (dates contain commas).
function parseSetCookieInput(text) {
  const lines = [];
  for (let line of String(text).split(/\r?\n/)) {
    if (!line.trim()) continue;
    const m = /^\s*set-cookie2?\s*:\s*/i.exec(line);
    if (m) line = line.slice(m[0].length);
    lines.push(parseSetCookieLine(line));
  }
  return lines;
}

function parseSetCookieLine(raw) {
  const segments = raw.split(';');
  const nv = segments[0];
  const eq = nv.indexOf('=');
  let name, value;
  if (eq === -1) { name = ''; value = nv.trim(); }
  else { name = nv.slice(0, eq).trim(); value = nv.slice(eq + 1).trim(); }
  const attrs = [];
  for (const seg of segments.slice(1)) {
    if (!seg.trim()) continue;
    const aeq = seg.indexOf('=');
    let an, av;
    if (aeq === -1) { an = seg.trim(); av = null; }
    else { an = seg.slice(0, aeq).trim(); av = seg.slice(aeq + 1).trim(); }
    // note: browsers do NOT strip quotes from attribute values —
    // Path="/x" simply fails the leading-slash check. Quoted Expires
    // dates still parse because '"' is a cookie-date delimiter.
    attrs.push({ rawName: an, name: an.toLowerCase(), value: av });
  }
  return { raw, name, value, attrs };
}

// "Cookie:" request header → list of pairs.
function parseCookieHeader(text) {
  let s = String(text).replace(/^\s*cookie\s*:\s*/i, '').trim();
  const pairs = [];
  for (const seg of s.split(';')) {
    if (!seg.trim()) continue;
    const eq = seg.indexOf('=');
    if (eq === -1) pairs.push({ name: '', value: seg.trim() });
    else pairs.push({ name: seg.slice(0, eq).trim(), value: seg.slice(eq + 1).trim() });
  }
  return pairs;
}

// ---------------------------------------------------------------------------
// Acceptance simulation

function isIpLiteral(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
}
function isTrustworthyHost(host) {
  const h = host.toLowerCase();
  return h === 'localhost' || h.endsWith('.localhost') || h === '127.0.0.1' || h === '[::1]';
}
function defaultPath(requestPath) {
  if (!requestPath.startsWith('/')) return '/';
  const i = requestPath.lastIndexOf('/');
  return i === 0 ? '/' : requestPath.slice(0, i);
}
function domainMatches(host, domain) {
  const h = host.toLowerCase(), d = domain.toLowerCase();
  return h === d || (h.endsWith('.' + d) && !isIpLiteral(host));
}

// analyzeCookie(entry, { pageUrl, now }) — the full verdict for one cookie.
function analyzeCookie(entry, opts = {}) {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  let page;
  try { page = new URL(opts.pageUrl || 'https://example.com/'); } catch { page = new URL('https://example.com/'); }
  const host = page.hostname.toLowerCase();
  const pageSecure = page.protocol === 'https:' || page.protocol === 'wss:' || isTrustworthyHost(host);

  const reject = [];
  const warnings = [];
  const notes = [];

  if (CTRL_RE.test(entry.raw)) {
    reject.push('the line contains a control byte (including TAB) — browsers reject the whole cookie');
  }
  if (entry.name === '' && entry.value === '') {
    reject.push('empty name and empty value — browsers store nothing');
  }
  if (entry.name === '' && entry.value.includes('=')) {
    reject.push('a nameless cookie whose value contains "=" is rejected — reread later, it would turn into a differently-named cookie');
  }
  if (entry.name === '' && /^__(host|secure)-/i.test(entry.value)) {
    reject.push('a nameless cookie whose value starts with __Host-/__Secure- is rejected — it could impersonate a prefixed cookie');
  }
  if (entry.name.length + entry.value.length > MAX_NAME_VALUE) {
    reject.push(`name + value is ${entry.name.length + entry.value.length} bytes — over the 4096-byte limit, the cookie is dropped entirely`);
  }

  // effective attributes: last occurrence wins
  const eff = {};
  const oversized = [];
  for (const a of entry.attrs) {
    if (a.value !== null && a.value.length > MAX_ATTR_VALUE) { oversized.push(a.rawName); continue; }
    eff[a.name] = a;
  }
  if (oversized.length) {
    warnings.push(`attribute value over 1024 bytes: ${oversized.join(', ')} — browsers ignore just that attribute, often silently changing the cookie's scope`);
  }

  // domain
  let domain = host, hostOnly = true;
  if (eff.domain && eff.domain.value) {
    let d = eff.domain.value.replace(/^\./, '').toLowerCase();
    if (d === '') { /* ignore */ }
    else if (TINY_PSL.has(d)) {
      reject.push(`Domain=${d} is a public suffix — browsers refuse cookies scoped to a whole registry (Chrome treats "localhost" as one too)`);
    } else if (!domainMatches(host, d)) {
      reject.push(`Domain=${d} does not cover the page host ${host} — the cookie is rejected`);
    } else {
      domain = d; hostOnly = false;
      if (d !== host) notes.push(`Domain=${d}: sent to ${d} and every subdomain of it`);
      else notes.push(`Domain=${d}: unlike the default host-only scope, this is also sent to every subdomain`);
    }
  } else if (eff.domain) {
    notes.push('empty Domain attribute is ignored (host-only cookie)');
  }

  // path
  let path = defaultPath(page.pathname);
  if (eff.path && eff.path.value && eff.path.value.startsWith('/')) path = eff.path.value;
  else if (eff.path) notes.push('Path without a leading "/" is ignored; the default path from the URL applies');

  // flags
  const secure = 'secure' in eff;
  const httpOnly = 'httponly' in eff;

  // samesite
  let sameSite = 'default';
  if (eff.samesite && eff.samesite.value) {
    const v = eff.samesite.value.toLowerCase();
    if (v === 'strict' || v === 'lax' || v === 'none') sameSite = v;
    else warnings.push(`SameSite=${eff.samesite.value} is not a valid value — browsers treat it as unspecified (Lax by default in Chrome)`);
  }
  if (sameSite === 'none' && !secure) {
    reject.push('SameSite=None requires Secure — without it the cookie is rejected outright');
  }

  // secure from insecure origin
  if (secure && !pageSecure) {
    reject.push(`Secure cookie set from an insecure origin (${page.protocol}//${host}) — rejected`);
  }

  // prefixes (case-insensitive in current Chrome)
  const lower = entry.name.toLowerCase();
  if (lower.startsWith('__host-')) {
    if (!secure) reject.push('__Host- prefix requires Secure');
    if (eff.domain && eff.domain.value) reject.push('__Host- prefix forbids a Domain attribute');
    if (!(eff.path && eff.path.value === '/')) reject.push('__Host- prefix requires Path=/ exactly');
    if (reject.length === 0) notes.push('__Host- prefix: locked to this exact host, secure, site-wide — the strongest cookie form');
  } else if (lower.startsWith('__secure-')) {
    if (!secure) reject.push('__Secure- prefix requires Secure');
  } else if (entry.name.startsWith('__')) {
    warnings.push(`name starts with __ but is not a recognized prefix — only __Host- and __Secure- carry enforced guarantees`);
  }

  // expiry: Max-Age wins over Expires
  let expires = 'session';  // 'session' | epoch seconds | 'past'
  let capped = false;
  let maxAgeInvalid = false;
  if (eff['max-age'] && eff['max-age'].value !== null) {
    const v = eff['max-age'].value;
    if (/^-?\d+$/.test(v)) {
      const n = parseInt(v, 10);
      expires = n <= 0 ? 'past' : now + Math.min(n, CAP_SECONDS);
      capped = n > CAP_SECONDS;
    } else {
      maxAgeInvalid = true;
      warnings.push(`Max-Age=${v} is not an integer — the attribute is ignored (browsers do not accept fractions)`);
    }
  }
  if ((expires === 'session') && eff.expires && eff.expires.value) {
    const t = parseCookieDate(eff.expires.value);
    if (t === null) {
      warnings.push(`Expires=${eff.expires.value} does not parse as a cookie date (needs hh:mm:ss, a month NAME, and a year ≥ 1601) — the cookie becomes a session cookie`);
    } else if (t <= now) {
      expires = 'past';
    } else {
      expires = Math.min(t, now + CAP_SECONDS);
      capped = t > now + CAP_SECONDS;
    }
  } else if (expires !== 'session' && eff.expires) {
    notes.push('both Max-Age and Expires present — Max-Age wins');
  }
  if (capped) notes.push('expiry capped at 400 days from now (Chrome enforces this cap on both Max-Age and Expires)');
  if (expires === 'past' && reject.length === 0) {
    notes.push('expiry is in the past: this does not store a cookie, it DELETES any existing cookie with the same name, domain and path');
  }

  // other attributes
  if (eff.partitioned) {
    if (!secure) warnings.push('Partitioned (CHIPS) requires Secure; without it the attribute is ignored');
    else notes.push('Partitioned: stored per top-level site (CHIPS) — a different jar inside each embedding site');
  }
  if (eff.priority) {
    const v = (eff.priority.value || '').toLowerCase();
    if (['low', 'medium', 'high'].includes(v)) notes.push(`Priority=${v}: Chrome-only eviction hint, not a standard`);
    else warnings.push('Priority takes Low, Medium or High (Chrome-only attribute)');
  }
  const KNOWN_ATTRS = new Set(['domain', 'path', 'secure', 'httponly', 'samesite', 'max-age', 'expires', 'partitioned', 'priority']);
  for (const a of entry.attrs) {
    if (!KNOWN_ATTRS.has(a.name)) warnings.push(`unknown attribute "${a.rawName}" — browsers silently ignore it`);
  }

  // value/content warnings
  if (/[^\x20-\x7e]/.test(entry.value)) {
    warnings.push('the value contains non-ASCII bytes — browsers mangle or reject these; percent- or base64-encode the value instead');
  }
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(entry.value) && entry.value.split('.')[0].startsWith('eyJ')) {
    warnings.push('the value looks like a JWT — decode it in the JWT tool to see what it discloses');
  }
  if (entry.value.includes(',')) {
    notes.push('comma in the value: legal for browsers, but some proxies and older frameworks split header lines on commas');
  }
  if (/^".*"$/.test(entry.value)) {
    notes.push('the surrounding double quotes are PART of the stored value for browsers, though some server frameworks strip them');
  }
  if (entry.name === '') notes.push('no "=" in the first segment: browsers store this as a value with an EMPTY name');
  const size = entry.name.length + entry.value.length;
  if (size > 3500 && size <= MAX_NAME_VALUE) {
    warnings.push(`name + value is ${size} bytes — close to the 4096-byte limit, and this cookie rides along on every single request`);
  }

  // hygiene notes for accepted, non-deletion cookies
  const accepted = reject.length === 0;
  if (accepted && expires !== 'past') {
    if (!httpOnly && /^(sid|sess|session|token|auth|jwt|.*session.*|.*token.*)$/i.test(entry.name)) {
      warnings.push('looks like a session credential without HttpOnly — any XSS can read it via document.cookie');
    }
    if (!secure && page.protocol === 'https:') {
      warnings.push('no Secure flag on a cookie set over HTTPS — it will also be sent over plaintext HTTP');
    }
    if (sameSite === 'default') {
      notes.push('no SameSite: Chrome defaults to Lax (plus a 2-minute window where it still accompanies cross-site POSTs); Safari and Firefox differ — say what you mean');
    }
    if (sameSite === 'none') notes.push('SameSite=None: sent on ALL cross-site requests — this is what makes CSRF and tracking possible; make sure that is intended');
    if (typeof expires === 'number' && expires - now > 366 * 86400) {
      notes.push('expiry over a year away — fine for preferences, a liability for anything identifying');
    }
  }

  // comma-fold hazard: one line that is probably several cookies
  if (/,\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+=[^;]*(;|$)/.test(entry.raw) && !/expires\s*=/i.test(entry.raw)) {
    warnings.push('this line looks like several Set-Cookie headers folded together with commas — browsers do NOT split on commas; everything after the comma ends up inside a single value or is dropped');
  }

  return {
    accepted, rejectReasons: reject, warnings, notes,
    stored: accepted ? {
      name: entry.name, value: entry.value, domain, hostOnly, path,
      expires, secure, httpOnly, sameSite,
      partitioned: !!(eff.partitioned && secure),
    } : null,
  };
}

// ---------------------------------------------------------------------------
// Would this stored cookie be sent with a request?

// context: 'same-site' | 'cross-site-nav' (top-level link/redirect) |
//          'cross-site-sub' (embedded fetch/img/iframe)
function wouldSend(stored, requestUrlStr, context = 'same-site') {
  const reasons = [];
  let url;
  try { url = new URL(requestUrlStr); } catch { return { sent: false, reasons: ['not a parseable absolute URL'] }; }
  const host = url.hostname.toLowerCase();
  const scheme = url.protocol.slice(0, -1);

  if (stored.secure && !(scheme === 'https' || scheme === 'wss' || isTrustworthyHost(host))) {
    reasons.push('Secure cookie, non-HTTPS request');
  }
  if (stored.hostOnly ? host !== stored.domain : !domainMatches(host, stored.domain)) {
    reasons.push(stored.hostOnly
      ? `host-only cookie for ${stored.domain}; ${host} does not match exactly`
      : `domain cookie for ${stored.domain}; ${host} is not it or a subdomain`);
  }
  const p = url.pathname || '/';
  const cp = stored.path;
  const pathOk = p === cp || (p.startsWith(cp) && (cp.endsWith('/') || p[cp.length] === '/'));
  if (!pathOk) reasons.push(`path ${p} is not under cookie path ${cp}`);

  const ss = stored.sameSite === 'default' ? 'lax' : stored.sameSite;
  if (context === 'cross-site-sub' && ss !== 'none') {
    reasons.push(`SameSite=${ss === stored.sameSite ? ss : 'Lax (default)'} cookie on a cross-site subresource/fetch`);
  }
  if (context === 'cross-site-nav' && ss === 'strict') {
    reasons.push('SameSite=Strict cookie on a cross-site top-level navigation');
  }
  return { sent: reasons.length === 0, reasons };
}

const exported = {
  parseSetCookieInput, parseSetCookieLine, parseCookieHeader, parseCookieDate,
  analyzeCookie, wouldSend,
  _internal: { defaultPath, domainMatches, TINY_PSL },
};
if (typeof module !== 'undefined' && module.exports) module.exports = exported;
if (typeof window !== 'undefined') window.COOKIE = exported;
