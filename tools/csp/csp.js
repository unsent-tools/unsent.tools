// csp.js — Content-Security-Policy parser, analyzer, and URL-match evaluator.
//
// The matching algorithm (matchesSourceList, selfMatches) is written to agree
// with real Chromium behavior, calibrated by differential testing against a
// headless Chrome (see csp.test.js). Where the CSP3 spec is loose or where
// implementations differ, the comments say what was observed. Notable
// Chrome-verified behaviors baked in here:
//   - A scheme match "via upgrade" (http source, https URL — or ws→wss) only
//     matches if the URL port is 443 and the source port is unspecified, 80,
//     443, or "*". Port equality does NOT count under an upgraded scheme
//     (x.example:8080 does not match https://x.example:8080/).
//   - A source with no scheme takes the page's scheme (plus http→https
//     upgrade); with no port it requires the URL's default port.
//   - Host grammar: letters/digits/hyphen labels only ("_" rejected), "*."
//     only as a leading full label, optional trailing dot matched literally.
//     IPv6 literal sources can never match (the grammar can't express them).
//   - Paths compare percent-DECODED on both sides (so %2F counts as "/");
//     invalid escapes stay literal. Trailing-slash source path = prefix
//     match, otherwise exact. Query/fragment in a source path is ignored.
//   - 'none' is ignored when any other source is present. An empty source
//     list blocks everything.

'use strict';

// ---------------------------------------------------------------------------
// Directive registry

const FETCH = 'fetch'; // source-list fetch directive (participates in default-src fallback)

// status: 'ok' | 'deprecated' | 'removed' | 'experimental'
const DIRECTIVES = {
  'default-src':      { kind: FETCH },
  'script-src':       { kind: FETCH },
  'script-src-elem':  { kind: FETCH },
  'script-src-attr':  { kind: FETCH },
  'style-src':        { kind: FETCH },
  'style-src-elem':   { kind: FETCH },
  'style-src-attr':   { kind: FETCH },
  'img-src':          { kind: FETCH },
  'font-src':         { kind: FETCH },
  'connect-src':      { kind: FETCH },
  'media-src':        { kind: FETCH },
  'object-src':       { kind: FETCH },
  'child-src':        { kind: FETCH },
  'frame-src':        { kind: FETCH },
  'worker-src':       { kind: FETCH },
  'manifest-src':     { kind: FETCH },
  'prefetch-src':     { kind: FETCH, status: 'deprecated', note: 'prefetch-src was removed from the spec and from Chrome 112; prefetches now follow the directive of the eventual use.' },
  'fenced-frame-src': { kind: FETCH, status: 'experimental' },
  'base-uri':         { kind: 'sourcelist' },   // source list, but no default-src fallback
  'form-action':      { kind: 'sourcelist' },
  'frame-ancestors':  { kind: 'sourcelist', metaIgnored: true },
  'navigate-to':      { kind: 'sourcelist', status: 'removed', note: 'navigate-to was removed from the CSP3 draft and never shipped in any browser.' },
  'sandbox':          { kind: 'tokens', metaIgnored: true },
  'report-uri':       { kind: 'uris', metaIgnored: true, status: 'deprecated', note: 'report-uri is deprecated in favor of report-to, but report-to is not yet supported everywhere; specify both.' },
  'report-to':        { kind: 'token' },
  'upgrade-insecure-requests': { kind: 'novalue' },
  'block-all-mixed-content':   { kind: 'novalue', status: 'deprecated', note: 'block-all-mixed-content is deprecated; mixed content is blocked/upgraded by default in modern browsers.' },
  'trusted-types':             { kind: 'tt-policies' },
  'require-trusted-types-for': { kind: 'tt-sink' },
  'webrtc':                    { kind: 'webrtc' },
  // removed/ancient — recognized so we can say something useful
  'plugin-types': { kind: 'tokens', status: 'removed', note: 'plugin-types was removed along with Flash-era plugins; use object-src \'none\'.' },
  'referrer':     { kind: 'tokens', status: 'removed', note: 'referrer never left CSP drafts; use the Referrer-Policy header.' },
  'reflected-xss':{ kind: 'tokens', status: 'removed', note: 'reflected-xss never shipped; XSS auditors are gone from all browsers.' },
  'disown-opener':{ kind: 'novalue', status: 'removed', note: 'disown-opener never shipped; use the Cross-Origin-Opener-Policy header.' },
  'require-sri-for': { kind: 'tokens', status: 'removed', note: 'require-sri-for was experimental and never shipped broadly.' },
};

// Fallback chains, most specific first (CSP3 "effective directive" logic).
const FALLBACK = {
  'script-src-elem': ['script-src-elem', 'script-src', 'default-src'],
  'script-src-attr': ['script-src-attr', 'script-src', 'default-src'],
  'style-src-elem':  ['style-src-elem', 'style-src', 'default-src'],
  'style-src-attr':  ['style-src-attr', 'style-src', 'default-src'],
  'worker-src':      ['worker-src', 'child-src', 'script-src', 'default-src'],
  'frame-src':       ['frame-src', 'child-src', 'default-src'],
  'fenced-frame-src':['fenced-frame-src', 'frame-src', 'child-src', 'default-src'],
  'child-src':       ['child-src', 'default-src'],
  'script-src':      ['script-src', 'default-src'],
  'style-src':       ['style-src', 'default-src'],
  'img-src':         ['img-src', 'default-src'],
  'font-src':        ['font-src', 'default-src'],
  'connect-src':     ['connect-src', 'default-src'],
  'media-src':       ['media-src', 'default-src'],
  'object-src':      ['object-src', 'default-src'],
  'manifest-src':    ['manifest-src', 'default-src'],
  'prefetch-src':    ['prefetch-src', 'default-src'],
  'base-uri':        ['base-uri'],
  'form-action':     ['form-action'],
  'frame-ancestors': ['frame-ancestors'],
};

// What a user can test a URL as.
const RESOURCE_TYPES = {
  script:   { label: '<script src> (script element)', directive: 'script-src-elem', nonceable: true },
  style:    { label: '<link rel=stylesheet>', directive: 'style-src-elem', nonceable: true },
  img:      { label: '<img> / favicon', directive: 'img-src' },
  font:     { label: '@font-face font', directive: 'font-src' },
  connect:  { label: 'fetch / XHR / WebSocket / EventSource', directive: 'connect-src' },
  media:    { label: '<audio> / <video>', directive: 'media-src' },
  frame:    { label: '<iframe>', directive: 'frame-src' },
  worker:   { label: 'Worker / SharedWorker / ServiceWorker', directive: 'worker-src' },
  object:   { label: '<object> / <embed>', directive: 'object-src' },
  manifest: { label: 'web app manifest', directive: 'manifest-src' },
  form:     { label: 'form action (submit target)', directive: 'form-action' },
  base:     { label: '<base href>', directive: 'base-uri' },
};

const KEYWORDS = new Set([
  'self', 'none', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic',
  'unsafe-hashes', 'unsafe-hashed-attributes', 'wasm-unsafe-eval', 'wasm-eval',
  'report-sample', 'inline-speculation-rules', 'unsafe-allow-redirects',
  'allow-duplicates', 'block', 'allow', 'script',
]);

const DEFAULT_PORTS = { http: 80, https: 443, ws: 80, wss: 443, ftp: 21 };

// ---------------------------------------------------------------------------
// Parsing

// Split header-ish input into policies. Accepts: a bare policy; full header
// lines ("Content-Security-Policy: ..."); multiple lines; commas inside a
// line split policies too (RFC 9110 combined field lines).
function parseHeader(text) {
  const policies = [];
  const lines = String(text).split(/\r?\n/);
  let sawHeaderName = false;
  for (const line of lines) {
    if (!line.trim()) continue;
    let rest = line;
    let disposition = 'enforce';
    const m = /^\s*content-security-policy(-report-only)?\s*:\s*/i.exec(line);
    if (m) {
      sawHeaderName = true;
      disposition = m[1] ? 'report-only' : 'enforce';
      rest = line.slice(m[0].length);
    }
    for (const part of rest.split(',')) {
      if (!part.trim()) continue;
      policies.push(parsePolicy(part, disposition));
    }
  }
  return { policies, sawHeaderName };
}

function parsePolicy(raw, disposition = 'enforce') {
  const directives = [];
  const map = Object.create(null);
  for (const chunk of raw.split(';')) {
    const tokens = chunk.match(/[^\t\n\f\r ]+/g);
    if (!tokens) continue;
    const rawName = tokens[0];
    const name = rawName.toLowerCase();
    const values = tokens.slice(1);
    const dup = name in map;
    directives.push({ rawName, name, values, ignored: dup });
    if (!dup) map[name] = values;
  }
  return { raw: raw.trim(), disposition, directives, map };
}

// ---------------------------------------------------------------------------
// Source-expression classification

const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+.-]*):$/;
const HOST_SOURCE_RE = new RegExp(
  '^(?:([A-Za-z][A-Za-z0-9+.-]*)://)?' +              // scheme://
  '(\\*|(?:\\*\\.)?[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.?)' + // host (wildcard only as leading label)
  '(?::(\\*|[0-9]+))?' +                              // :port
  '(/[^?#]*)?' +                                      // path
  '([?#].*)?$'                                        // query/fragment (ignored by browsers)
);
const STRICT_NONCE_RE = /^'nonce-([A-Za-z0-9+/_-]+={0,2})'$/i;
const STRICT_HASH_RE = /^'(sha256|sha384|sha512)-([A-Za-z0-9+/_-]+={0,2})'$/i;

// classifySource(token) -> { kind, ... }
//  kind: 'keyword' | 'nonce' | 'hash' | 'scheme' | 'host' | 'invalid'
function classifySource(token) {
  if (token.startsWith("'")) {
    const lower = token.toLowerCase();
    const inner = lower.replace(/^'|'$/g, '');
    if (token.endsWith("'") && token.length > 1 && KEYWORDS.has(inner)) {
      return { kind: 'keyword', keyword: inner };
    }
    let m = STRICT_NONCE_RE.exec(token);
    if (m) return { kind: 'nonce', nonce: m[1] };
    m = STRICT_HASH_RE.exec(token);
    if (m) return { kind: 'hash', alg: m[1].toLowerCase(), digest: m[2] };
    if (/^'nonce-/i.test(token)) return { kind: 'invalid', reason: 'malformed nonce (empty or non-base64 characters)' };
    if (/^'sha\d/i.test(token)) return { kind: 'invalid', reason: 'malformed hash (empty or non-base64 characters)' };
    return { kind: 'invalid', reason: 'not a recognized quoted keyword' };
  }
  let m = SCHEME_RE.exec(token);
  if (m) return { kind: 'scheme', scheme: m[1].toLowerCase() };
  m = HOST_SOURCE_RE.exec(token);
  if (m) {
    const [, scheme, host, port, path, junk] = m;
    return {
      kind: 'host',
      scheme: scheme ? scheme.toLowerCase() : null,
      host,
      port: port === undefined ? null : port,
      path: path || '',
      junk: junk || '',  // "?..." / "#..." — present in the token but ignored by browsers
    };
  }
  let reason = 'not a valid source expression';
  if (/^\[[0-9A-Fa-f:.]+\]/.test(token) || /^[0-9A-Fa-f]*:[0-9A-Fa-f:]+$/.test(token)) {
    reason = 'IPv6 literals cannot be expressed in CSP host grammar; this source never matches';
  } else if (token.includes('@')) {
    reason = 'user@host is not allowed in a source expression';
  } else if (/^(\*\.)?.*\*/.test(token) && token !== '*') {
    reason = "'*' is only allowed alone, as a port, or as a leading '*.' host label";
  } else if (token.includes('_')) {
    reason = 'underscores are not allowed in CSP host names (letters, digits, hyphens only)';
  } else if (/^[A-Za-z][A-Za-z0-9+.-]*\/\//.test(token)) {
    reason = 'looks like a scheme with a missing colon';
  }
  return { kind: 'invalid', reason };
}

// ---------------------------------------------------------------------------
// URL matching (Chrome-calibrated)

// Percent-decode, leaving invalid escape sequences literal.
function lenientDecode(s) {
  return s.replace(/(%[0-9A-Fa-f]{2})+/g, (seq) => {
    try { return decodeURIComponent(seq); } catch { return seq; }
  });
}

function urlPortOf(u) {
  if (u.port !== '') return parseInt(u.port, 10);
  return DEFAULT_PORTS[u.protocol.slice(0, -1)] ?? null;
}

// scheme match: exact, or upgrade (http→https, ws→wss). Returns
// 'match' | 'upgrade' | null.
function schemeMatch(sourceScheme, urlScheme) {
  if (sourceScheme === urlScheme) return 'match';
  if (sourceScheme === 'http' && urlScheme === 'https') return 'upgrade';
  if (sourceScheme === 'ws' && urlScheme === 'wss') return 'upgrade';
  return null;
}

function hostMatch(pattern, host) {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p === '*') return true;
  if (p.startsWith('*.')) {
    const rest = p.slice(1); // ".x.example"
    return h.length > rest.length && h.endsWith(rest);
  }
  return p === h;
}

function pathMatch(sourcePath, urlPath) {
  if (sourcePath === '' || sourcePath === '/') return true;
  const sp = lenientDecode(sourcePath);
  const up = lenientDecode(urlPath || '/');
  if (sp.endsWith('/')) return up.startsWith(sp);
  return up === sp;
}

// One host-source expression vs a URL. `pageScheme` fills in a missing
// source scheme.
function hostSourceMatches(src, url, pageScheme) {
  const s = src.scheme || pageScheme;
  const urlScheme = url.protocol.slice(0, -1);
  let sm;
  if (src.host === '*' && !src.scheme && src.port === null && !src.path) {
    // plain "*": any network scheme (data:/blob:/filesystem: need explicit listing)
    return !['data', 'blob', 'filesystem', 'about', 'javascript'].includes(urlScheme);
  }
  sm = schemeMatch(s, urlScheme);
  if (!sm) return false;
  if (!url.hostname || !hostMatch(src.host, url.hostname)) return false;
  const urlPort = urlPortOf(url);
  if (src.port === '*') {
    // wildcard port: any port, either scheme path
  } else if (sm === 'upgrade') {
    // Chrome: under a scheme upgrade the port must upgrade too — URL port
    // must be 443, and the source port must itself be upgradeable
    // (unspecified, 80, or 443).
    if (urlPort !== 443) return false;
    const sp = src.port === null ? null : parseInt(src.port, 10);
    if (sp !== null && sp !== 80 && sp !== 443) return false;
  } else if (src.port !== null) {
    if (urlPort !== parseInt(src.port, 10)) return false;
  } else {
    if (urlPort !== (DEFAULT_PORTS[urlScheme] ?? null)) return false;
  }
  return pathMatch(src.path, url.pathname);
}

// 'self' per CSP3 §6.6.1 (verified against Chrome): same origin, or same
// host with an https/wss URL and matching-or-both-default ports.
function selfMatches(url, pageOrigin) {
  let origin;
  try { origin = new URL(pageOrigin); } catch { return false; }
  const oScheme = origin.protocol.slice(0, -1);
  const uScheme = url.protocol.slice(0, -1);
  if (origin.hostname.toLowerCase() !== url.hostname.toLowerCase()) return false;
  const oPort = urlPortOf(origin);
  const uPort = urlPortOf(url);
  if (oScheme === uScheme && oPort === uPort) return true;
  if (uScheme === 'https' || uScheme === 'wss') {
    if (uPort === oPort) return true;
    if (uPort === DEFAULT_PORTS[uScheme] && oPort === DEFAULT_PORTS[oScheme]) return true;
  }
  return false;
}

// matchesSourceList(values, urlStr, pageOrigin) ->
//   { allowed, matched: token|null, notes: string[] }
// Pure allowlist matching: nonces/hashes/strict-dynamic never match a URL
// (evaluateLoad layers their semantics on top).
function matchesSourceList(values, urlStr, pageOrigin) {
  const notes = [];
  let url;
  try { url = new URL(urlStr); } catch { return { allowed: false, matched: null, notes: ['not a parseable absolute URL'] }; }
  const pageScheme = (() => {
    try { return new URL(pageOrigin).protocol.slice(0, -1); } catch { return 'https'; }
  })();
  const real = values.filter((v) => classifySource(v).kind !== 'keyword' || classifySource(v).keyword !== 'none');
  if (values.length > real.length && real.length > 0) {
    notes.push("'none' is ignored because other sources are present");
  }
  for (const token of real) {
    const c = classifySource(token);
    switch (c.kind) {
      case 'keyword':
        if (c.keyword === 'self' && selfMatches(url, pageOrigin)) {
          return { allowed: true, matched: token, notes };
        }
        break; // other keywords never match a URL
      case 'scheme': {
        const sm = schemeMatch(c.scheme, url.protocol.slice(0, -1));
        if (sm) return { allowed: true, matched: token, notes };
        break;
      }
      case 'host':
        if (hostSourceMatches(c, url, pageScheme)) {
          return { allowed: true, matched: token, notes };
        }
        break;
      default:
        break; // nonce/hash/invalid: never match a URL
    }
  }
  if (real.length === 0 && values.length > 0) {
    notes.push(values.some((v) => classifySource(v).keyword === 'none')
      ? "'none': blocks everything"
      : 'source list has no usable sources; blocks everything');
  } else if (values.length === 0) {
    notes.push("empty source list blocks everything (same as 'none')");
  }
  return { allowed: false, matched: null, notes };
}

// ---------------------------------------------------------------------------
// Load evaluation (which directive governs, what's the verdict)

function governingDirective(policy, type) {
  const chain = FALLBACK[RESOURCE_TYPES[type].directive];
  for (const name of chain) {
    if (name in policy.map) return { directive: name, chain };
  }
  return { directive: null, chain };
}

// evaluateLoad(parsed, type, urlStr, pageOrigin) ->
//   { results: [per policy], verdict: 'allowed'|'blocked'|'conditional' }
function evaluateLoad(parsed, type, urlStr, pageOrigin) {
  const results = [];
  for (const policy of parsed.policies) {
    const { directive, chain } = governingDirective(policy, type);
    if (!directive) {
      results.push({
        policy, directive: null, chain, verdict: 'allowed', matched: null,
        notes: [`no ${chain.join(' / ')} directive — this policy does not restrict this load`],
      });
      continue;
    }
    const values = policy.map[directive];
    const { allowed, matched, notes } = matchesSourceList(values, urlStr, pageOrigin);
    let verdict = allowed ? 'allowed' : 'blocked';
    const isScript = type === 'script' || type === 'worker';
    if (isScript && values.some((v) => classifySource(v).keyword === 'strict-dynamic')) {
      // strict-dynamic (CSP3): host/scheme/'self' sources are ignored for
      // scripts; only nonces/hashes and trusted propagation load scripts.
      verdict = 'conditional';
      notes.push("'strict-dynamic': host and scheme sources are ignored; this loads only with a valid nonce/hash on the script tag, or if injected by an already-trusted script");
    } else if (!allowed && RESOURCE_TYPES[type].nonceable &&
               values.some((v) => ['nonce', 'hash'].includes(classifySource(v).kind))) {
      notes.push('blocked by the source list, but a matching nonce/hash attribute on the element would allow it');
    }
    if (!allowed && policy.disposition === 'report-only') {
      notes.push('report-only policy: the load is NOT actually blocked, only reported');
    }
    results.push({ policy, directive, chain, verdict, matched, notes });
  }
  // Combined verdict: every enforced policy must allow.
  const enforced = results.filter((r) => r.policy.disposition === 'enforce');
  let verdict = 'allowed';
  if (enforced.some((r) => r.verdict === 'blocked')) verdict = 'blocked';
  else if (enforced.some((r) => r.verdict === 'conditional')) verdict = 'conditional';
  return { results, verdict };
}

// ---------------------------------------------------------------------------
// Analyzer

// Small curated list of allowlist-bypass hosts: hosting JSONP endpoints or
// AngularJS builds that allow full script execution if allowlisted. From
// public CSP-bypass research (Lekies et al., "CSP Is Dead, Long Live CSP!",
// CCS 2016) and widely-known CDN layouts. Deliberately small: only hosts
// that are (a) commonly allowlisted and (b) well documented as bypassable.
const BYPASS_HOSTS = {
  'www.google.com': 'JSONP endpoints',
  'ajax.googleapis.com': 'AngularJS builds and JSONP',
  'www.googleapis.com': 'JSONP endpoints',
  'translate.googleapis.com': 'JSONP endpoints',
  'www.google-analytics.com': 'JSONP-style callbacks',
  'cdnjs.cloudflare.com': 'AngularJS and Prototype builds',
  'cdn.jsdelivr.net': 'AngularJS builds (and any npm package)',
  'unpkg.com': 'any npm package, including AngularJS',
  'code.jquery.com': 'jQuery(-ui) with $.globalEval gadgets',
  'ajax.aspnetcdn.com': 'AngularJS builds',
  'yandex.st': 'AngularJS builds',
  'ads.pubmatic.com': 'JSONP endpoints',
  's.wordpress.com': 'JSONP endpoints',
};

function effectiveDirectiveFor(policy, directive) {
  const chain = FALLBACK[directive] || [directive];
  for (const name of chain) if (name in policy.map) return name;
  return null;
}

function editDistance(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1, dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
  }
  return dp[a.length][b.length];
}

function suggestDirective(name) {
  let best = null, bestD = 3;
  for (const known of Object.keys(DIRECTIVES)) {
    const d = editDistance(name, known);
    if (d < bestD) { bestD = d; best = known; }
  }
  return best;
}

const SANDBOX_TOKENS = new Set([
  'allow-downloads', 'allow-forms', 'allow-modals', 'allow-orientation-lock',
  'allow-pointer-lock', 'allow-popups', 'allow-popups-to-escape-sandbox',
  'allow-presentation', 'allow-same-origin', 'allow-scripts',
  'allow-storage-access-by-user-activation', 'allow-top-navigation',
  'allow-top-navigation-by-user-activation', 'allow-top-navigation-to-custom-protocols',
]);

// analyze(parsed, { delivery: 'header'|'meta' }) -> findings[]
// finding: { id, level: 'high'|'medium'|'info'|'syntax', policy: i, directive?, value?, message }
function analyze(parsed, opts = {}) {
  const delivery = opts.delivery || 'header';
  const findings = [];
  const add = (id, level, policyIndex, directive, value, message) =>
    findings.push({ id, level, policy: policyIndex, directive, value, message });

  parsed.policies.forEach((policy, pi) => {
    const map = policy.map;

    // --- structural / syntax ------------------------------------------------
    for (const d of policy.directives) {
      if (d.ignored) {
        add('duplicate-directive', 'medium', pi, d.name, null,
          `duplicate ${d.name} directive — browsers use the FIRST occurrence and ignore this one entirely`);
        continue;
      }
      const seen = new Set();
      for (const v of d.values) {
        const key = v.toLowerCase();
        if (seen.has(key)) {
          add('duplicate-value', 'info', pi, d.name, v, `${v} appears more than once in ${d.name} (harmless, but probably unintended)`);
        }
        seen.add(key);
      }
      if (!(d.name in DIRECTIVES)) {
        if (d.name.endsWith(':')) {
          add('unknown-directive', 'syntax', pi, d.name, null, `directive names don't end with a colon: "${d.name}"`);
        } else {
          const sug = suggestDirective(d.name);
          add('unknown-directive', 'syntax', pi, d.name, null,
            `"${d.name}" is not a CSP directive${sug ? ` — did you mean ${sug}?` : ''}`);
        }
        continue;
      }
      const info = DIRECTIVES[d.name];
      if (info.status === 'deprecated' || info.status === 'removed') {
        add('deprecated-directive', d.name === 'report-uri' ? 'info' : 'medium', pi, d.name, null,
          info.note || `${d.name} is ${info.status}`);
      }
      if (info.kind === 'novalue' && d.values.length > 0) {
        add('valueless-directive', 'syntax', pi, d.name, d.values.join(' '),
          `${d.name} takes no value — "${d.values.join(' ')}" is ignored`);
      }
      if (delivery === 'meta' && info.metaIgnored) {
        add('meta-ignored', 'high', pi, d.name, null,
          `${d.name} is ignored when the policy is delivered in a <meta> tag — it only works as an HTTP header`);
      }
      if (d.name === 'webrtc' && !(d.values.length === 1 && /^'(allow|block)'$/i.test(d.values[0]))) {
        add('bad-value', 'syntax', pi, d.name, d.values.join(' '), `webrtc takes exactly one of 'allow' or 'block'`);
      }
      if (d.name === 'require-trusted-types-for' && !d.values.some((v) => /^'script'$/i.test(v))) {
        add('bad-value', 'syntax', pi, d.name, d.values.join(' '), `require-trusted-types-for needs the value 'script'`);
      }
      if (d.name === 'sandbox') {
        for (const v of d.values) {
          if (!SANDBOX_TOKENS.has(v.toLowerCase())) {
            add('bad-value', 'syntax', pi, d.name, v, `"${v}" is not a sandbox token`);
          }
        }
      }

      // per-value checks on source-list directives
      if (info.kind === FETCH || info.kind === 'sourcelist') {
        for (const v of d.values) {
          const c = classifySource(v);
          if (c.kind === 'invalid') {
            add('invalid-source', 'medium', pi, d.name, v, `${v}: ${c.reason}`);
          } else if (c.kind === 'host') {
            if (/^(https?|wss?|ftp|data|blob|filesystem)$/i.test(c.host) && c.path.startsWith('//')) {
              add('suspicious-host', 'medium', pi, d.name, v,
                `${v} parses as host "${c.host}" with path "${c.path}" — missing colon after the scheme?`);
            }
            if (c.junk) {
              add('query-in-source', 'syntax', pi, d.name, v,
                `everything from "${c.junk[0]}" on is ignored in a source expression — browsers match only scheme/host/port/path`);
            }
            const bare = c.host.replace(/\.$/, '').toLowerCase();
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) {
              if (bare === '127.0.0.1' || bare.startsWith('127.')) {
                add('ip-source', 'info', pi, d.name, v, `${v} allows loopback — fine for development, remove in production`);
              } else {
                add('ip-source', 'info', pi, d.name, v,
                  `${v} is an IP-address source — it works in Chrome, but certificates and deployments rarely stay pinned to raw IPs`);
              }
            }
          } else if (c.kind === 'nonce') {
            if (c.nonce.length < 8) {
              add('nonce-length', 'medium', pi, d.name, v, 'nonce values should be at least 8 characters (64+ bits) of fresh randomness per response');
            }
          }
          if (/^http:\/\//i.test(v)) {
            add('src-http', 'medium', pi, d.name, v, `${v} allows plaintext HTTP — the source (and page) can be tampered with in transit`);
          }
        }
        const nonNone = d.values.filter((v) => classifySource(v).keyword !== 'none');
        if (nonNone.length !== d.values.length && nonNone.length > 0) {
          add('none-with-others', 'medium', pi, d.name, "'none'",
            `'none' is ignored when other sources are listed in ${d.name}`);
        }
      }
      if (d.name === 'report-uri') {
        for (const v of d.values) {
          if (/^http:\/\//i.test(v)) {
            add('src-http', 'medium', pi, d.name, v, `violation reports go over plaintext HTTP — they contain page URLs and can be read in transit`);
          }
        }
      }
    }

    // unquoted keywords / directive-name-as-value (missing semicolon)
    for (const d of policy.directives) {
      if (d.ignored) continue;
      for (const v of d.values) {
        const lv = v.toLowerCase();
        if (lv in DIRECTIVES) {
          add('missing-semicolon', 'syntax', pi, d.name, v,
            `"${v}" looks like a directive name used as a value — did you forget a semicolon?`);
        } else if (KEYWORDS.has(lv) || /^nonce-/i.test(v) || /^(sha256|sha384|sha512)-/i.test(v)) {
          add('unquoted-keyword', 'syntax', pi, d.name, v,
            `"${v}" only counts as a keyword inside single quotes — bare, it's read as a host name`);
        }
      }
    }

    // --- script-context security checks ------------------------------------
    const scriptContexts = new Set(
      ['script-src', 'script-src-elem', 'script-src-attr']
        .map((n) => effectiveDirectiveFor(policy, n)).filter(Boolean));

    for (const ctx of scriptContexts) {
      const values = map[ctx];
      const hasNonceOrHash = values.some((v) => ['nonce', 'hash'].includes(classifySource(v).kind));
      const hasStrictDynamic = values.some((v) => classifySource(v).keyword === 'strict-dynamic');

      if (values.some((v) => classifySource(v).keyword === 'unsafe-inline')) {
        if (hasNonceOrHash) {
          add('ignored-unsafe-inline', 'info', pi, ctx, "'unsafe-inline'",
            `'unsafe-inline' in ${ctx} is ignored because a nonce or hash is present (CSP2+) — it only takes effect in ancient browsers`);
        } else if (!hasStrictDynamic) {
          add('unsafe-inline', 'high', pi, ctx, "'unsafe-inline'",
            `'unsafe-inline' in ${ctx} allows any injected <script> or event handler to run — it disables the main protection CSP exists for`);
        }
      }
      if (values.some((v) => classifySource(v).keyword === 'unsafe-eval')) {
        add('unsafe-eval', 'medium', pi, ctx, "'unsafe-eval'",
          `'unsafe-eval' in ${ctx} allows eval()/new Function() — injected strings can become code`);
      }
      if (values.some((v) => classifySource(v).keyword === 'unsafe-hashes')) {
        add('unsafe-hashes', 'medium', pi, ctx, "'unsafe-hashes'",
          `'unsafe-hashes' in ${ctx} lets hashed inline event handlers run from ANY element — safer than 'unsafe-inline', but still executes attacker-positioned handlers`);
      }
      if (hasStrictDynamic) {
        if (!hasNonceOrHash) {
          add('strict-dynamic-alone', 'high', pi, ctx, "'strict-dynamic'",
            `'strict-dynamic' in ${ctx} with no nonce or hash blocks ALL scripts in CSP3 browsers — nothing can establish initial trust`);
        }
        for (const v of values) {
          const c = classifySource(v);
          if (c.kind === 'scheme' || c.kind === 'host' ||
              ['self', 'unsafe-inline'].includes(c.keyword)) {
            add('ignored-strict-dynamic', 'info', pi, ctx, v,
              `${v} in ${ctx} is ignored in CSP3 browsers because of 'strict-dynamic'`);
          }
        }
      }
      if (!hasStrictDynamic) {
        for (const v of values) {
          const c = classifySource(v);
          if (c.kind === 'scheme' && ['data', 'http', 'https'].includes(c.scheme)) {
            add('plain-scheme', 'high', pi, ctx, v,
              `${v} in ${ctx} allows scripts from ${c.scheme === 'data' ? 'data: URLs — a classic XSS vector' : 'ANY ' + c.scheme + ' host'}`);
          } else if (c.kind === 'host') {
            if (c.host === '*' && !c.scheme && c.port === null && !c.path) {
              add('wildcard', 'high', pi, ctx, v, `* in ${ctx} allows scripts from anywhere`);
            } else {
              const bare = c.host.replace(/^\*\./, '').replace(/\.$/, '').toLowerCase();
              const hit = BYPASS_HOSTS[c.host.toLowerCase()] || BYPASS_HOSTS[bare] ||
                (c.host.startsWith('*.') && Object.keys(BYPASS_HOSTS).find((h) => h.endsWith('.' + bare)) ?
                  'bypassable endpoints (wildcard covers a known-bypassable host)' : null);
              if (hit && !c.path) {
                add('known-bypass', 'high', pi, ctx, v,
                  `${v} is known to host ${typeof hit === 'string' ? hit : 'bypass gadgets'} that can defeat this policy — allowlisting this host ≈ no script protection`);
              }
            }
          }
        }
      }
    }

    // object-src / base-uri wildcard-ish checks (same spirit as script)
    for (const name of ['object-src', 'base-uri']) {
      const eff = name === 'object-src' ? effectiveDirectiveFor(policy, name) : (name in map ? name : null);
      if (!eff) continue;
      for (const v of map[eff]) {
        const c = classifySource(v);
        if (c.kind === 'host' && c.host === '*' && !c.scheme && c.port === null && !c.path) {
          add('wildcard', 'high', pi, eff, v, `* in ${eff} — ${name === 'object-src' ? 'plugin content from anywhere can execute script' : 'an injected <base> tag can redirect every relative URL'}`);
        } else if (c.kind === 'scheme' && ['data', 'http', 'https'].includes(c.scheme)) {
          add('plain-scheme', 'high', pi, eff, v, `${v} in ${eff} is effectively no restriction`);
        }
      }
    }

    // --- missing directives -------------------------------------------------
    if (!('object-src' in map) && !('default-src' in map)) {
      add('missing-object-src', 'high', pi, 'object-src', null,
        "no object-src (and no default-src fallback): injected <object>/<embed> content can execute script — add object-src 'none'");
    }
    if (!('script-src' in map) && !('default-src' in map)) {
      add('missing-script-src', 'high', pi, 'script-src', null,
        'no script-src and no default-src: scripts from anywhere are allowed — this policy does not prevent XSS');
    }
    // base-uri matters when scripts are trusted by URL-relative means: a
    // nonce (nonced <script src="/app.js"> follows an injected <base>), or
    // hashes combined with 'strict-dynamic'. A plain hash pins exact content,
    // so <base> injection can't redirect it.
    const scriptEff = effectiveDirectiveFor(policy, 'script-src');
    const nonced = scriptEff && (
      map[scriptEff].some((v) => classifySource(v).kind === 'nonce') ||
      (map[scriptEff].some((v) => classifySource(v).kind === 'hash') &&
       map[scriptEff].some((v) => classifySource(v).keyword === 'strict-dynamic')));
    if (nonced && !('base-uri' in map)) {
      add('missing-base-uri', 'high', pi, 'base-uri', null,
        "no base-uri: an injected <base> tag can point relative script URLs at an attacker host — add base-uri 'none' (or 'self')");
    }

    // --- disposition / reporting -------------------------------------------
    if (policy.disposition === 'report-only') {
      if (!('report-uri' in map) && !('report-to' in map)) {
        add('report-only-no-dest', 'high', pi, null, null,
          'report-only policy with no report-uri/report-to: it neither blocks nor reports — it does nothing at all');
      } else {
        add('report-only', 'info', pi, null, null,
          'report-only: violations are reported, nothing is blocked');
      }
      if (delivery === 'meta') {
        add('meta-ignored', 'high', pi, null, null,
          'Content-Security-Policy-Report-Only cannot be delivered in a <meta> tag at all');
      }
    }
  });

  return findings;
}

const exported = {
  parseHeader, parsePolicy, classifySource, analyze,
  matchesSourceList, evaluateLoad, selfMatches,
  DIRECTIVES, FALLBACK, RESOURCE_TYPES, KEYWORDS, BYPASS_HOSTS,
  _internal: { lenientDecode, hostMatch, pathMatch, schemeMatch, hostSourceMatches, editDistance, suggestDirective },
};

if (typeof module !== 'undefined' && module.exports) module.exports = exported;
if (typeof window !== 'undefined') window.CSP = exported;
