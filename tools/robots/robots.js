// robots.txt parser and access checker per RFC 9309, entirely client-side.
//
// Matching semantics (pinned by tests, differential against protego —
// Scrapy's RFC 9309 parser):
//   - Group selection: a group applies if its user-agent token appears
//     case-insensitively as a substring of the crawler's user-agent string;
//     the longest matching token wins, and every group sharing that winning
//     token is merged. "*" applies only when nothing else matches. A specific
//     group fully shadows "*" — rules are never combined across tokens.
//   - Rule precedence: the matching rule with the longest pattern wins,
//     length measured on the percent-normalized pattern (wildcards count as
//     one character each). Equal lengths: allow wins. No match: allowed.
//   - Patterns: "*" matches any run of characters, a single trailing "$"
//     anchors the end; "$" anywhere else is literal.
//   - Both patterns and paths are percent-normalized before comparison:
//     valid %XX triplets are uppercased, and characters outside RFC 3986
//     unreserved + reserved (spaces, non-ASCII, controls, "<>{}|\^ etc.) are
//     UTF-8 percent-encoded. %2F is NOT decoded — it stays distinct from "/".
//   - Paths are compared as-is beyond that: case-sensitive, no dot-segment
//     normalization ("/a/../b" does not become "/b"), query string included,
//     fragment stripped.

const RESERVED_OK = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" +
  "-._~:/?#[]@!$&'()*+,;=%"
);

function isHex(c) {
  return (c >= "0" && c <= "9") || (c >= "a" && c <= "f") || (c >= "A" && c <= "F");
}

// Percent-normalize a pattern or path (see header comment).
export function normalize(s) {
  let out = "";
  for (let i = 0; i < s.length; ) {
    const c = s[i];
    if (c === "%" && isHex(s[i + 1] || "") && isHex(s[i + 2] || "")) {
      out += "%" + s[i + 1].toUpperCase() + s[i + 2].toUpperCase();
      i += 3;
      continue;
    }
    const cp = s.codePointAt(i);
    const ch = String.fromCodePoint(cp);
    if (cp < 0x80 && RESERVED_OK.has(ch)) {
      out += ch;
    } else {
      // UTF-8 percent-encode (covers space, controls, non-ASCII, "<>{}|\^`)
      const bytes = new TextEncoder().encode(ch);
      for (const b of bytes) out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
    }
    i += ch.length;
  }
  return out;
}

// Match a normalized pattern against a normalized path.
export function matchPattern(pattern, path) {
  let anchored = false;
  if (pattern.endsWith("$")) {
    anchored = true;
    pattern = pattern.slice(0, -1);
  }
  const segs = pattern.split("*");
  // First segment must be a prefix.
  if (!path.startsWith(segs[0])) return false;
  let pos = segs[0].length;
  if (segs.length === 1) {
    return anchored ? pos === path.length : true;
  }
  // Middle segments: earliest occurrence (greedy-left is correct for '*').
  for (let k = 1; k < segs.length - 1; k++) {
    const at = path.indexOf(segs[k], pos);
    if (at === -1) return false;
    pos = at + segs[k].length;
  }
  const last = segs[segs.length - 1];
  if (anchored) {
    return path.endsWith(last) && path.length - last.length >= pos;
  }
  return path.indexOf(last, pos) !== -1;
}

const KNOWN_KEYS = new Set(["user-agent", "allow", "disallow", "sitemap", "crawl-delay"]);
// Directives seen in the wild that are not part of RFC 9309.
const NONSTANDARD_KEYS = new Map([
  ["noindex", "Noindex in robots.txt has never been standard, and Google dropped unofficial support in 2019. Use a <meta name=\"robots\"> tag or X-Robots-Tag header instead."],
  ["host", "Host is a Yandex extension; other crawlers ignore it."],
  ["clean-param", "Clean-param is a Yandex extension; other crawlers ignore it."],
  ["request-rate", "Request-rate was never standardized and is ignored by major crawlers."],
  ["visit-time", "Visit-time was never standardized and is ignored by major crawlers."],
]);
const TYPO_KEYS = new Map([
  ["disalow", "disallow"], ["dissallow", "disallow"], ["disallows", "disallow"],
  ["useragent", "user-agent"], ["user-agents", "user-agent"], ["agent", "user-agent"],
  ["crawldelay", "crawl-delay"], ["allows", "allow"], ["sitemaps", "sitemap"],
]);

const SENSITIVE_HINTS = /admin|login|signin|backup|private|secret|internal|staging|\.git|\.env|wp-admin|password|config|\.sql|dump/i;

// Parse robots.txt text into groups, sitemaps, warnings, and an annotated
// line list. Never throws.
export function parseRobots(text) {
  const warnings = [];
  let hadBom = false;
  if (text.startsWith("﻿")) {
    hadBom = true;
    text = text.slice(1);
    warnings.push({
      code: "bom",
      message: "File starts with a UTF-8 byte-order mark. This tool (and Google) strip it, but some parsers do not and will fail to recognize the first line — if that line is User-agent, they treat the whole first group's rules as orphaned. Save the file without a BOM.",
      line: 1,
    });
  }

  const rawLines = text.split(/\r\n|\r|\n/);
  const lines = [];       // annotated, for UI display
  const groups = [];      // {agents:[{token,line}], rules:[...], crawlDelay, startLine}
  const sitemaps = [];
  const orphanRules = [];

  let current = null;     // group being filled with rules
  let pendingAgents = []; // consecutive user-agent lines before first rule

  const openGroup = () => {
    if (pendingAgents.length > 0) {
      current = { agents: pendingAgents, rules: [], crawlDelay: null, startLine: pendingAgents[0].line };
      groups.push(current);
      pendingAgents = [];
    }
  };

  for (let idx = 0; idx < rawLines.length; idx++) {
    const n = idx + 1;
    const raw = rawLines[idx];
    const hash = raw.indexOf("#");
    const body = (hash === -1 ? raw : raw.slice(0, hash)).trim();
    if (body === "") {
      lines.push({ n, raw, kind: hash === -1 ? "blank" : "comment" });
      continue;
    }
    const colon = body.indexOf(":");
    if (colon === -1) {
      lines.push({ n, raw, kind: "invalid" });
      warnings.push({ code: "no-colon", message: `Line ${n} has no ":" separator and is ignored: "${body.length > 60 ? body.slice(0, 60) + "…" : body}"`, line: n });
      continue;
    }
    const key = body.slice(0, colon).trim().toLowerCase();
    const value = body.slice(colon + 1).trim();

    if (key === "user-agent") {
      const token = value;
      if (token === "") {
        warnings.push({ code: "empty-agent", message: `Line ${n}: User-agent with no value is ignored.`, line: n });
        lines.push({ n, raw, kind: "invalid" });
        continue;
      }
      if (current !== null) current = null; // a rule block was open; this starts a new group
      pendingAgents.push({ token, line: n });
      if (token !== "*" && token.includes("*")) {
        warnings.push({ code: "wildcard-agent", message: `Line ${n}: "${token}" — wildcards inside user-agent names are not standard. Only a bare "*" is special; most parsers treat this name literally (this tool matches it as a plain substring).`, line: n });
      }
      lines.push({ n, raw, kind: "agent", token });
      continue;
    }

    if (key === "allow" || key === "disallow") {
      const rule = {
        verb: key,
        rawPattern: value,
        pattern: normalize(value),
        line: n,
      };
      if (pendingAgents.length > 0) openGroup();
      if (current === null) {
        orphanRules.push(rule);
        lines.push({ n, raw, kind: "orphan", rule });
        warnings.push({ code: "orphan-rule", message: `Line ${n}: ${key.charAt(0).toUpperCase() + key.slice(1)} appears before any User-agent line, belongs to no group, and is ignored by crawlers.`, line: n });
        continue;
      }
      current.rules.push(rule);
      lines.push({ n, raw, kind: "rule", rule });
      if (value === "" && key === "disallow") {
        // valid: means "allow everything" for this group — no warning
      } else if (value !== "" && !value.startsWith("/") && !value.startsWith("*")) {
        warnings.push({ code: "no-leading-slash", message: `Line ${n}: pattern "${value}" does not start with "/" or "*". Paths always start with "/", so this rule never matches anything.`, line: n });
      }
      if (key === "disallow" && SENSITIVE_HINTS.test(value)) {
        warnings.push({ code: "sensitive-path", message: `Line ${n}: robots.txt is public — "Disallow: ${value}" advertises this path to anyone who looks, including people probing for exactly such paths. robots.txt is not access control.`, line: n });
      }
      continue;
    }

    if (key === "sitemap") {
      // A non-group line ends a run of user-agent lines (RFC 9309 ABNF:
      // only blank lines and comments may sit between a group's UA lines).
      if (pendingAgents.length > 0) openGroup();
      sitemaps.push({ url: value, line: n });
      lines.push({ n, raw, kind: "sitemap", url: value });
      if (!/^https?:\/\//i.test(value)) {
        warnings.push({ code: "sitemap-not-absolute", message: `Line ${n}: Sitemap value "${value}" is not an absolute http(s) URL. The sitemaps.org protocol requires a full URL; relative values are ignored by most crawlers.`, line: n });
      }
      continue;
    }

    if (key === "crawl-delay") {
      if (pendingAgents.length > 0) openGroup();
      const num = /^\d+(\.\d+)?$/.test(value) ? parseFloat(value) : null;
      if (current !== null) {
        current.crawlDelay = { value: num, raw: value, line: n };
      }
      lines.push({ n, raw, kind: "crawl-delay", value: num });
      if (num === null) {
        warnings.push({ code: "bad-crawl-delay", message: `Line ${n}: Crawl-delay value "${value}" is not a number and is ignored.`, line: n });
      } else {
        warnings.push({ code: "crawl-delay", message: `Line ${n}: Crawl-delay is not part of RFC 9309. Bing and Yandex honor it; Google ignores it entirely (set crawl rate in Search Console instead).`, line: n });
      }
      continue;
    }

    // Unknown / non-standard / typo keys — these also end a UA-line run
    if (pendingAgents.length > 0) openGroup();
    lines.push({ n, raw, kind: "other", key, value });
    if (TYPO_KEYS.has(key)) {
      warnings.push({ code: "typo", message: `Line ${n}: "${key}" looks like a typo for "${TYPO_KEYS.get(key)}" — as written it is ignored by every crawler.`, line: n });
    } else if (NONSTANDARD_KEYS.has(key)) {
      warnings.push({ code: "nonstandard", message: `Line ${n}: ${NONSTANDARD_KEYS.get(key)}`, line: n });
    } else {
      warnings.push({ code: "unknown-key", message: `Line ${n}: unknown directive "${key}" is ignored.`, line: n });
    }
  }
  openGroup(); // trailing user-agent lines with no rules still form a group

  // Full-site block warning, per group
  for (const g of groups) {
    for (const r of g.rules) {
      if (r.verb === "disallow" && (r.rawPattern === "/" || r.rawPattern === "*" || r.rawPattern === "/*")) {
        const who = g.agents.map((a) => a.token).join(", ");
        const hasOverridingAllow = g.rules.some((o) => o.verb === "allow" && o.rawPattern !== "");
        if (!hasOverridingAllow) {
          warnings.push({ code: "full-block", message: `Line ${r.line}: "Disallow: ${r.rawPattern}" blocks the entire site for ${who === "*" ? "every crawler" : `"${who}"`}.`, line: r.line });
        }
      }
    }
  }

  return { lines, groups, sitemaps, warnings, orphanRules, hadBom };
}

// Which groups apply to this user-agent? Returns merged rules.
// ua is the crawler's user-agent string or product token.
export function selectGroups(parsed, ua) {
  const lower = ua.trim().toLowerCase();
  let bestLen = -1;
  let bestToken = null;
  for (const g of parsed.groups) {
    for (const a of g.agents) {
      const tok = a.token.toLowerCase();
      if (tok === "*") continue;
      // protego-compatible: strip a leading "*" then substring-match
      const needle = tok !== "*" && tok.startsWith("*") ? tok.slice(1) : tok;
      if (needle !== "" && lower.includes(needle) && tok.length > bestLen) {
        bestLen = tok.length;
        bestToken = tok;
      }
    }
  }
  const useStar = bestToken === null;
  const matched = [];
  for (const g of parsed.groups) {
    const hit = g.agents.some((a) =>
      useStar ? a.token === "*" : a.token.toLowerCase() === bestToken
    );
    if (hit) matched.push(g);
  }
  const rules = matched.flatMap((g) => g.rules);
  let crawlDelay = null;
  for (const g of matched) {
    if (g.crawlDelay && g.crawlDelay.value !== null) crawlDelay = g.crawlDelay;
  }
  return {
    matchedToken: useStar ? (matched.length > 0 ? "*" : null) : bestToken,
    groups: matched,
    rules,
    crawlDelay,
  };
}

// Extract the path (+query) to test from a full URL or a bare path.
export function toPath(input) {
  const s = input.trim();
  const notes = [];
  if (/^https?:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      if (u.hash) notes.push("fragment ignored (never sent to servers)");
      return { path: u.pathname + u.search, notes, host: u.host };
    } catch {
      return { path: null, notes: ["not a valid URL"], host: null };
    }
  }
  if (s === "") return { path: null, notes: ["empty"], host: null };
  let p = s;
  const hash = p.indexOf("#");
  if (hash !== -1) {
    p = p.slice(0, hash);
    notes.push("fragment ignored (never sent to servers)");
  }
  if (!p.startsWith("/")) {
    p = "/" + p;
    notes.push('leading "/" added');
  }
  return { path: p, notes, host: null };
}

// The verdict for one user-agent + one URL/path.
export function checkUrl(parsed, ua, input) {
  const { path, notes, host } = toPath(input);
  if (path === null) return { input, path: null, notes, allowed: null };
  const sel = selectGroups(parsed, ua);
  const normPath = normalize(path);
  const matches = [];
  for (const r of sel.rules) {
    if (r.rawPattern === "") continue; // empty pattern matches nothing
    if (matchPattern(r.pattern, normPath)) {
      matches.push(r);
    }
  }
  let winner = null;
  for (const m of matches) {
    if (
      winner === null ||
      m.pattern.length > winner.pattern.length ||
      (m.pattern.length === winner.pattern.length && m.verb === "allow" && winner.verb === "disallow")
    ) {
      winner = m;
    }
  }
  const allowed = winner === null ? true : winner.verb === "allow";
  const extraNotes = [...notes];
  if (/^\/robots\.txt$/i.test(path) && !allowed) {
    extraNotes.push("crawlers always may fetch /robots.txt itself, regardless of rules");
  }
  if (path.includes("/../") || path.endsWith("/..")) {
    extraNotes.push('".." is not resolved — robots.txt matching is textual, per the standard');
  }
  return {
    input,
    path,
    host,
    normPath,
    notes: extraNotes,
    matchedToken: sel.matchedToken,
    matches,
    winner,
    allowed,
    crawlDelay: sel.crawlDelay,
  };
}
