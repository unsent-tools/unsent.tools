// .gitignore parser and path checker, entirely client-side.
//
// Semantics mirror git's own (differential-tested against `git
// check-ignore -v`, calibration-probed first):
//   - Last matching pattern on a path wins; "!" negates.
//   - A path is ignored if ANY ancestor directory is ignored, checked from
//     the shallowest down — and that ancestor's pattern is the decider,
//     which is why a later "!" on a file inside an excluded directory has
//     no effect: git never descends into excluded directories.
//   - A pattern with a "/" anywhere but the end is anchored to the
//     .gitignore's directory; otherwise it matches against basenames at
//     any depth. A trailing "/" restricts the pattern to directories.
//   - Wildcards: "*" and "?" never cross "/"; "**" crosses directories
//     when it stands alone between slashes or at the edges ("**/", "/**/",
//     "/**"); anywhere else it degrades to "*". Character classes [a-z],
//     [!a-z], and POSIX names like [[:alpha:]] are supported. "\" escapes.
//   - Matching is BYTE-based, exactly like git: "?" matches one byte, so
//     it does not match a two-byte UTF-8 character like "é".
//   - Trailing spaces are stripped unless backslash-escaped; "#" starts a
//     comment and "!" negates only at the start of a line (escape with \).
//
// Scope: a single .gitignore at the repository root. Nested .gitignore
// files, $GIT_DIR/info/exclude, and core.excludesFile stack on top with
// the same per-file semantics.

const enc = new TextEncoder();

// UTF-8 bytes of a JS string, as a latin1-mapped string so RegExp can
// operate bytewise (each char = one byte).
function toBytes(s) {
  return Array.from(enc.encode(s), (b) => String.fromCharCode(b)).join("");
}

const POSIX_CLASSES = new Map([
  ["alpha", "A-Za-z"], ["digit", "0-9"], ["alnum", "0-9A-Za-z"],
  ["upper", "A-Z"], ["lower", "a-z"], ["space", " \\t\\r\\n\\v\\f"],
  ["blank", " \\t"], ["punct", "!-/:-@\\[-`{-~"], ["xdigit", "0-9A-Fa-f"],
  ["cntrl", "\\x00-\\x1f\\x7f"], ["print", " -~"], ["graph", "!-~"],
]);

const reEscape = (c) => /[.*+?^${}()|[\]\\/]/.test(c) ? "\\" + c : c;

// Compile a (byte-string) glob into a RegExp source. `pathname` = slashes
// are significant (anchored patterns); otherwise the input is a basename.
function globToRegex(glob, pathname) {
  let out = "";
  let i = 0;
  const n = glob.length;
  while (i < n) {
    const c = glob[i];
    if (c === "\\") {
      if (i + 1 < n) { out += reEscape(glob[i + 1]); i += 2; }
      else { out += "\\\\"; i += 1; } // lone trailing backslash: literal
      continue;
    }
    if (c === "?") { out += pathname ? "[^/]" : "[\\s\\S]"; i += 1; continue; }
    if (c === "*") {
      let j = i;
      while (j < n && glob[j] === "*") j++;
      const stars = j - i;
      const prevOk = i === 0 || glob[i - 1] === "/";
      const nextOk = j === n || glob[j] === "/";
      if (pathname && stars >= 2 && prevOk && nextOk) {
        if (j === n) {
          out += "[\\s\\S]*";          // trailing "/**": everything inside
        } else {
          out += "(?:[\\s\\S]*/)?";    // "**/": any depth, including none
          j += 1;                       // consume the following "/"
        }
      } else {
        out += pathname ? "[^/]*" : "[\\s\\S]*";
      }
      i = j;
      continue;
    }
    if (c === "[") {
      // find the closing ], honoring []..], [!]..], escapes, [[:class:]]
      let j = i + 1;
      let cls = "";
      let neg = false;
      if (glob[j] === "!" || glob[j] === "^") { neg = true; j += 1; }
      if (glob[j] === "]") { cls += "\\]"; j += 1; }
      let closed = false;
      while (j < n) {
        if (glob[j] === "]") { closed = true; break; }
        if (glob[j] === "[" && glob[j + 1] === ":") {
          const end = glob.indexOf(":]", j + 2);
          const name = end === -1 ? null : glob.slice(j + 2, end);
          if (name !== null && POSIX_CLASSES.has(name)) {
            cls += POSIX_CLASSES.get(name);
            j = end + 2;
            continue;
          }
        }
        const hex = (ch) => "\\x" + ch.charCodeAt(0).toString(16).padStart(2, "0");
        if (glob[j] === "\\" && j + 1 < n) {
          cls += hex(glob[j + 1]); // escaped literal, even if it's - or ]
          j += 2;
          continue;
        }
        const ch = glob[j];
        // "-" stays raw so ranges keep working; everything else goes as a
        // hex escape, immune to regex-class metacharacters
        cls += ch === "-" ? "-" : hex(ch);
        j += 1;
      }
      if (!closed) { out += "\\["; i += 1; continue; } // unclosed [: literal
      out += "[" + (neg ? "^" : "") + (pathname && neg ? "\\x2f" : "") + cls + "]";
      i = j + 1;
      continue;
    }
    out += reEscape(c);
    i += 1;
  }
  return out;
}

// One parsed .gitignore line.
//   kind: "pattern" | "comment" | "blank"
//   For patterns: negated, dirOnly, anchored, glob (byte string, leading
//   "/" stripped), raw (original line), line (1-based)
export function parseGitignore(text) {
  const warnings = [];
  const lines = [];
  const patterns = [];
  const rawLines = text.split(/\r\n|\n/);
  for (let idx = 0; idx < rawLines.length; idx++) {
    const n = idx + 1;
    const raw = rawLines[idx];
    if (raw.trim() === "") { lines.push({ n, raw, kind: "blank" }); continue; }
    if (raw.startsWith("#")) { lines.push({ n, raw, kind: "comment" }); continue; }
    let body = raw;
    // strip unescaped trailing spaces
    let stripped = 0;
    while (body.endsWith(" ") && !body.endsWith("\\ ")) { body = body.slice(0, -1); stripped++; }
    if (stripped > 0) {
      warnings.push({ code: "trailing-space", line: n, message: `Line ${n}: ${stripped} trailing space${stripped > 1 ? "s" : ""} stripped. To match a name ending in a space, escape it: "\\ ".` });
    }
    const display = body; // the pattern as git reports it (spaces stripped)
    let negated = false;
    if (body.startsWith("!")) { negated = true; body = body.slice(1); }
    else if (body.startsWith("\\!") || body.startsWith("\\#")) { body = body.slice(1); }
    let dirOnly = false;
    if (body.endsWith("/") && !body.endsWith("\\/")) { dirOnly = true; body = body.slice(0, -1); }
    let anchored = false;
    if (body.startsWith("/")) { anchored = true; body = body.slice(1); }
    if (body.includes("/")) anchored = true;
    if (body === "") {
      // Not dropped: git keeps these. A bare "!" is a negation with an
      // empty stem, which really does match a directory query's empty
      // basename in the self-scan (verified against check-ignore).
      warnings.push({ code: "empty-pattern", line: n, message: `Line ${n}: "${raw}" reduces to an empty pattern — almost certainly a mistake.` });
    }
    if (body.includes("\\") && /\\[^ !#*?\[\]\\\-]/.test(body)) {
      warnings.push({ code: "backslash", line: n, message: `Line ${n}: backslash in "${body}" — in .gitignore "\\" escapes the next character, it is not a path separator. Use "/" even on Windows.` });
    }
    const pat = {
      kind: "pattern", n, raw, line: n, negated, dirOnly, anchored,
      glob: toBytes(body),
      display,
    };
    pat.re = new RegExp("^(?:" + globToRegex(pat.glob, anchored) + ")$");
    patterns.push(pat);
    lines.push(pat);
  }

  // duplicate patterns
  const seen = new Map();
  for (const p of patterns) {
    const key = p.display;
    if (seen.has(key)) {
      warnings.push({ code: "duplicate", line: p.line, message: `Line ${p.line}: "${p.display}" duplicates line ${seen.get(key)} — the earlier one never decides anything.` });
    } else {
      seen.set(key, p.line);
    }
  }
  return { lines, patterns, warnings };
}

const basenameOf = (path) => {
  const i = path.lastIndexOf("/");
  return i === -1 ? path : path.slice(i + 1);
};

// Does one pattern match one target string? The target is either a bare
// path ("a/b") or, for git's self-scan of an explicitly queried directory,
// the string with its trailing slash kept ("a/b/") — in which case the
// basename is the empty string, exactly as git computes it.
export function patternMatches(pat, target, isDir) {
  if (pat.dirOnly && !isDir) return false;
  if (!pat.anchored) return pat.re.test(basenameOf(target));
  return pat.re.test(target);
}

// Last matching pattern for a single target, or null.
function lastMatch(patterns, target, isDir) {
  let m = null;
  for (const p of patterns) {
    if (patternMatches(p, target, isDir)) m = p;
  }
  return m;
}

// The verdict for one path. `input` may end with "/" to mean "a directory".
// Returns { path, isDir, ignored, decider, via, notes, ineffective }
//   decider: the pattern that decided (git check-ignore -v reports this)
//   via: null if the path itself decided, else the ancestor dir that did
//   ineffective: negations on the path that cannot work (excluded parent)
export function checkPath(parsed, input) {
  const notes = [];
  let p = input.trim();
  if (p === "") return { path: null, notes: ["empty"], ignored: null };
  const isDir = p.endsWith("/");
  p = p.replace(/\/+$/, "");
  if (p.startsWith("./")) { p = p.slice(2); notes.push('leading "./" removed'); }
  if (p.startsWith("/")) {
    p = p.replace(/^\/+/, "");
    notes.push("paths are relative to the repository root — leading / removed");
  }
  if (p === "" || p === ".") return { path: input, notes: ["not a checkable path"], ignored: null };
  if (p.includes("\\")) notes.push('backslash treated as a literal character — git paths use "/"');

  const bytes = toBytes(p);
  // Stage 1 — the directory-exclusion walk, shallowest first, with normal
  // last-match-wins per directory. A directory query's own name is the
  // final step of this walk (its string ends in "/", so the name is a
  // proper prefix). The first dir whose last match is positive decides,
  // and negations deeper down can never re-include anything under it.
  const parts = bytes.split("/");
  const walk = [];
  for (let i = 1; i < parts.length; i++) walk.push(parts.slice(0, i).join("/"));
  if (isDir) walk.push(bytes);

  let decider = null;
  let via = null;
  let ignored = false;
  for (const anc of walk) {
    const m = lastMatch(parsed.patterns, anc, true);
    if (m && !m.negated) {
      decider = m;
      via = anc === bytes ? null : anc;
      ignored = true;
      break;
    }
  }
  // Stage 2 — the path itself, matched as the raw string: with its
  // trailing slash for directory queries (so basename patterns see an
  // empty basename), bare for files. Negated matches are reported too.
  // Dir-only patterns do NOT participate here — they only act through
  // the stage-1 walk (git treats this raw string as a non-directory).
  if (!ignored) {
    const m = lastMatch(parsed.patterns, isDir ? bytes + "/" : bytes, false);
    decider = m;
    ignored = m !== null && !m.negated;
  }

  // negations on this path that can never take effect
  const ineffective = [];
  if (ignored && via !== null) {
    for (const pat of parsed.patterns) {
      if (pat.negated && patternMatches(pat, bytes, isDir)) ineffective.push(pat);
    }
  }
  return { path: p, isDir, ignored, decider, via: via === null ? null : decodeBytes(via), notes, ineffective };
}

function decodeBytes(byteStr) {
  const arr = Uint8Array.from(byteStr, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(arr);
}

// Static lint: negation patterns that sit entirely inside a directory that
// an earlier positive dir-pattern excludes (the classic trap), detectable
// without any test paths. Only flags the unambiguous literal-prefix case.
export function lintNegations(parsed) {
  const findings = [];
  for (const neg of parsed.patterns) {
    if (!neg.negated || !neg.anchored || /[*?[\]\\]/.test(neg.glob)) continue;
    const segs = neg.glob.split("/");
    for (let i = 1; i < segs.length; i++) {
      const prefix = segs.slice(0, i).join("/");
      for (const pos of parsed.patterns) {
        if (pos.negated || pos.line > neg.line || /[*?[\]\\]/.test(pos.glob)) continue;
        const excludesPrefix =
          (pos.anchored && pos.glob === prefix) ||
          (!pos.anchored && segs[i - 1] === pos.glob && i === 1);
        // was the prefix re-included by a negation in between?
        const reIncluded = parsed.patterns.some((q) =>
          q.negated && q.line > pos.line && q.glob === pos.glob && q.anchored === pos.anchored);
        if (excludesPrefix && !reIncluded) {
          findings.push({
            code: "dead-negation", line: neg.line,
            message: `Line ${neg.line}: "!${decodeBytes(neg.glob)}" has no effect — its parent directory "${decodeBytes(prefix)}" is excluded by "${decodeBytes(pos.glob)}${pos.dirOnly ? "/" : ""}" (line ${pos.line}), and git never looks inside an excluded directory. To re-include it: un-ignore each parent (e.g. "!${decodeBytes(prefix)}/") and exclude their other contents instead.`,
          });
        }
      }
    }
  }
  return findings;
}
