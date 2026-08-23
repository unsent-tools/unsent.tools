// url.js — pure logic for the URL inspector.
// Parses a URL into its components, decodes percent-encoding and punycode,
// and flags things worth knowing before you share a URL. No I/O.

// --- percent-encoding ------------------------------------------------------

// Strict percent-decode. Throws on a malformed %-sequence, with the position
// of the offending "%" in the message. Invalid UTF-8 byte sequences decode to
// U+FFFD (replacement character) rather than throwing — pinned by a test.
export function percentDecode(s, { plusAsSpace = false } = {}) {
  const bytes = [];
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "%") {
      const hex = s.slice(i + 1, i + 3);
      if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
        throw new Error(`Malformed percent-sequence at position ${i}: "%${hex}"`);
      }
      bytes.push(parseInt(hex, 16));
      i += 2;
    } else if (ch === "+" && plusAsSpace) {
      bytes.push(0x20);
    } else {
      for (const b of new TextEncoder().encode(ch)) bytes.push(b);
    }
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(new Uint8Array(bytes));
}

// Lenient decode for display: never throws; undecodable input is shown raw.
function lenientDecode(s, opts) {
  try {
    return percentDecode(s, opts);
  } catch {
    return opts?.plusAsSpace ? s.replace(/\+/g, " ") : s;
  }
}

// The three encodings people actually reach for, side by side.
export function encodeVariants(s) {
  return {
    component: encodeURIComponent(s), // for one path segment / query value
    full: encodeURI(s), // for a whole URL (keeps :/?#&=)
    form: encodeURIComponent(s).replace(/%20/g, "+"), // application/x-www-form-urlencoded
  };
}

// --- punycode (RFC 3492, decode only) --------------------------------------

const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;

function adapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

// Decodes the part of an IDN label AFTER the "xn--" prefix.
export function punycodeDecode(input) {
  const output = [];
  const basicEnd = input.lastIndexOf("-");
  if (basicEnd > 0) {
    for (const ch of input.slice(0, basicEnd)) {
      const cp = ch.codePointAt(0);
      if (cp >= 0x80) throw new Error("non-ASCII in basic part");
      output.push(cp);
    }
  }
  let idx = basicEnd >= 0 ? basicEnd + 1 : 0;
  let i = 0, n = 0x80, bias = 72;
  while (idx < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error("truncated punycode");
      const c = input.charCodeAt(idx++);
      let digit;
      if (c >= 48 && c <= 57) digit = c - 22; // 0-9 → 26-35
      else if (c >= 65 && c <= 90) digit = c - 65; // A-Z → 0-25
      else if (c >= 97 && c <= 122) digit = c - 97; // a-z → 0-25
      else throw new Error("invalid punycode digit");
      i += digit * w;
      if (i > Number.MAX_SAFE_INTEGER) throw new Error("punycode overflow");
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    if (n > 0x10ffff) throw new Error("punycode overflow");
    i %= output.length + 1;
    output.splice(i, 0, n);
    i++;
  }
  return String.fromCodePoint(...output);
}

// ASCII hostname → its Unicode display form. Labels that aren't valid
// punycode are left as-is.
export function hostToUnicode(hostname) {
  let isIdn = false;
  const unicode = hostname
    .split(".")
    .map((label) => {
      if (!/^xn--/i.test(label)) return label;
      try {
        const decoded = punycodeDecode(label.slice(4).toLowerCase());
        isIdn = true;
        return decoded;
      } catch {
        return label;
      }
    })
    .join(".");
  return { unicode, isIdn };
}

// --- URL parsing -----------------------------------------------------------

const DEFAULT_PORTS = { http: 80, https: 443, ws: 80, wss: 443, ftp: 21 };

const CREDENTIAL_PARAM = /(^|[_.-])(token|secret|session|auth|password|passwd|pwd|apikey|api[_-]?key|access[_-]?key|bearer|jwt|sig|signature|credential)s?([_.-]|$)/i;

function parseQuery(query) {
  const params = [];
  if (!query) return params;
  for (const part of query.split("&")) {
    if (part === "") continue;
    const eq = part.indexOf("=");
    const rawKey = eq === -1 ? part : part.slice(0, eq);
    const rawValue = eq === -1 ? null : part.slice(eq + 1);
    params.push({
      rawKey,
      rawValue,
      key: lenientDecode(rawKey, { plusAsSpace: true }),
      value: rawValue === null ? null : lenientDecode(rawValue, { plusAsSpace: true }),
    });
  }
  return params;
}

export function parseUrl(raw) {
  const input = raw.trim();
  if (!input) throw new Error("Enter a URL.");
  let u = null;
  let assumedScheme = false;
  try {
    u = new URL(input);
  } catch {
    /* fall through to the https:// retry */
  }
  // "example.com/x" has no scheme; "localhost:8080/x" parses but with the
  // bogus scheme "localhost:". In both cases retry as https://.
  const schemeless = u === null && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(input);
  const hostPort = u !== null && u.hostname === "" && /^[a-zA-Z0-9.-]+:\d+([/?#]|$)/.test(input);
  if (schemeless || hostPort) {
    try {
      u = new URL("https://" + input);
      assumedScheme = true;
    } catch {
      u = null;
    }
  }
  if (u === null) throw new Error("Not a valid URL.");

  const scheme = u.protocol.slice(0, -1);
  const { unicode: hostUnicode, isIdn } = hostToUnicode(u.hostname);
  const query = u.search.startsWith("?") ? u.search.slice(1) : u.search;
  const params = parseQuery(query);
  const fragment = u.hash.startsWith("#") ? u.hash.slice(1) : u.hash;

  const warnings = [];
  if (u.username || u.password) {
    warnings.push({
      id: "credentials",
      text: "This URL embeds a username" + (u.password ? " and password" : "") +
        " — anyone you share it with gets them.",
    });
  }
  const credParams = params.filter((p) => CREDENTIAL_PARAM.test(p.key)).map((p) => p.key);
  if (credParams.length) {
    warnings.push({
      id: "credential-params",
      text: `Query contains credential-looking parameter${credParams.length > 1 ? "s" : ""}: ` +
        credParams.join(", ") + " — careful where you paste this URL.",
    });
  }
  if (isIdn) {
    warnings.push({
      id: "idn",
      text: `Internationalized hostname: displays as "${hostUnicode}". ` +
        "Check it for lookalike characters before trusting it.",
    });
  }
  const keyCounts = new Map();
  for (const p of params) keyCounts.set(p.key, (keyCounts.get(p.key) ?? 0) + 1);
  const repeated = [...keyCounts.entries()].filter(([, n]) => n > 1).map(([k]) => k);
  if (repeated.length) {
    warnings.push({
      id: "repeated-params",
      text: "Repeated query parameter" + (repeated.length > 1 ? "s" : "") + ": " +
        repeated.join(", ") + " — servers differ on which occurrence wins.",
    });
  }

  return {
    href: u.href,
    scheme,
    assumedScheme,
    username: lenientDecode(u.username),
    password: lenientDecode(u.password),
    hostname: u.hostname,
    hostUnicode,
    isIdn,
    port: u.port, // "" when the scheme's default port applies (or none given)
    defaultPort: DEFAULT_PORTS[scheme] ?? null,
    origin: u.origin,
    pathname: u.pathname,
    pathSegments: u.pathname
      .split("/")
      .filter((seg) => seg !== "")
      .map((seg) => lenientDecode(seg)),
    query,
    params,
    fragment,
    fragmentDecoded: lenientDecode(fragment),
    warnings,
  };
}
