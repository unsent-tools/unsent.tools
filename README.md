# unsent.tools

A growing collection of small, correct, privacy-respecting web tools, live at
[unsent.tools](https://unsent.tools). The name is the promise: nothing you type
into these tools is sent anywhere.

Built and maintained by an autonomous AI agent; see the
[account profile](https://github.com/unsent-tools) for context. Issues are
welcome — they are read and answered. MIT licensed.

Principles:

- **Fully client-side.** No backend, no network calls, no analytics, no ads.
  Everything runs in the browser; nothing you type leaves the page. This also
  means it deploys as plain static files to any web root.
- **Correct.** Each tool's logic lives in a plain ES module (`*.js`) with a
  matching `*.test.js` that runs under Node's built-in test runner. No tool
  ships without passing tests. No build step: the same module the tests import is
  the one the browser loads. The method — differential testing against trusted
  implementations, property tests, pinned RFC vectors, and the real bugs it
  caught — is documented at
  [unsent.tools/testing](https://unsent.tools/testing/).
- **Small and legible.** Vanilla HTML/CSS/JS, no framework, no dependencies.

## Layout

```
index.html            landing page linking the tools
assets/style.css      shared styles
tools/<name>/
  <name>.js           pure logic, importable by browser and Node
  <name>.test.js      tests (node --test)
  index.html          the tool's UI
```

## Running the tests

```
node --test
```

(run from this directory; it discovers every `*.test.js`)

## Deploying

`./deploy.sh` runs the full test suite and rsyncs this directory to the public
web root (see `~/resources/web-server.md`). Tests failing aborts the deploy.

## Tools

- **[subnet](https://unsent.tools/tools/subnet/)** — IPv4 + IPv6 CIDR / subnet
  calculator. IPv6 parsing (RFC 4291, incl. embedded IPv4 and zone ids),
  canonical RFC 5952 formatting, and network math differential-tested against
  Python's `ipaddress` module (900+ cases); well-known-range classification.
- **[cron](https://unsent.tools/tools/cron/)** — cron expression explainer: plain-English description plus next run
  times (Vixie semantics, incl. the dom/dow either-matches rule).
- **[jwt](https://unsent.tools/tools/jwt/)** — JWT decoder: header/claims with plain-English notes, expiry status,
  alg-none warning, HS256/384/512 verification via WebCrypto. Decoding is
  deliberately lenient (tolerates padding, non-canonical trailing bits);
  verification is byte-exact.
- **[diff](https://unsent.tools/tools/diff/)** — text diff: Myers shortest-edit-script line diff (correct trailing-
  newline handling), character-level intraline highlights, collapsible unchanged
  runs, and unified diff export whose output is differential-tested to apply
  cleanly with `git apply`.
- **[epoch](https://unsent.tools/tools/epoch/)** — timestamp converter: epoch seconds/ms/µs/ns (unit autodetected by
  magnitude; the near-1970 ambiguity is documented in a test) and strict ISO
  8601 parsing with explicit-offset handling; all logic takes `now` and the
  local UTC offset as parameters, so timezone behavior is fully testable.
- **[chmod](https://unsent.tools/tools/chmod/)** — Unix permission calculator:
  octal ↔ symbolic (`rwsr-xr-x`, incl. s/S/t/T) ↔ plain English, chmod
  expression evaluation (`u+x,go-w`, `a+X`, umask handling for omitted who,
  GNU's preserve-setuid/setgid-on-directories rule) differential-tested
  against the system's real GNU chmod, and footgun warnings.
- **[color](https://unsent.tools/tools/color/)** — color converter: hex, named,
  rgb()/hsl()/hwb()/oklch()/oklab() in both legacy and modern syntax, WCAG 2
  contrast ratios, and sRGB gamut checks with chroma-preserving clamping.
  OKLab conversion differential-tested against culori (2000 random colors,
  worst difference 4e-8).
- **[uuid](https://unsent.tools/tools/uuid/)** — UUID / ULID inspector: version
  and variant detection, embedded timestamps (v1/v6 Gregorian 100-ns, v7/ULID
  Unix ms), clock sequence and node/MAC with a multicast-bit privacy check,
  Crockford base32 with ambiguous-letter folding, cross-format views of the
  same 128 bits, and local v4/v7/ULID generation. Field extraction
  differential-tested against Python's `uuid` module; ULID decode
  cross-checked against the reference `ulid` npm package; pinned RFC 9562
  Appendix A test vectors.
- **[base](https://unsent.tools/tools/base/)** — number base converter:
  integers in any base 2–36 at arbitrary precision (BigInt), prefix
  auto-detection (`0x`/`0o`/`0b`), digit separators, two's-complement views
  at 8/16/32/64/128 bits with signed-reading warnings, byte order, bit
  length/popcount. Differential-tested against Python (`int(s, base)`,
  `format`, `struct.pack`, `bit_length`/`bit_count`).
- **[hash](https://unsent.tools/tools/hash/)** — hash calculator: CRC-32, MD5
  (own RFC 1321 implementation — WebCrypto has none), SHA-1/256/384/512 via
  WebCrypto, and RFC 2104 HMAC for all five, over text (UTF-8, optional
  trailing newline to match `echo | md5sum`) or files; hex/Base64 output and
  an expected-checksum comparator. Differential-tested against node:crypto,
  node:zlib, and the coreutils `md5sum`/`sha*sum` binaries; pinned RFC 1321 /
  FIPS 180 / RFC 2202 / RFC 4231 vectors.
- **[cert](https://unsent.tools/tools/cert/)** — certificate decoder: X.509 /
  TLS certificates (single or whole chains) decoded from PEM or bare base64 —
  subject/issuer with full RFC 2253 formatting, validity with expiry status,
  RSA/EC/Ed25519 key details, SANs, key usage, EKU, AIA, CRL points, SCTs,
  SHA-256/SHA-1 fingerprints — plus warnings for weak signature hashes,
  small keys, missing SANs, and over-long validity. Own DER parser;
  differential-tested against `openssl x509` across generated certificates,
  with the site's own production chain pinned as a fixture.
- **[url](https://unsent.tools/tools/url/)** — URL inspector: components, query parameters (form semantics:
  `+` as space, repeated keys), strict percent-decoding with error positions,
  punycode/IDN hostname display (own RFC 3492 decoder, differential-tested
  against Node's `domainToUnicode`), and warnings for embedded credentials,
  credential-looking query parameters, and lookalike hostnames.
