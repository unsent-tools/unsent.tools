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
- **[csr](https://unsent.tools/tools/csr/)** — CSR decoder: PKCS#10 certificate
  signing requests — subject, key details, requested SANs and extensions,
  attributes (including plaintext challengePassword, with a warning) — plus
  real self-signature verification via WebCrypto (RSA, ECDSA, Ed25519), so
  tampering and corruption are actually detected, not assumed away.
  Differential-tested against `openssl req`, including a tamper test both
  implementations must reject.
- **[qr](https://unsent.tools/tools/qr/)** — QR code generator: ISO/IEC 18004
  from scratch — versions 1–40, error-correction levels L/M/Q/H,
  numeric/alphanumeric/byte (UTF-8) modes, Reed-Solomon over GF(256), mask
  chosen by the standard's penalty rules; SVG and PNG output. Matrices are
  compared bit-for-bit against the segno reference across all 160
  version/level combinations, every symbol must scan with zbar (an
  independent C decoder), and qrencode serves as a third implementation.
- **[sshkey](https://unsent.tools/tools/sshkey/)** — SSH key decoder: public
  keys, authorized_keys lines (options with full quoting), known_hosts
  (plain and hashed, markers), RFC 4716 blocks, and OpenSSH certificates
  (key ID, serial, principals, validity, extensions, signing CA) — with
  SHA256/MD5 fingerprints and the randomart drawing, all byte-compatible
  with ssh-keygen, which is exactly what the tests compare against.
  Private keys are refused with a warning, never parsed.
- **[email](https://unsent.tools/tools/email/)** — email header analyzer:
  the Received chain as a timeline with per-hop delays, SPF/DKIM/DMARC
  verdicts from Authentication-Results, DKIM-Signature inspection (including
  the `l=` footgun), decoded RFC 2047 subjects/names, and spoofing red flags
  (Reply-To mismatch, display-name addresses, forged Date). Header parsing,
  dates, address lists, and encoded-words are differential-tested against
  Python's `email` stdlib. Headers carry IPs and account names — the whole
  point is that they never leave your browser.
- **[unicode](https://unsent.tools/tools/unicode/)** — Unicode inspector:
  every codepoint with its official UCD name, category, and script;
  grapheme/codepoint/UTF-16/UTF-8 counts; NFC/NFD/NFKC/NFKD; warnings for
  zero-widths, bidirectional controls (Trojan Source), tag characters,
  space lookalikes, and mixed-script homographs. Character data generated
  from UCD 15.0.0; names/categories differential-tested against Python's
  `unicodedata`, the script table against Node's own ICU.
- **[spf](https://unsent.tools/tools/spf/)** — mail DNS record checker:
  SPF, DMARC, DKIM public-key, MTA-STS, and TLSRPT records parsed and
  explained — every SPF mechanism in plain language with DNS lookups counted
  against the limit of 10, DMARC effective policies under RFC 9989 (with
  legacy RFC 7489 tags flagged), DKIM key algorithm/size checks against
  RFC 8301/8463, and an offline would-this-IP-pass evaluator. Accepts bare
  values or dig/zone-file lines (multi-string TXT records are concatenated).
  Differential-tested against pyspf (mechanism grammar and full-record
  evaluation), checkdmarc, dkimpy's tag parser, and openssl-generated keys.
- **[bytes](https://unsent.tools/tools/bytes/)** — data size converter:
  bytes/bits and decimal/binary prefixes (GB vs GiB) with exact BigInt
  rational arithmetic — no floating point anywhere. Strict notation
  (lowercase b = bits) explained, sloppy forms ("500 mb") interpreted
  charitably with the alternative shown, the disk-marketing gap quantified,
  and transfer times for any size at any bandwidth. Differential-tested
  against Python's humanfriendly and bitmath (which disagree with each
  other about bits — documented) and fractions.Fraction for the exact math.
- **[robots](https://unsent.tools/tools/robots/)** — robots.txt tester:
  paste a robots.txt and test URLs against it per RFC 9309 — which group
  applies to a crawler (longest name wins, named groups fully shadow `*`),
  which rule decides each URL (longest percent-normalized pattern wins,
  Allow beats Disallow on ties), wildcards and `$` anchors, plus lint
  warnings for typos, orphaned rules, BOM breakage, non-standard
  directives, and Disallow lines that advertise sensitive paths.
  Differential-tested against protego, Scrapy's RFC 9309 parser
  (calibration-probed first; the one BOM divergence is documented).
- **[gitignore](https://unsent.tools/tools/gitignore/)** — .gitignore
  tester: paste a .gitignore and paths, get git's exact answer — ignored
  or not, decided by which pattern on which line, with the excluded-parent
  trap called out explicitly (a `!` negation can never re-include a file
  whose parent directory is excluded, and the tool says so per path).
  Anchoring, dir-only patterns, `**`, character classes, byte-level
  wildcard semantics. Differential-tested against `git check-ignore -v`
  itself (verdict + pattern + line all pinned), plus a randomized sweep
  that caught git's undocumented bare-`!` behavior.
- **[url](https://unsent.tools/tools/url/)** — URL inspector: components, query parameters (form semantics:
  `+` as space, repeated keys), strict percent-decoding with error positions,
  punycode/IDN hostname display (own RFC 3492 decoder, differential-tested
  against Node's `domainToUnicode`), and warnings for embedded credentials,
  credential-looking query parameters, and lookalike hostnames.
