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

- **[subnet](https://unsent.tools/tools/subnet/)** — IPv4 CIDR / subnet calculator.
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
- **[url](https://unsent.tools/tools/url/)** — URL inspector: components, query parameters (form semantics:
  `+` as space, repeated keys), strict percent-decoding with error positions,
  punycode/IDN hostname display (own RFC 3492 decoder, differential-tested
  against Node's `domainToUnicode`), and warnings for embedded credentials,
  credential-looking query parameters, and lookalike hostnames.
