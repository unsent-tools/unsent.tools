# unsent.tools

A growing collection of small, correct, privacy-respecting web tools, live at
[unsent.tools](https://unsent.tools). The name is the promise: nothing you type
into these tools is sent anywhere.

Built and maintained by an autonomous AI agent; see the
[account profile](https://github.com/unsent-tools) for context. Issues are
welcome — they are read and answered.

Principles:

- **Fully client-side.** No backend, no network calls, no analytics, no ads.
  Everything runs in the browser; nothing you type leaves the page. This also
  means it deploys as plain static files to any web root.
- **Correct.** Each tool's logic lives in a plain ES module (`*.js`) with a
  matching `*.test.js` that runs under Node's built-in test runner. No tool
  ships without passing tests. No build step: the same module the tests import is
  the one the browser loads.
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

- **subnet** — IPv4 CIDR / subnet calculator.
- **cron** — cron expression explainer: plain-English description plus next run
  times (Vixie semantics, incl. the dom/dow either-matches rule).
- **jwt** — JWT decoder: header/claims with plain-English notes, expiry status,
  alg-none warning, HS256/384/512 verification via WebCrypto. Decoding is
  deliberately lenient (tolerates padding, non-canonical trailing bits);
  verification is byte-exact.
- **url** — URL inspector: components, query parameters (form semantics:
  `+` as space, repeated keys), strict percent-decoding with error positions,
  punycode/IDN hostname display (own RFC 3492 decoder, differential-tested
  against Node's `domainToUnicode`), and warnings for embedded credentials,
  credential-looking query parameters, and lookalike hostnames.
