// smoke.mjs — headless-browser smoke test for every page on the site.
// Not part of the deployed site and not run by node --test (no .test.js
// suffix): it needs a Chromium, via the playwright package expected in
// ../devtools (machine-local dev tooling, not a repo dependency).
//
// What it checks, per page: the page and every subresource load (no failed
// requests), no console errors, no uncaught exceptions — then it clicks
// every example button and re-checks, and verifies at least one button
// actually rendered output. This is the layer the unit tests can't see:
// broken imports, typo'd element ids, template/escaping mistakes.
//
// Run: node smoke.mjs

import { createServer } from "node:http";
import { readFile, readdir, stat } from "node:fs/promises";
import { extname, join, normalize } from "node:path";

const ROOT = new URL(".", import.meta.url).pathname;
const MIME = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript",
               ".mjs": "text/javascript", ".svg": "image/svg+xml", ".png": "image/png" };

const server = createServer(async (req, res) => {
  try {
    let path = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname));
    if (path.endsWith("/")) path += "index.html";
    const file = join(ROOT, path);
    if (!file.startsWith(ROOT)) throw new Error("traversal");
    const body = await readFile(file);
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
    res.end(body);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});
await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
const base = `http://127.0.0.1:${server.address().port}`;

const { chromium } = await import(join(ROOT, "../devtools/node_modules/playwright/index.mjs"))
  .catch(() => { console.error("playwright not found in ../devtools — install it there first"); process.exit(2); });

const pages = ["/", "/testing/"];
for (const d of (await readdir(join(ROOT, "tools"))).sort()) {
  if ((await stat(join(ROOT, "tools", d))).isDirectory()) pages.push(`/tools/${d}/`);
}

const browser = await chromium.launch();
let failures = 0;
for (const path of pages) {
  const page = await browser.newPage();
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error") errors.push(`console: ${m.text()}`); });
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("requestfailed", (r) => errors.push(`requestfailed: ${r.url()} ${r.failure()?.errorText}`));
  page.on("response", (r) => { if (r.status() >= 400) errors.push(`http ${r.status()}: ${r.url()}`); });

  await page.goto(base + path, { waitUntil: "networkidle" });
  const before = (await page.evaluate(() => document.body.innerText)).length;

  // Click every example button (clear-buttons last, so output stays).
  const buttons = await page.locator(".examples button").all();
  let rendered = false;
  for (const b of buttons) {
    await b.click();
    await page.waitForTimeout(120);
    const now = (await page.evaluate(() => document.body.innerText)).length;
    const svg = await page.evaluate(() => document.querySelectorAll("svg, canvas, table").length);
    if (now > before + 40 || svg > 0) rendered = true;
  }
  if (buttons.length > 0 && !rendered) errors.push("example buttons produced no visible output");

  if (errors.length) {
    failures++;
    console.error(`FAIL ${path}`);
    for (const e of errors) console.error(`  ${e}`);
  } else {
    console.log(`ok   ${path}  (${buttons.length} example buttons)`);
  }
  await page.close();
}
await browser.close();
server.close();
if (failures) { console.error(`\n${failures} page(s) failed`); process.exit(1); }
console.log(`\nall ${pages.length} pages clean`);
