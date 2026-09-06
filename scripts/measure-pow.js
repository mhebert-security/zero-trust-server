#!/usr/bin/env node
'use strict';

// scripts/measure-pow.js
//
// Measures the PURE WASM PoW solve time (DIFFICULTY=20) from a real browser,
// isolated from page load / network / navigation noise, across CPU tiers.
// This is the tuning baseline — log the output to Obsidian before touching
// the difficulty, and re-run after any change.
//
// Why a harness instead of timing the live challenge page end-to-end:
// timing attach→detach on the real page includes ~1–3 s of fixed overhead
// (module fetch, wasm compile, the /pow/verify round trip, navigation) that
// does NOT scale with CPU speed and swamps the actual solve. Here we serve
// the real deployed pow_challenge glue from a throwaway local static server,
// embed a REAL server-issued nonce (fetched from the live site), then time
// from calling glue.solve() to the instant the solver first touches the
// network (its compute ends where its POST to /pow/verify would begin). That
// window is the solve itself, plus sub-ms glue overhead.
//
// Device-class method: CDP CPU throttling as a SURROGATE for slower hardware.
// 1x ≈ this desktop; 3x ≈ mid-range phone; 6x ≈ low-end phone. It scales CPU
// time, which approximates a slower single core, but is not a real device —
// treat mobile rows as estimates until measured on actual hardware.
//
// Usage:
//   node scripts/measure-pow.js
//   RUNS=5 THROTTLES=1,3,6 node scripts/measure-pow.js
//   CAPTURE_URL=https://mhebert.dev RUNS=3 node scripts/measure-pow.js   (challenge source)
//
// Env:
//   CAPTURE_URL   where to fetch a real challenge nonce (default https://mhebert.dev/)
//   RUNS          iterations per tier        (default 5)
//   THROTTLES     comma-separated CPU rates  (default 1,3,6)

const http = require('http');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const BASE_URL = process.env.CAPTURE_URL || 'https://mhebert.dev/';
const RUNS = parseInt(process.env.RUNS || '5', 10);
const THROTTLES = (process.env.THROTTLES || '1,3,6').split(',').map(Number);

const MIME = {
  '.js': 'text/javascript',
  '.wasm': 'application/wasm',
  '.html': 'text/html',
  '.css': 'text/css',
};

async function launchBrowser() {
  const opts = { headless: true };
  try {
    return await chromium.launch({ ...opts, channel: 'chrome' });
  } catch {
    return chromium.launch({ ...opts, executablePath: '/usr/bin/google-chrome' });
  }
}

// Throwaway server: serves the real static/ directory (so pow_challenge.js /
// .wasm load from the same origin as the harness) plus /harness.html, which is
// re-rendered per request from the CURRENT challenge so each run solves a
// FRESH nonce (a per-visitor solve time is a geometric draw; reusing one nonce
// would hide that variance).
function createServer(getChallenge) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      const url = req.url.split('?')[0];
      if (url === '/harness.html') {
        res.setHeader('Content-Type', 'text/html');
        res.end(harnessHtml(getChallenge()));
        return;
      }
      const file = path.join('static', url === '/' ? 'index.html' : url);
      if (fs.existsSync(file)) {
        res.setHeader('Content-Type', MIME[path.extname(file)] || 'application/octet-stream');
        fs.createReadStream(file).pipe(res);
      } else {
        res.statusCode = 404;
        res.end('nf');
      }
    });
    srv.listen(0, () => resolve(srv));
  });
}

// Pull one live, server-signed challenge (nonce + signature) so the harness
// solve runs against data the server actually issued. The measure never POSTs
// it back; it only times how long the solver computes before it would.
async function fetchLiveChallenge() {
  const html = await (await fetch(BASE_URL)).text();
  const grab = (re) => (html.match(re) || [])[1] || '';
  const nonce = grab(/data-nonce="([^"]*)"/);
  const sig = grab(/data-nonce-sig="([^"]*)"/);
  const dest = grab(/data-destination="([^"]*)"/);
  if (!nonce || !sig) throw new Error(`no challenge data at ${BASE_URL}`);
  return { nonce, sig, dest };
}

function harnessHtml({ nonce, sig, dest }) {
  // Inline module is fine here: the throwaway static server sends no CSP.
  // Patches fetch + XHR so we see the exact moment compute ends and the
  // solver's verify POST begins; the delta from t0 is the solve time.
  return `<!doctype html><html><head><meta charset="utf-8"></head><body>
<div id="challenge-data" data-nonce="${nonce}" data-nonce-sig="${sig}" data-destination="${dest}"></div>
<script type="module">
const glue = await import('/pow_challenge.js');
await glue.default('/pow_challenge.wasm');
let tNet = 0;
const origFetch = window.fetch;
window.fetch = function (u, o) { if (!tNet) tNet = performance.now(); return origFetch.apply(this, arguments); };
const origOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function () { if (!tNet) tNet = performance.now(); return origOpen.apply(this, arguments); };
const t0 = performance.now();
glue.solve();
const iv = setInterval(() => {
  if (tNet) { clearInterval(iv); window.__result = { solveMs: Math.round(tNet - t0) }; }
}, 1);
setTimeout(() => { clearInterval(iv); if (!window.__result) window.__result = { note: 'no network attempt', solveMs: null }; }, 180000);
</script></body></html>`;
}

async function oneSolve(browser, srv, port, throttle) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: throttle });

  try {
    await page.goto(`http://127.0.0.1:${port}/harness.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.__result && window.__result.solveMs, {
      timeout: 190000,
    });
    return await page.evaluate(() => window.__result.solveMs);
  } finally {
    await context.close();
  }
}

function medianAsc(vals) {
  const n = vals.length;
  const mid = Math.floor(n / 2);
  return n % 2 ? vals[mid] : Math.round((vals[mid - 1] + vals[mid]) / 2);
}

async function main() {
  const srv = await createServer(fetchLiveChallenge);
  const port = srv.address().port;

  const browser = await launchBrowser();
  const rows = [];
  for (const t of THROTTLES) {
    const samples = [];
    for (let i = 0; i < RUNS; i++) {
      try {
        // Fresh nonce per run (getChallenge() is called when the harness page
        // is served) so the median spans real per-visitor variance.
        const ms = await oneSolve(browser, srv, port, t);
        samples.push(ms);
        process.stdout.write(`throttle ${t}x run ${i + 1}/${RUNS}: ${ms}ms\n`);
      } catch (e) {
        process.stdout.write(`throttle ${t}x run ${i + 1}/${RUNS}: FAILED (${e.message.split('\n')[0]})\n`);
      }
    }
    if (samples.length) {
      samples.sort((a, b) => a - b);
      rows.push({ t, min: samples[0], med: medianAsc(samples), max: samples[samples.length - 1], n: samples.length });
      console.log(`RESULT throttle ${t}x: median ${rows[rows.length - 1].med}ms  (min ${rows[0] ? rows[rows.length - 1].min : 0}ms, max ${rows[rows.length - 1].max}ms, n=${rows[rows.length - 1].n})`);
    }
  }

  console.log('\n=== Pure WASM PoW solve time (DIFFICULTY=20), harness-isolated ===');
  console.log('tier   CPU-throttle  median(ms)   min(ms)   max(ms)');
  for (const r of rows) {
    console.log(`${String(r.t).padEnd(7)}  ${String(r.med).padEnd(10)}  ${String(r.min).padEnd(9)}  ${String(r.max).padEnd(9)}`);
  }
  console.log('Window = glue.solve() compute until its verify POST would fire;');
  console.log('1x ≈ this desktop, 3x/6x = CPU-throttle surrogates for mobile tiers.');
  console.log('Throughput estimate: expected ~2^20 trials / median(s). Log to Obsidian.');

  await browser.close();
  srv.close();
}

main().catch((e) => {
  console.error(`measure-pow failed: ${e.message}`);
  process.exit(1);
});
