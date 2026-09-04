#!/usr/bin/env node
'use strict';

// scripts/capture-stage.js
//
// Captures a stage of the zero-trust PoW challenge flow and writes a PNG
// straight into the Obsidian asset folder.
//
// Usage:
//   node scripts/capture-stage.js challenge      # initial PoW screen (pre-solve)
//   node scripts/capture-stage.js verified       # post-auth state after WASM solve
//
// Output:   <OUT_DIR>/<stage>.png   (default OUT_DIR is the Obsidian screenshots dir)
//
// Env overrides:
//   CAPTURE_URL    target to load  (default https://127.0.0.1:8443/ — local dev TLS)
//   CAPTURE_NAME   output filename stem (default: the stage name) — lets a
//                  caller keep the standard 'verified' behavior but save under
//                  a bespoke name, e.g. CAPTURE_NAME=stage-0-initial-deployment
//   CAPTURE_OUT_DIR  where the PNG is written
//   CHROME_PATH    explicit Chrome/Chromium executable (defaults to system Chrome)
//
// TLS: ignoreHTTPSErrors is always on, so a local self-signed dev cert is fine.

const path = require('path');
const fs = require('fs');
const { chromium } = require('playwright');

const OUT_DIR =
  process.env.CAPTURE_OUT_DIR ||
  '/home/splayingcow/Obsidian/08_Assets/screenshots';
const BASE_URL = process.env.CAPTURE_URL || 'https://127.0.0.1:8443/';
const CHROME_PATH =
  process.env.CHROME_PATH || '/usr/bin/google-chrome';

// The two canonical stages.
const STAGES = new Set(['challenge', 'verified']);

async function launchBrowser() {
  // Prefer system Chrome (no Playwright browser download needed). Some
  // Playwright versions can use channel:'chrome' directly; fall back to an
  // explicit executable path if that is unavailable.
  const launchOpts = { headless: true };
  try {
    return await chromium.launch({ ...launchOpts, channel: 'chrome' });
  } catch (err) {
    console.warn(
      `channel:'chrome' unavailable (${err.message.split('\n')[0]}); ` +
        `launching ${CHROME_PATH}`,
    );
    return chromium.launch({ ...launchOpts, executablePath: CHROME_PATH });
  }
}

async function main() {
  const stage = process.argv[2];
  if (!stage || !STAGES.has(stage)) {
    console.error(
      'Usage: node scripts/capture-stage.js <stage>\n' +
        '  challenge   initial PoW challenge screen (before the WASM solve)\n' +
        '  verified    post-auth state, after the WASM solve + redirect',
    );
    process.exit(1);
  }

  const outName = process.env.CAPTURE_NAME || stage;
  const outFile = path.join(OUT_DIR, `${outName}.png`);

  fs.mkdirSync(OUT_DIR, { recursive: true });

  const browser = await launchBrowser();
  const context = await browser.newContext({
    ignoreHTTPSErrors: true, // local self-signed dev cert
    viewport: { width: 1280, height: 900 },
  });
  const page = await context.newPage();

  try {
    if (stage === 'challenge') {
      // Deterministically capture the PRE-SOLVE frame: hold the WASM fetch
      // so the solve never starts (and the page never redirects) until after
      // the screenshot. challenge.js only calls glue.default(wasm) → solve()
      // once that fetch resolves.
      let releaseWasm;
      const wasmGate = new Promise((resolve) => {
        releaseWasm = resolve;
      });
      await page.route('**/pow_challenge.wasm', async (route) => {
        await wasmGate;
        await route.continue();
      });

      await page.goto(BASE_URL, { waitUntil: 'domcontentloaded' });
      await page.waitForSelector('#challenge-data', { timeout: 15000 });
      await page.waitForTimeout(600); // let CSS paint the initial frame
      await page.screenshot({ path: outFile });

      releaseWasm(); // unblock; we close the browser right after anyway
    } else {
      // 'verified': load, let the page WASM solve the challenge and the
      // browser follow the /pow/verify redirect, then capture the
      // authenticated result. Waits for the challenge element to leave the
      // DOM (i.e. real content replaced it) up to a generous cap.
      await page.goto(BASE_URL, { waitUntil: 'domcontentloaded' });

      const wasChallenge = await page
        .waitForSelector('#challenge-data', {
          state: 'attached',
          timeout: 8000,
        })
        .then(() => true)
        .catch(() => false);

      if (wasChallenge) {
        await page.waitForFunction(
          () => !document.getElementById('challenge-data'),
          { timeout: 30000 },
        );
      }
      await page.waitForTimeout(500); // let post-auth layout settle
      await page.screenshot({ path: outFile });
    }

    console.log(`[capture-stage] wrote ${outFile}`);
  } finally {
    await browser.close();
  }
}

main().catch((err) => {
  console.error(`[capture-stage] failed: ${err.message}`);
  process.exit(1);
});
