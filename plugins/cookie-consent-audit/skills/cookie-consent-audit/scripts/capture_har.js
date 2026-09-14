#!/usr/bin/env node
/**
 * capture_har.js — Capture three network states for a cookie consent audit:
 *   1. pre       — fresh session, no interaction with the consent banner
 *   2. postaccept — fresh session, click "Accept All" (or equivalent)
 *   3. postreject — fresh session, click "Reject All" (or equivalent)
 *
 * Each state uses a brand-new browser context (no shared cookies/localStorage)
 * so results aren't contaminated by a previous run.
 *
 * Usage:
 *   node capture_har.js <url> [--outdir ./out] [--wait 4000]
 *                       [--accept-selector "<css>"] [--reject-selector "<css>"]
 *                       [--paths "/,/about,/pricing"]
 *                       [--executable-path /path/to/chrome]
 *
 * If Playwright's bundled Chromium isn't available (some CI images ship their
 * own browser), point at it with --executable-path or the
 * CONSENT_AUDIT_CHROMIUM environment variable.
 *
 * Requires: npm install playwright && npx playwright install chromium
 */
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
      args[key] = val;
    } else {
      args._.push(a);
    }
  }
  return args;
}

// Known consent-management-platform button profiles, tried in order.
// Each entry gives CSS selectors for Accept All / Reject All / Open-settings.
const CMP_PROFILES = [
  {
    name: 'CookieYes',
    accept: '[data-cky-tag="accept-button"]',
    reject: '[data-cky-tag="reject-button"]',
  },
  {
    name: 'OneTrust',
    accept: '#onetrust-accept-btn-handler',
    reject: '#onetrust-reject-all-handler',
  },
  {
    name: 'Cookiebot',
    accept: '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll, #CybotCookiebotDialogBodyButtonAccept',
    reject: '#CybotCookiebotDialogBodyButtonDecline',
  },
  {
    name: 'Termly',
    accept: '.termly-styles-btn-accept, [data-tid="banner-accept"]',
    reject: '.termly-styles-btn-reject, [data-tid="banner-reject"]',
  },
  {
    name: 'Osano',
    accept: '.osano-cm-accept-all',
    reject: '.osano-cm-deny-all',
  },
  {
    name: 'Usercentrics',
    accept: '[data-testid="uc-accept-all-button"]',
    reject: '[data-testid="uc-deny-all-button"]',
  },
];

// Fallback: search visible buttons/links by text content.
const ACCEPT_TEXT = /^(accept all|allow all|accept cookies|i accept|agree|allow cookies)$/i;
const REJECT_TEXT = /^(reject all|decline all|reject cookies|deny all|do not accept|necessary only|reject)$/i;

async function findButton(page, selectorList, textPattern) {
  if (selectorList) {
    for (const sel of selectorList.split(',').map((s) => s.trim())) {
      const el = page.locator(sel).first();
      if ((await el.count()) > 0 && (await el.isVisible().catch(() => false))) return el;
    }
  }
  // Fallback: scan clickable text
  const candidates = page.locator('button, a[role="button"], [role="button"], a');
  const count = await candidates.count();
  for (let i = 0; i < count; i++) {
    const el = candidates.nth(i);
    const visible = await el.isVisible().catch(() => false);
    if (!visible) continue;
    const text = (await el.innerText().catch(() => ''))?.trim();
    if (text && textPattern.test(text)) return el;
  }
  return null;
}

async function detectAndClick(page, kind, overrideSelector) {
  const textPattern = kind === 'accept' ? ACCEPT_TEXT : REJECT_TEXT;

  if (overrideSelector) {
    const el = page.locator(overrideSelector).first();
    if ((await el.count()) > 0) {
      await el.click({ timeout: 5000 });
      return { matched: 'override', selector: overrideSelector };
    }
  }

  for (const profile of CMP_PROFILES) {
    const sel = profile[kind];
    const el = await findButton(page, sel, textPattern);
    if (el) {
      await el.click({ timeout: 5000 });
      return { matched: profile.name, selector: sel };
    }
  }

  // Last resort: pure text scan with no selector hints
  const el = await findButton(page, null, textPattern);
  if (el) {
    await el.click({ timeout: 5000 });
    return { matched: 'text-fallback', selector: null };
  }

  return null;
}

// Cookie values can carry identifiers, so record a short preview and the length
// rather than the raw value — audits need the name/domain/lifetime, not the payload.
function summarizeCookie(c) {
  const val = typeof c.value === 'string' ? c.value : '';
  const persistent = typeof c.expires === 'number' && c.expires > 0;
  return {
    name: c.name,
    domain: c.domain,
    path: c.path,
    session_cookie: !persistent,
    expires_days: persistent ? Math.round((c.expires * 1000 - Date.now()) / 86400000) : null,
    http_only: !!c.httpOnly,
    secure: !!c.secure,
    same_site: c.sameSite || null,
    value_preview: val.length > 24 ? val.slice(0, 24) + '...' : val,
    value_length: val.length,
  };
}

// HAR files only record HTTP traffic, so client-side `document.cookie` writes and
// localStorage/sessionStorage never appear there. Pull them from the live context
// before it closes so the audit sees storage the network capture structurally misses.
async function captureStorage(context, page) {
  const out = { cookies: [], local_storage: [], session_storage: [], errors: [] };

  try {
    const state = await context.storageState();
    out.cookies = (state.cookies || []).map(summarizeCookie);
    for (const origin of state.origins || []) {
      for (const item of origin.localStorage || []) {
        out.local_storage.push({
          origin: origin.origin,
          name: item.name,
          value_length: (item.value || '').length,
        });
      }
    }
  } catch (e) {
    out.errors.push(`storageState: ${e.message}`);
  }

  try {
    const ss = await page.evaluate(() => {
      const items = [];
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        items.push({ name: k, value_length: (sessionStorage.getItem(k) || '').length });
      }
      return { origin: location.origin, items };
    });
    out.session_storage = (ss.items || []).map((it) => ({ origin: ss.origin, ...it }));
  } catch (e) {
    out.errors.push(`sessionStorage: ${e.message}`);
  }

  return out;
}

async function captureState({ url, outPath, storagePath, action, overrideSelectors, waitMs, extraPaths, executablePath }) {
  const browser = await chromium.launch(executablePath ? { executablePath } : {});
  const context = await browser.newContext({ recordHar: { path: outPath, mode: 'full' } });
  const page = await context.newPage();

  const result = { url, action, cmpMatch: null, error: null };

  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(1500); // let the CMP banner render

    if (action === 'accept') {
      result.cmpMatch = await detectAndClick(page, 'accept', overrideSelectors.accept);
    } else if (action === 'reject') {
      result.cmpMatch = await detectAndClick(page, 'reject', overrideSelectors.reject);
    }
    // action === 'pre' → no interaction at all

    await page.waitForTimeout(waitMs);

    // Visit a couple more pages so cookies/tags set on navigation get captured too.
    // This runs for the pre-consent state as well: browsing a different number of
    // pages per state would make the request counts and tracker sets incomparable,
    // and would hide pre-consent trackers that only fire on deeper pages.
    if (extraPaths && extraPaths.length) {
      for (const p of extraPaths) {
        try {
          await page.goto(new URL(p, url).toString(), { waitUntil: 'networkidle', timeout: 20000 });
          await page.waitForTimeout(Math.min(waitMs, 2000));
        } catch (e) {
          // non-fatal — keep going
        }
      }
    }
    result.storage = await captureStorage(context, page);
  } catch (e) {
    result.error = e.message;
  } finally {
    await context.close(); // HAR is flushed on context close
    await browser.close();
  }

  if (result.storage && storagePath) {
    fs.writeFileSync(storagePath, JSON.stringify({ state: action, ...result.storage }, null, 2));
    result.storageFile = storagePath;
    result.cookieCount = result.storage.cookies.length;
    result.localStorageCount = result.storage.local_storage.length;
    delete result.storage; // keep capture-summary.json readable; detail lives in the storage file
  }

  return result;
}

(async () => {
  const args = parseArgs(process.argv.slice(2));
  const url = args._[0];
  if (!url) {
    console.error('Usage: node capture_har.js <url> [--outdir ./out] [--wait 4000] [--accept-selector css] [--reject-selector css] [--paths "/a,/b"] [--executable-path /path/to/chrome]');
    process.exit(1);
  }

  const outdir = args.outdir || './out';
  const waitMs = parseInt(args.wait || '4000', 10);
  const extraPaths = args.paths ? args.paths.split(',').map((s) => s.trim()).filter(Boolean) : [];
  const overrideSelectors = { accept: args['accept-selector'] || null, reject: args['reject-selector'] || null };
  const executablePath = args['executable-path'] || process.env.CONSENT_AUDIT_CHROMIUM || null;

  fs.mkdirSync(outdir, { recursive: true });

  const states = [
    { action: 'pre', file: 'pre.har' },
    { action: 'accept', file: 'postaccept.har' },
    { action: 'reject', file: 'postreject.har' },
  ];

  const summary = { url, capturedAt: new Date().toISOString(), states: {} };

  for (const s of states) {
    const outPath = path.join(outdir, s.file);
    // Name the storage file after the HAR (pre/postaccept/postreject), not the
    // action verb, so the analyzer finds it alongside its matching capture.
    const storagePath = path.join(outdir, s.file.replace(/\.har$/, '.storage.json'));
    console.log(`Capturing [${s.action}] -> ${outPath}`);
    const result = await captureState({ url, outPath, storagePath, action: s.action, overrideSelectors, waitMs, extraPaths, executablePath });
    summary.states[s.action] = { ...result, harFile: outPath };
    if (result.error) {
      console.warn(`  Warning: ${result.error}`);
    } else if (s.action !== 'pre') {
      console.log(`  Consent button matched via: ${result.cmpMatch ? result.cmpMatch.matched : 'NOT FOUND'}`);
    }
    if (result.cookieCount !== undefined) {
      console.log(`  Cookies: ${result.cookieCount}, localStorage keys: ${result.localStorageCount}`);
    }
  }

  const summaryPath = path.join(outdir, 'capture-summary.json');
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
  console.log(`\nDone. Summary written to ${summaryPath}`);

  const anyMissing = ['accept', 'reject'].some((k) => !summary.states[k].cmpMatch && !summary.states[k].error);
  if (anyMissing) {
    console.warn('\nWARNING: Could not auto-detect Accept/Reject buttons for at least one state.');
    console.warn('Re-run with --accept-selector and --reject-selector pointing at the real buttons.');
  }
})();
