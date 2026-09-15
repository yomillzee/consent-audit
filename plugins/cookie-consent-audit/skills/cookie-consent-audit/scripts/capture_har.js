#!/usr/bin/env node
/**
 * capture_har.js — Capture the network/storage states for a cookie consent audit:
 *   1. pre        — fresh session, no interaction with the consent banner
 *   2. postaccept — fresh session, click "Accept All" (or equivalent)
 *   3. postreject — fresh session, click "Reject All" (or equivalent)
 *   4. category:X — fresh session, open the preferences panel and grant ONLY
 *                   category X, denying every other non-necessary category.
 *                   One capture per category the CMP exposes.
 *
 * Each state uses a brand-new browser context (no shared cookies/localStorage)
 * so results aren't contaminated by a previous run.
 *
 * Usage:
 *   node capture_har.js <url> [--outdir ./out] [--wait 4000]
 *                       [--accept-selector "<css>"] [--reject-selector "<css>"]
 *                       [--paths "/,/about,/pricing"]
 *                       [--executable-path /path/to/chrome]
 *                       [--categories auto|analytics,advertising] [--skip-categories]
 *                       [--settings-selector "<css>"] [--save-selector "<css>"]
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
    settings: '[data-cky-tag="settings-button"]',
    save: '[data-cky-tag="detail-save-button"]',
  },
  {
    name: 'OneTrust',
    accept: '#onetrust-accept-btn-handler',
    reject: '#onetrust-reject-all-handler',
    settings: '#onetrust-pc-btn-handler',
    save: '.save-preference-btn-handler',
  },
  {
    name: 'Cookiebot',
    accept: '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll, #CybotCookiebotDialogBodyButtonAccept',
    reject: '#CybotCookiebotDialogBodyButtonDecline',
    settings: '#CybotCookiebotDialogBodyLevelButtonCustomize, #CybotCookiebotDialogBodyButtonDetails',
    save: '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowallSelection, #CybotCookiebotDialogBodyButtonAcceptSelected',
  },
  {
    name: 'Termly',
    accept: '.termly-styles-btn-accept, [data-tid="banner-accept"]',
    reject: '.termly-styles-btn-reject, [data-tid="banner-reject"]',
    settings: '[data-tid="banner-manage"], .termly-styles-btn-manage',
    save: '[data-tid="prefs-save"], .termly-styles-btn-save',
  },
  {
    name: 'Osano',
    accept: '.osano-cm-accept-all',
    reject: '.osano-cm-deny-all',
    settings: '.osano-cm-manage, .osano-cm-link--type_manage',
    save: '.osano-cm-save, .osano-cm-button--type_save',
  },
  {
    name: 'Usercentrics',
    accept: '[data-testid="uc-accept-all-button"]',
    reject: '[data-testid="uc-deny-all-button"]',
    settings: '[data-testid="uc-more-button"], [data-testid="uc-customize-button"]',
    save: '[data-testid="uc-save-button"]',
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

const SETTINGS_TEXT = /(cookie settings|manage preferences|manage options|manage cookies|customi[sz]e|preferences|let me choose|more options|settings)/i;
const SAVE_TEXT = /(save preferences|save settings|save my choices|save and close|confirm choices|confirm my choices|allow selection|accept selection|save choices|^save$|^confirm$)/i;

// Consent categories, most specific first: "personalisation" appears in both
// functional and advertising wording, so functional must be tested first.
const CATEGORY_PATTERNS = [
  ['necessary', /necessar|essential|strictly|always active|required/i],
  ['functional', /functional|preference/i],
  ['analytics', /analytic|statistic|performance|measurement/i],
  ['advertising', /advertis|marketing|targeting|personali[sz]|social media/i],
];

function categoryOf(text) {
  for (const [cat, re] of CATEGORY_PATTERNS) {
    if (re.test(text)) return cat;
  }
  return null;
}

const TOGGLE_SELECTOR = 'input[type="checkbox"], [role="switch"]';

// Read every toggle in the preferences panel along with the label a human would
// read next to it, so categories can be matched without per-CMP DOM knowledge.
async function enumerateCategoryToggles(page) {
  return page.evaluate((sel) => {
    const isOn = (el) => (el.getAttribute('role') === 'switch'
      ? el.getAttribute('aria-checked') === 'true'
      : !!el.checked);
    return Array.from(document.querySelectorAll(sel)).map((el, index) => {
      let label = el.getAttribute('aria-label') || '';
      if (!label && el.id) {
        const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`);
        if (l) label = l.innerText || l.textContent || '';
      }
      if (!label.trim()) {
        let node = el.parentElement;
        for (let d = 0; node && d < 4 && !label.trim(); d++, node = node.parentElement) {
          label = node.innerText || node.textContent || '';
        }
      }
      return {
        index,
        label: (label || '').replace(/\s+/g, ' ').trim().slice(0, 120),
        checked: isOn(el),
        disabled: !!el.disabled || el.getAttribute('aria-disabled') === 'true',
      };
    });
  }, TOGGLE_SELECTOR);
}

// CMPs style their switches in many ways, so try the native control, then the
// associated label, then a forced click — verifying the state after each.
async function setToggle(page, index, wantChecked) {
  const loc = page.locator(TOGGLE_SELECTOR).nth(index);
  const state = () => loc.evaluate((el) => (el.getAttribute('role') === 'switch'
    ? el.getAttribute('aria-checked') === 'true'
    : !!el.checked));

  if ((await state().catch(() => null)) === wantChecked) return 'already-correct';

  try {
    if (wantChecked) await loc.check({ timeout: 2000 });
    else await loc.uncheck({ timeout: 2000 });
    if ((await state()) === wantChecked) return 'native';
  } catch (e) { /* styled switch — fall through */ }

  try {
    await loc.evaluate((el) => {
      const lbl = (el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`)) || el.closest('label');
      if (lbl) lbl.click();
    });
    if ((await state()) === wantChecked) return 'label-click';
  } catch (e) { /* fall through */ }

  try {
    await loc.click({ force: true, timeout: 2000 });
    if ((await state()) === wantChecked) return 'force-click';
  } catch (e) { /* fall through */ }

  return 'failed';
}

// Open the preferences panel and grant exactly one category, denying every
// other non-necessary one. Returns enough detail for the analyzer to decide
// whether the scenario is trustworthy evidence at all.
async function configureCategories(page, grantCategory, profile, overrides) {
  const result = {
    granted: grantCategory, opened: false, saved: false, target_applied: false,
    toggles: [], categories_seen: [], failures: [], error: null,
  };

  const settingsSel = (overrides && overrides.settings) || (profile && profile.settings) || null;
  const settingsEl = await findButton(page, settingsSel, SETTINGS_TEXT);
  if (!settingsEl) {
    result.error = 'preferences/settings button not found';
    return result;
  }
  try {
    await settingsEl.click({ timeout: 5000 });
  } catch (e) {
    result.error = `could not open preferences: ${e.message}`;
    return result;
  }
  result.opened = true;
  await page.waitForTimeout(1500);

  const toggles = await enumerateCategoryToggles(page);
  for (const t of toggles) {
    const cat = categoryOf(t.label);
    if (!cat) continue;
    if (!result.categories_seen.includes(cat)) result.categories_seen.push(cat);
    // Necessary is locked in every compliant CMP; leave it alone.
    if (cat === 'necessary' || t.disabled) continue;

    const want = cat === grantCategory;
    const status = await setToggle(page, t.index, want);
    result.toggles.push({ label: t.label, category: cat, wanted: want, status });
    if (status === 'failed') result.failures.push(`${cat}: could not set to ${want}`);
    else if (cat === grantCategory && want) result.target_applied = true;
  }

  if (!result.toggles.length) {
    result.error = 'no category toggles found in the preferences panel';
    return result;
  }

  const saveSel = (overrides && overrides.save) || (profile && profile.save) || null;
  const saveEl = await findButton(page, saveSel, SAVE_TEXT);
  if (!saveEl) {
    result.error = 'save/confirm button not found in the preferences panel';
    return result;
  }
  try {
    await saveEl.click({ timeout: 5000 });
    result.saved = true;
  } catch (e) {
    result.error = `could not save preferences: ${e.message}`;
  }
  return result;
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

// Consent banners are routinely geo-targeted, and the targeting is done on the
// visitor's IP address. Locale and timezone do not move it: a US runner with a
// European locale is still a US visitor as far as the CMP is concerned. A real
// European test needs an egress proxy in the region, which is what --proxy is
// for; --locale and --timezone only cover the minority of banners that read
// browser hints. Neither is a substitute for testing from the right country.
function browserEnv(args) {
  return {
    executablePath: args['executable-path'] || process.env.CONSENT_AUDIT_CHROMIUM || null,
    proxy: (args.proxy && args.proxy !== true) ? args.proxy : (process.env.CONSENT_AUDIT_PROXY || null),
    locale: (args.locale && args.locale !== true) ? args.locale : null,
    timezone: (args.timezone && args.timezone !== true) ? args.timezone : null,
  };
}

function launchOpts(env) {
  const opts = {};
  if (env.executablePath) opts.executablePath = env.executablePath;
  if (env.proxy) opts.proxy = { server: env.proxy };
  return opts;
}

function contextOpts(env, extra = {}) {
  const opts = { ...extra };
  if (env.locale) opts.locale = env.locale;
  if (env.timezone) opts.timezoneId = env.timezone;
  return opts;
}

// Three hand-picked paths is thin coverage for a site of any size: a tag
// present only on a landing or form page is invisible to it. Reading the site's
// own navigation makes coverage follow the site instead of a guess.
async function discoverPaths(url, limit, env) {
  const browser = await chromium.launch(launchOpts(env));
  const context = await browser.newContext(contextOpts(env));
  const page = await context.newPage();
  const found = [];
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
    const origin = new URL(url).origin;
    const hrefs = await page.$$eval('a[href]', (as) => as.map((a) => a.href));
    const seen = new Set();
    for (const href of hrefs) {
      let u;
      try { u = new URL(href); } catch { continue; }
      if (u.origin !== origin) continue;
      const path_ = (u.pathname.replace(/\/+$/, '') || '/');
      if (path_ === '/' || seen.has(path_)) continue;
      if (/\.(pdf|jpe?g|png|gif|svg|webp|zip|docx?|xlsx?|mp4|avi)$/i.test(path_)) continue;
      seen.add(path_);
      found.push(path_);
      if (found.length >= limit) break;
    }
  } catch (e) {
    console.warn(`  Could not read the site navigation (${e.message.split('\n')[0]}); falling back to the given paths.`);
  } finally {
    await context.close();
    await browser.close();
  }
  return found;
}

async function captureState({ url, outPath, storagePath, configPath, action, overrideSelectors, waitMs, extraPaths, env, detectedCmp }) {
  const browser = await chromium.launch(launchOpts(env));
  const context = await browser.newContext(contextOpts(env, { recordHar: { path: outPath, mode: 'full' } }));
  const page = await context.newPage();

  const result = { url, action, cmpMatch: null, error: null };

  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(1500); // let the CMP banner render

    if (action === 'accept') {
      result.cmpMatch = await detectAndClick(page, 'accept', overrideSelectors.accept);
    } else if (action === 'reject') {
      result.cmpMatch = await detectAndClick(page, 'reject', overrideSelectors.reject);
    } else if (action.startsWith('category:')) {
      const grant = action.slice('category:'.length);
      const profile = CMP_PROFILES.find((pr) => pr.name === detectedCmp) || null;
      result.categoryConfig = await configureCategories(page, grant, profile, overrideSelectors);
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

  if (result.categoryConfig && configPath) {
    fs.writeFileSync(configPath, JSON.stringify(result.categoryConfig, null, 2));
    result.configFile = configPath;
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

// A quick throwaway visit to learn which CMP is in use and which consent
// categories its preferences panel exposes. No HAR is recorded here.
async function discoverCmp(url, overrideSelectors, env) {
  const browser = await chromium.launch(launchOpts(env));
  const context = await browser.newContext(contextOpts(env));
  const page = await context.newPage();
  const found = { cmp: null, categories: [], error: null };
  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(1500);

    for (const profile of CMP_PROFILES) {
      const el = await findButton(page, profile.accept, ACCEPT_TEXT);
      if (el && profile.accept) {
        for (const sel of profile.accept.split(',').map((x) => x.trim())) {
          if ((await page.locator(sel).count()) > 0) { found.cmp = profile.name; break; }
        }
      }
      if (found.cmp) break;
    }

    const profile = CMP_PROFILES.find((pr) => pr.name === found.cmp) || null;
    const settingsSel = overrideSelectors.settings || (profile && profile.settings) || null;
    const settingsEl = await findButton(page, settingsSel, SETTINGS_TEXT);
    if (settingsEl) {
      await settingsEl.click({ timeout: 5000 });
      await page.waitForTimeout(1500);
      for (const t of await enumerateCategoryToggles(page)) {
        const cat = categoryOf(t.label);
        if (cat && cat !== 'necessary' && !t.disabled && !found.categories.includes(cat)) {
          found.categories.push(cat);
        }
      }
    } else {
      found.error = 'no preferences/settings button found';
    }
  } catch (e) {
    found.error = e.message;
  } finally {
    await context.close();
    await browser.close();
  }
  return found;
}

(async () => {
  const args = parseArgs(process.argv.slice(2));
  const url = args._[0];
  if (!url) {
    console.error('Usage: node capture_har.js <url> [--outdir ./out] [--wait 4000] [--accept-selector css] [--reject-selector css] [--paths "/a,/b"] [--executable-path /path/to/chrome] [--categories auto|a,b] [--skip-categories] [--settings-selector css] [--save-selector css] [--discover N] [--proxy http://host:port] [--locale en-GB] [--timezone Europe/London]');
    process.exit(1);
  }

  const outdir = args.outdir || './out';
  const waitMs = parseInt(args.wait || '4000', 10);
  const extraPaths = args.paths ? args.paths.split(',').map((s) => s.trim()).filter(Boolean) : [];
  const discoverLimit = args.discover && args.discover !== true ? parseInt(args.discover, 10) : (args.discover ? 8 : 0);
  const overrideSelectors = {
    accept: args['accept-selector'] || null,
    reject: args['reject-selector'] || null,
    settings: args['settings-selector'] || null,
    save: args['save-selector'] || null,
  };
  const env = browserEnv(args);

  fs.mkdirSync(outdir, { recursive: true });

  let pathsToVisit = extraPaths;
  if (discoverLimit > 0) {
    console.log(`Discovering up to ${discoverLimit} pages from the site navigation...`);
    const discovered = await discoverPaths(url, discoverLimit, env);
    // Explicit --paths always win; discovery tops the list up rather than
    // replacing a deliberate choice.
    const merged = [...extraPaths];
    for (const d of discovered) if (!merged.includes(d)) merged.push(d);
    pathsToVisit = merged;
    console.log(`  Pages to visit: ${pathsToVisit.length ? pathsToVisit.join(', ') : '(homepage only)'}`);
  }

  const states = [
    { action: 'pre', file: 'pre.har' },
    { action: 'accept', file: 'postaccept.har' },
    { action: 'reject', file: 'postreject.har' },
  ];

  // Per-category testing: grant exactly one category and deny the rest, so a
  // tracker from a denied category firing is an unambiguous violation.
  let discovery = { cmp: null, categories: [], error: 'skipped' };
  if (!args['skip-categories']) {
    if (args.categories && args.categories !== true && args.categories !== 'auto') {
      discovery = { cmp: null, categories: String(args.categories).split(',').map((c) => c.trim()).filter(Boolean), error: null };
      console.log(`Category scenarios (explicit): ${discovery.categories.join(', ')}`);
    } else {
      console.log('Detecting consent categories...');
      discovery = await discoverCmp(url, overrideSelectors, env);
      if (discovery.categories.length) {
        console.log(`  CMP: ${discovery.cmp || 'unknown'}; categories: ${discovery.categories.join(', ')}`);
      } else {
        console.warn(`  No per-category controls detected${discovery.error ? ` (${discovery.error})` : ''}. Skipping per-category tests.`);
      }
    }
    for (const cat of discovery.categories) {
      states.push({ action: `category:${cat}`, file: `category-${cat}.har`, category: cat });
    }
  }

  const summary = {
    url,
    capturedAt: new Date().toISOString(),
    cmp: discovery.cmp,
    categories_tested: discovery.categories,
    category_detection_error: discovery.error,
    states: {},
  };

  for (const s of states) {
    const outPath = path.join(outdir, s.file);
    // Name the storage file after the HAR (pre/postaccept/postreject), not the
    // action verb, so the analyzer finds it alongside its matching capture.
    const storagePath = path.join(outdir, s.file.replace(/\.har$/, '.storage.json'));
    const configPath = s.category ? path.join(outdir, s.file.replace(/\.har$/, '.config.json')) : null;
    console.log(`Capturing [${s.action}] -> ${outPath}`);
    const result = await captureState({
      url, outPath, storagePath, configPath, action: s.action, overrideSelectors,
      waitMs, extraPaths: pathsToVisit, env, detectedCmp: discovery.cmp,
    });
    summary.states[s.action] = { ...result, harFile: outPath };
    if (result.error) {
      console.warn(`  Warning: ${result.error}`);
    } else if (s.action === 'accept' || s.action === 'reject') {
      console.log(`  Consent button matched via: ${result.cmpMatch ? result.cmpMatch.matched : 'NOT FOUND'}`);
    }
    if (result.cookieCount !== undefined) {
      console.log(`  Cookies: ${result.cookieCount}, localStorage keys: ${result.localStorageCount}`);
    }
    if (result.categoryConfig) {
      const c = result.categoryConfig;
      const ok = c.opened && c.saved && c.target_applied && !c.failures.length;
      console.log(`  Granted "${c.granted}" only: ${ok ? 'configured' : 'NOT RELIABLY CONFIGURED'}`
        + (c.error ? ` (${c.error})` : '')
        + (c.failures.length ? ` (${c.failures.join('; ')})` : ''));
      if (!ok) {
        console.warn('    This scenario will be reported as inconclusive, not as a pass.');
      }
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

  // A capture where the page never loaded is worthless, but it still writes a
  // summary and three HARs that look superficially like a result. Exiting
  // non-zero stops a pipeline from analyzing and reporting on nothing.
  const failed = Object.entries(summary.states).filter(([, v]) => v.error);
  if (failed.length) {
    console.error(`\nERROR: ${failed.length} of ${Object.keys(summary.states).length} state(s) failed to load:`);
    for (const [name, v] of failed) console.error(`  - ${name}: ${v.error.split('\n')[0]}`);
    console.error('These states observed nothing. Do not read an empty result as "no trackers fired" —');
    console.error('fix the cause (network access, URL, browser) and re-run before analyzing.');
    process.exitCode = 1;
  }
})();
