---
name: cookie-consent-audit
description: Automates a cookie/tracking consent compliance audit for any website. Use this whenever the user asks to audit, check, or verify cookie consent behavior, GDPR/CCPA cookie compliance, whether trackers fire before consent, or wants a "cookie audit", "consent audit", or similar report for a site. Also trigger if the user asks to compare pre-consent vs post-consent network traffic, or wants to verify a cookie banner (CookieYes, OneTrust, Cookiebot, Termly, Osano, Usercentrics, or a custom banner) is gating trackers correctly. Requires a real browser with internet access (Playwright) — run this in Claude Code or another environment with network access, not a sandboxed chat environment.
license: Apache-2.0
metadata:
  author: yomillzee
  version: "1.0"
---

# Cookie Consent Audit

Automates the full workflow: ask for a website → capture live network traffic,
cookies and web storage before and after a consent decision, **and once per
individual consent category** → classify everything observed → produce a
client-ready Word report.

This is a **full-disclosure audit**. Every tracker, cookie and third-party
domain observed is carried through to the report. The allowlist only changes how
an item is *labelled* so the headline gap count stays legally meaningful — it
never hides anything. Do not filter findings when summarizing for the user.

## Prerequisites

This skill needs a real browser and real internet access. It will NOT work in a
sandboxed environment with restricted network egress (e.g. a locked-down chat
sandbox) — it needs to reach the actual target site. Claude Code on a local
machine, or a CI runner with open network access, both work.

Python 3 (standard library only) is used for `analyze_har.py`; Node 18+ for the
other two scripts.

## Workflow

### 0. Locate the scripts and install dependencies

All script paths below are relative to `$SCRIPTS`. Set it once at the start of
the session:

```bash
SCRIPTS="${CLAUDE_PLUGIN_ROOT}/skills/cookie-consent-audit/scripts"
```

If `CLAUDE_PLUGIN_ROOT` is unset (the skill was copied into a project as a plain
skill rather than installed as a plugin), set `SCRIPTS` to the `scripts/`
directory sitting next to this SKILL.md instead.

Then bootstrap the runtime dependencies. This is idempotent — it's a no-op after
the first run, so just run it rather than asking the user whether they've done it:

```bash
cd "$SCRIPTS" && [ -d node_modules ] || npm install
npx playwright install chromium
```

### 1. Get the target site

Ask the user for the website URL if not already given. Confirm whether to test
production or staging — staging is safer since the capture clicks Accept/Reject
and navigates multiple pages.

### 2. Capture network traffic

Run from the user's working directory so output lands somewhere they can find:

```bash
node "$SCRIPTS/capture_har.js" <url> --outdir ./audit-out --paths "/,/about,/pricing"
```

This produces `pre.har`, `postaccept.har`, `postreject.har`, one
`category-<name>.har` per consent category the banner exposes, matching
`<state>.storage.json` files, and `capture-summary.json` in `./audit-out`. Each
capture uses a fresh, isolated browser context so results from one state can't
leak into another, and every state visits the same pages so the three are
directly comparable.

The `.storage.json` files hold cookies, localStorage and sessionStorage read
straight from the browser. This matters: most tracking cookies (`_ga`, `_fbp`,
`_hjSessionUser`) are written client-side as **first-party** cookies and never
appear in HAR traffic at all, so a network-only capture misses them.

The script auto-detects the consent banner using known selector profiles for
CookieYes, OneTrust, Cookiebot, Termly, Osano, and Usercentrics, falling back
to a text-based scan for buttons labeled things like "Accept All" / "Reject All".

**If auto-detection fails** (check the console output — it warns if a button
wasn't found), inspect the site's banner manually and re-run with explicit
selectors:

```bash
node "$SCRIPTS/capture_har.js" <url> --outdir ./audit-out \
  --accept-selector "#my-accept-button" \
  --reject-selector "#my-reject-button"
```

#### Per-category consent testing

By default the capture also opens the banner's preferences panel and runs one
scenario per category it finds: grant exactly that category, deny every other
non-necessary one, save, then re-capture. This catches the common failure where
accepting analytics silently enables advertising too — which all-accept and
all-reject testing cannot detect.

Each scenario writes a `category-<name>.config.json` recording exactly which
toggles were found and set. **A scenario whose panel could not be driven is
reported as inconclusive, never as a pass** — an empty violation list there
means "not tested", and you must say so rather than reporting it as clean.

If auto-detection misses the panel, pass the selectors explicitly:

```bash
node "$SCRIPTS/capture_har.js" <url> --outdir ./audit-out \
  --settings-selector "#open-preferences" --save-selector "#save-preferences"
```

Use `--categories "analytics,advertising"` to force a specific set, or
`--skip-categories` to skip this phase (it adds one capture per category).

**If Playwright's bundled Chromium is unavailable** (some CI images ship their
own browser), point at it explicitly:

```bash
node "$SCRIPTS/capture_har.js" <url> --outdir ./audit-out --executable-path /path/to/chrome
# or: export CONSENT_AUDIT_CHROMIUM=/path/to/chrome
```

### 3. Analyze the captures

```bash
python3 "$SCRIPTS/analyze_har.py" ./audit-out
```

This classifies requests against `trackers.json` (URL signatures) and cookies
against `cookie_signatures.json` (cookie-name signatures, since first-party
tracking cookies can only be identified by name), maps each service to a consent
category via `tracker_categories.json`, then writes
`./audit-out/findings.json`, which includes:

- `capture_usable` / `capture_errors` / `states_inconclusive`: whether the site
  actually loaded in each state. If any state failed, everything below it was
  never observed and must not be reported as a pass
- `technology_matrix`: the client-facing inventory — one row per technology with
  vendor, purpose, how many pages it was found on, what it did before consent /
  after accept / after reject, a red/amber/green status and a recommended action
- `health_score` / `health_deductions`: a 0-100 score from a transparent
  deduction rubric, with every point traced to a named finding. Suppressed
  (`null`) when the capture is unusable
- `duplicate_tags` / `legacy_tags`: technologies deployed more than once with
  different container IDs, and Universal Analytics tags still firing
- `tracker_matrix`: **every** tracker observed, with its full pre/accept/reject
  firing pattern, request volume and classification
- `consent_gaps`: trackers that fired **before consent** (high severity) or
  **after rejection** (medium severity) — the core compliance finding
- `cookie_gaps_pre_consent` / `cookie_gaps_after_reject`: tracking or
  third-party cookies present when they shouldn't be
- `necessary_services_active`: services in `necessary_allowlist.json`
  (anti-spam, CAPTCHA, payments, the CMP's own cookie) — labelled, still fully
  reported, but excluded from the headline gap count
- `category_tests`: one entry per category scenario, each with its violations
  (trackers that fired while their category was denied), the toggles that were
  actually applied, and a `configured` flag
- `category_violations`: violations from **conclusive** scenarios only
- `category_scenarios_inconclusive`: scenarios that could not be tested
- `third_party_domains_all_states`: every non-first-party domain contacted,
  with unclassified ones flagged for manual review
- Complete per-state cookie, localStorage and sessionStorage inventories

A tracker with no signature entry still appears as an unclassified domain — it
is never dropped. Add known services to `trackers.json` / `cookie_signatures.json`
so future audits name them, and flag the rest to the user for manual review.

### 4. Generate the client-ready report

```bash
node "$SCRIPTS/generate_report.js" ./audit-out/findings.json "<Site Display Name>" "<url>" \
  --out "Cookie_Consent_Compliance_Review.docx"
```

This produces a formatted Word document covering: executive summary, audit
scope, the full tracker inventory, consent-gap analysis, services classified as
necessary (with their firing pattern shown so the classification can be
reviewed), complete cookie and web-storage tables per state, every third-party
domain contacted, recommendations tailored to the findings, and methodology
with its limitations stated.

If LibreOffice is available, verify it renders before handing it over:

```bash
soffice --headless --convert-to pdf Cookie_Consent_Compliance_Review.docx
pdftoppm -jpeg -r 100 Cookie_Consent_Compliance_Review.pdf page
```
(then view the resulting `page-*.jpg` files — skip this step if `soffice` isn't
installed, it's a visual check only)

### 5. Present results

Summarize the top-line finding conversationally (e.g. "No gaps found — X, Y, Z
trackers all correctly wait for consent" or "Found N trackers firing before
consent — see the report"), then deliver the .docx.

Report per-category results honestly. If a scenario is inconclusive, say it was
not tested and why — never fold it into a clean result. If no per-category
controls were found at all, say that only all-accept and all-reject were
exercised.

## Notes and limitations

- A capture in which a state failed to load is **inconclusive, not clean**. The
  page never rendered, so nothing could fire: an empty gap list there means "not
  tested". `capture_har.js` exits non-zero and `analyze_har.py` sets
  `capture_usable: false`, lists the failed states in `capture_errors`, and the
  report is stamped inconclusive rather than reporting a pass. Fix the cause
  (network access, URL, browser) and re-run before reporting anything.
- Auto-detection covers common CMPs; unusual custom banners may need manual
  selectors (see step 2).
- `trackers.json`, `cookie_signatures.json`, `tracker_categories.json`,
  `vendors.json` and `necessary_allowlist.json` are living lists — extend them as
  new services come up, rather than hardcoding new logic into the scripts. A
  service added to a signature list must also be given a category **and** a
  vendor/purpose entry, or `smoke_test.sh` will fail.
- The health score is a deduction rubric for prioritizing work, **not** a legal
  grade or a certification. It is reported alongside the deductions that produced
  it so a client can argue with the number. Never present it as a compliance
  verdict.
- "Pages found" counts distinct pages a technology was seen on, attributed by
  walking the HAR in order and treating each first-party document request as a
  page boundary. Playwright reuses one page object across navigations, so its
  `pageref` is identical for every entry and cannot be used for this. When a
  capture records no document entries the column reads `—` rather than 0.
- Google consent mode is read from the `gcs` parameter: a tag pinging with
  storage denied (`G100`) is reported as a "cookieless ping" rather than being
  flattened into "fired". Whether such a ping is lawful before consent is a legal
  determination, so it is surfaced as amber for review — never auto-passed.
- Which category a service belongs to is a judgment call that should be checked
  against the client's own declared cookie categories, not assumed.
- Per-category testing drives the CMP's own UI. Unusual panels may need explicit
  `--settings-selector` / `--save-selector` values.
- First/third-party classification uses a best-effort registrable-domain
  heuristic rather than the full public suffix list.
- A capture is a point-in-time snapshot. Tag manager changes can alter behavior
  immediately afterwards.
- Whether a service is "strictly necessary" is a legal determination, not a
  technical one. Present the allowlist as an assumption to be confirmed, never
  as a settled conclusion.
- Consider running the capture against staging rather than production if the
  site has irreversible actions tied to page navigation (forms, purchases).
