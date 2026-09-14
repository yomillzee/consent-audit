---
name: cookie-consent-audit
description: Automates a cookie/tracking consent compliance audit for any website. Use this whenever the user asks to audit, check, or verify cookie consent behavior, GDPR/CCPA cookie compliance, whether trackers fire before consent, or wants a "cookie audit", "consent audit", or similar report for a site. Also trigger if the user asks to compare pre-consent vs post-consent network traffic, or wants to verify a cookie banner (CookieYes, OneTrust, Cookiebot, Termly, Osano, Usercentrics, or a custom banner) is gating trackers correctly. Requires a real browser with internet access (Playwright) — run this in Claude Code or another environment with network access, not a sandboxed chat environment.
license: Apache-2.0
metadata:
  author: yomillzee
  version: "1.0"
---

# Cookie Consent Audit

Automates the full workflow: ask for a website → capture live network traffic before and after a consent decision → classify trackers → produce a client-ready Word report.

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

This produces `pre.har`, `postaccept.har`, `postreject.har`, and
`capture-summary.json` in `./audit-out`. Each capture uses a fresh, isolated
browser context so results from one state can't leak into another.

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

This classifies every request in each HAR against `trackers.json` (a
generic signature list covering GA4, Google Ads, Meta Pixel, TikTok, LinkedIn,
HubSpot, Hotjar, Clarity, and more) and writes `./audit-out/findings.json`,
which includes:

- Request counts and detected trackers per state
- `consent_gaps`: trackers that fired **before consent** (high severity) or
  **after rejection** (medium severity) — the core compliance finding
- `trackers_correctly_gated`: trackers that only appeared after Accept
- `necessary_services_active`: services in `necessary_allowlist.json`
  (anti-spam, CAPTCHA, payments) that are expected pre-consent and are
  therefore reported separately rather than counted as gaps

If the site uses a tracker not in `trackers.json`, its domain will show up
under `unknown_domains` in each state's analysis — add a new entry to
`trackers.json` if it's a known service, or mention it to the user for manual
classification.

### 4. Generate the client-ready report

```bash
node "$SCRIPTS/generate_report.js" ./audit-out/findings.json "<Site Display Name>" "<url>" \
  --out "Cookie_Consent_Compliance_Review.docx"
```

This produces a formatted Word document: executive summary, a findings table,
a consent-gap table (if any gaps exist), correctly-gated trackers, necessary
services, and recommendations tailored to whether gaps were found.

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

## Notes and limitations

- HAR captures record HTTP-level network requests, not client-side
  `document.cookie` writes — a tracker's exact cookie names may not appear
  even when its network requests do. The report notes this.
- Auto-detection covers common CMPs; unusual custom banners may need manual
  selectors (see step 2).
- `trackers.json` and `necessary_allowlist.json` are living lists — extend them
  as new services come up, rather than hardcoding new logic into the scripts.
- Consider running the capture against staging rather than production if the
  site has irreversible actions tied to page navigation (forms, purchases).
