# consent-audit

A Claude Code plugin marketplace hosting **cookie-consent-audit** — a skill that
runs a cookie/tracking consent compliance audit on any website and produces a
client-ready Word report.

Given a URL, it captures live network traffic **plus cookies, localStorage and
sessionStorage** in isolated browser sessions — no consent decision, after
"Accept All", after "Reject All", and **once per individual consent category** —
classifies everything observed, and flags anything that fired or was stored
against the visitor's stated choice.

It is a full-disclosure audit: every tracker, cookie and third-party domain seen
is reported. Services classified as strictly necessary are labelled as such and
kept out of the headline gap count, but are still shown in full with their
firing pattern, so the classification can be reviewed rather than taken on
trust.

## Setup (each team member, once)

Requires [Claude Code](https://claude.com/product/claude-code) installed locally,
plus Node 18+ and Python 3.

```
/plugin marketplace add yomillzee/consent-audit
/plugin install cookie-consent-audit@consent-audit
```

That's it. The skill installs its own npm dependencies and Chromium the first
time you run an audit.

### Auto-install for a whole project (optional)

To have Claude Code offer the plugin automatically to anyone who opens a given
project, commit this to that project's `.claude/settings.json`:

```json
{
  "extraKnownMarketplaces": {
    "consent-audit": {
      "source": { "source": "github", "repo": "yomillzee/consent-audit" }
    }
  },
  "enabledPlugins": {
    "cookie-consent-audit@consent-audit": true
  }
}
```

If the prompt doesn't appear, fall back to the two commands above.

## Using it

Ask Claude Code in plain language:

> Audit cookie consent on https://example.com

Claude runs capture → analyze → report and hands back
`Cookie_Consent_Compliance_Review.docx` along with a plain-English summary.

Useful things to ask for:

- `Audit cookie consent on https://staging.example.com` — prefer staging; the
  capture clicks banner buttons and navigates several pages.
- `...and check /about and /pricing too` — captures extra paths.
- `The banner wasn't detected, the accept button is #cky-btn-accept` — passes
  explicit selectors when auto-detection misses.
- `Skip the per-category tests, just do accept and reject` — faster, since
  per-category testing adds one capture per category.

## What gets reported

| Section | Contents |
| --- | --- |
| Executive summary | Whether any tracker or cookie consent gaps were found |
| Scope of this audit | Requests, trackers, third-party domains and cookies per state |
| Full tracker inventory | Every tracker observed, its firing pattern across all three states, request volume and classification |
| Consent gap analysis | Trackers that fired pre-consent (high) or after reject (medium) |
| Per-category consent testing | One scenario per category: what fired when only that category was granted, which toggles were applied, and any violations |
| Services classified as necessary | Allowlisted services shown with their actual firing pattern, for sign-off |
| Cookies and web storage | Cookies set before consent, cookies surviving reject, and the complete cookie / localStorage / sessionStorage inventory per state |
| All third-party domains | Every non-first-party domain contacted, with unclassified ones flagged |
| Recommendations | Tailored to the findings |
| Methodology | How the capture was performed, and its limitations |

### Why per-category testing matters

Accepting everything and rejecting everything only tests the two extremes. The
common real-world failure sits in between: a visitor allows analytics but
declines advertising, and the site fires the advertising tags anyway because
they were never registered with the consent platform under the right category.

The audit opens the banner's own preferences panel, grants exactly one category,
denies the rest, saves, and re-captures — once per category. A tracker from a
denied category that still fires is an unambiguous violation of a promise the
site made to the visitor.

**A scenario that could not be driven is reported as inconclusive, never as a
pass.** An empty violation list is only meaningful if the toggles demonstrably
applied, so each scenario records which controls it found and what it set them
to, and the report prints that evidence alongside the verdict.

### Why cookies are captured separately from network traffic

HAR files record HTTP traffic only. Most tracking cookies — `_ga`, `_fbp`,
`_hjSessionUser` — are written client-side by JavaScript as **first-party**
cookies, so they never appear in network traffic and can't be identified by
domain. The audit reads them straight from the browser and matches them by
cookie name, which is why `cookie_signatures.json` exists alongside
`trackers.json`. In testing, this surfaced a tracker that made no network
request at all.

## Repo layout

```
.claude-plugin/marketplace.json         marketplace manifest
plugins/cookie-consent-audit/
  .claude-plugin/plugin.json            plugin manifest
  skills/cookie-consent-audit/
    SKILL.md                            the workflow Claude follows
    scripts/
      capture_har.js                    Playwright capture (pre / accept / reject)
      analyze_har.py                    HAR classification + gap analysis
      generate_report.js                .docx report generation
      trackers.json                     URL signatures for network requests
      cookie_signatures.json            cookie-name signatures (first-party cookies)
      tracker_categories.json           service -> consent category mapping
      necessary_allowlist.json          services labelled as expected pre-consent
      smoke_test.sh                     offline end-to-end check
```

## Maintaining the signature lists

`trackers.json` maps a display name to URL substrings:

```json
"Vendor Name": ["vendor.com", "/vendor/collect"]
```

`cookie_signatures.json` maps the same display name to cookie names, where a
trailing `*` matches by prefix:

```json
"Vendor Name": ["_vnd_id", "_vnd_ses*"]
```

`tracker_categories.json` assigns each service to a consent category
(`necessary`, `functional`, `analytics`, `advertising`, `tag_manager`), which is
what per-category testing checks against.

Use the same display name in all three files so network evidence, cookie
evidence and category verdicts line up for one service. No code changes are
needed to add a service — but a service missing a category will fail
`smoke_test.sh`, which checks the lists stay in sync.

Category assignment is a judgment call: check it against the client's own
declared cookie categories rather than assuming. `tag_manager` is treated as
informational rather than a violation, since a container tag loading is not
itself tracking — what it goes on to load is judged on its own.

`necessary_allowlist.json` lists services that are *expected* to run before
consent (CAPTCHA, anti-spam, fraud prevention, payments, the consent banner's
own cookie). Entries there are kept out of the headline gap count but are still
listed in full, with their firing pattern, under "Services Classified as
Necessary". **Whether a service genuinely qualifies as "strictly necessary" is a
legal determination, not a technical one** — treat the allowlist as an
assumption for whoever signs off on the audit to confirm.

When an audit surfaces an unclassified domain or cookie that turns out to be a
real tracker, add it to the signature lists and open a PR so the whole team
benefits.

## Verifying your setup

```bash
bash plugins/cookie-consent-audit/skills/cookie-consent-audit/scripts/smoke_test.sh
```

Runs the analyze → report pipeline against built-in fixtures with known
outcomes, and checks the signature lists haven't drifted out of sync. No network
or browser needed, so it isolates a broken install from a browser/network
problem.

## Why a Claude Code plugin and not a claude.ai skill

The capture step drives a real browser to arbitrary external sites. claude.ai and
Cowork run skills inside a sandboxed container that can't reach arbitrary hosts,
so the capture would fail there regardless of who ran it. Claude Code, running on
a real machine, is the right environment.

## Adding another tool to this marketplace

1. Add a folder under `plugins/`.
2. Give it a `.claude-plugin/plugin.json`.
3. Register it in the root `.claude-plugin/marketplace.json`.
4. Open a PR.

## License

Apache-2.0 — see [LICENSE](LICENSE).
