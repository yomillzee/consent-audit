# consent-audit

A Claude Code plugin marketplace hosting **cookie-consent-audit** — a skill that
runs a cookie/tracking consent compliance audit on any website and produces a
client-ready Word report.

Given a URL, it captures live network traffic in three isolated browser sessions
(no consent decision, after "Accept All", after "Reject All"), classifies every
request against a tracker signature list, and flags trackers that fired before
consent or after rejection.

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

## What gets reported

| Section | Contents |
| --- | --- |
| Executive summary | Whether any consent gaps were found |
| Key findings | Request counts and trackers per state (pre / post-reject / post-accept) |
| Consent gap analysis | Trackers that fired pre-consent (high) or after reject (medium) |
| Correctly gated trackers | Trackers that only appeared after Accept |
| Necessary services | Allowlisted services (CAPTCHA, anti-spam, payments) expected pre-consent |
| Recommendations | Tailored to whether gaps were found |
| Methodology | How the capture was performed, and its limitations |

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
      trackers.json                     tracker signature list
      necessary_allowlist.json          services expected to run pre-consent
      smoke_test.sh                     offline end-to-end check
```

## Maintaining the tracker lists

`trackers.json` maps a display name to URL substrings. To add a service, add an
entry — no code changes needed:

```json
"Vendor Name": ["vendor.com", "/vendor/collect"]
```

`necessary_allowlist.json` lists tracker names that are *expected* to run before
consent (CAPTCHA, anti-spam, fraud prevention, payments). Anything listed there
is reported separately instead of being flagged as a compliance gap. Whether a
given service is genuinely "strictly necessary" is a legal judgment call — review
it with whoever signs off on the audit.

When an audit surfaces a domain under `unknown_domains` that turns out to be a
real tracker, add it to `trackers.json` and open a PR so the whole team benefits.

## Verifying your setup

```bash
bash plugins/cookie-consent-audit/skills/cookie-consent-audit/scripts/smoke_test.sh
```

Runs the analyze → report pipeline against built-in fixtures. No network or
browser needed, so it isolates a broken install from a browser/network problem.

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
