---
description: Run a cookie/tracking consent compliance audit on a website and produce a client-ready Word report
argument-hint: <url> [site name]
---

Run a cookie consent compliance audit on: **$ARGUMENTS**

Use the `cookie-consent-audit` skill. The first argument is the URL; anything
after it is the client-facing site name for the report title (derive one from
the domain if not given).

The fastest path is the one-command runner, which installs what it needs,
captures, analyzes and writes the report in a single step:

```bash
bash "${CLAUDE_PLUGIN_ROOT}/skills/cookie-consent-audit/scripts/run_audit.sh" <url> "<Site Name>"
```

Add `--paths "/,/about,/contact"` with real pages from the site's navigation —
more pages give better per-page counts. Add `--skip-categories` only if asked;
per-category testing is what catches accepting analytics silently enabling
advertising.

Before reporting anything back, confirm the run is trustworthy:

- The command exited 0. It exits non-zero if a state failed to load.
- The console does **not** print `CAPTURE INCONCLUSIVE` or
  `NO CONSENT BANNER WAS EXERCISED`. If it prints the latter, the banner was
  never clicked and the result proves nothing — find the real Accept/Reject
  selectors in the page and re-run with `--accept-selector` / `--reject-selector`
  before drawing any conclusion.

Then summarize in plain language: the health score, how many technologies fired
before consent, how many persisted after rejection, and which cookies were set
pre-consent. Hand over the `.docx`.

Report honestly. If any part was inconclusive, say it was not tested and why —
never fold it into a clean result. The health score is a rubric for prioritizing
work, not a legal grade, and whether a service is "strictly necessary" is a legal
determination to confirm with the client, not a settled conclusion.
