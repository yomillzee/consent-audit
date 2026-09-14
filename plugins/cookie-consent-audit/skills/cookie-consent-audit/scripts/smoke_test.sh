#!/usr/bin/env bash
# smoke_test.sh — verify the analyze -> report pipeline works, offline.
#
# Runs analyze_har.py and generate_report.js against checked-in fixture HARs
# whose expected outcome is known, so a failure here means a broken install
# rather than a browser or network problem.
#
# Usage: bash smoke_test.sh
set -euo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp "$SCRIPTS/fixtures/"*.har "$SCRIPTS/fixtures/"*.json "$WORK/"

echo "== analyze =="
python3 "$SCRIPTS/analyze_har.py" "$WORK"

python3 - "$WORK/findings.json" <<'PY'
import json, sys
f = json.load(open(sys.argv[1]))
s = f["summary"]

errors = []

# --- network-level gap analysis ---
gaps = {g["tracker"]: g for g in s["consent_gaps"]}
expected_gaps = {"Google Analytics (GA4/UA)", "Google Tag Manager"}
expected_gated = {"Meta / Facebook Pixel", "Microsoft Clarity"}
expected_necessary = {"reCAPTCHA"}

if set(gaps) != expected_gaps:
    errors.append(f"consent_gaps: expected {sorted(expected_gaps)}, got {sorted(gaps)}")
if set(s["trackers_correctly_gated"]) != expected_gated:
    errors.append(f"correctly_gated: expected {sorted(expected_gated)}, got {s['trackers_correctly_gated']}")
if set(s["necessary_services_active"]) != expected_necessary:
    errors.append(f"necessary: expected {sorted(expected_necessary)}, got {s['necessary_services_active']}")
# GTM fires pre-consent AND after reject; GA4 only pre-consent.
if gaps.get("Google Tag Manager", {}).get("fired_after_reject") is not True:
    errors.append("expected Google Tag Manager to be flagged as firing after reject")
if gaps.get("Google Analytics (GA4/UA)", {}).get("severity") != "high":
    errors.append("expected Google Analytics gap to be high severity")

# --- full disclosure: nothing observed may be dropped from the matrix ---
matrix = {m["tracker"]: m for m in s["tracker_matrix"]}
if set(matrix) != set(s["trackers_detected_total"]):
    errors.append("tracker_matrix must contain every detected tracker")
if not matrix.get("reCAPTCHA", {}).get("allowlisted_as_necessary"):
    errors.append("allowlisted services must still appear in the matrix, labelled necessary")

# --- cookies: first-party, JS-set tracking cookies must be caught by NAME ---
if not s["storage_captured"]:
    errors.append("storage fixtures were not picked up")
cookie_gaps = {c["name"]: c for c in s["cookie_gaps_pre_consent"]}
if "_ga" not in cookie_gaps:
    errors.append("_ga (first-party, JS-set) must be flagged as a pre-consent cookie")
if cookie_gaps.get("_ga", {}).get("attributed_to") != "Google Analytics (GA4/UA)":
    errors.append("_ga must be attributed to Google Analytics by cookie name")
# Hotjar has no network request anywhere in the fixtures - cookie-only detection.
if "_hjSessionUser" not in cookie_gaps:
    errors.append("_hjSessionUser must be detected from the cookie alone (no Hotjar request exists)")
if "Hotjar" in s["trackers_detected_total"]:
    errors.append("fixture drift: Hotjar should NOT be detectable from network traffic")
# Allowlisted and genuinely-first-party cookies must not be flagged as gaps.
if "_GRECAPTCHA" in cookie_gaps:
    errors.append("_GRECAPTCHA is allowlisted and must not be a cookie gap")
if "sessionid" in cookie_gaps:
    errors.append("unattributed first-party cookie must not be a cookie gap")
# ...but they must still be listed in the full per-state cookie table.
all_pre = {c["name"] for c in f["states"]["pre"]["storage"]["cookies"]}
if not {"_ga", "_GRECAPTCHA", "sessionid"} <= all_pre:
    errors.append(f"full pre-consent cookie list must include everything observed, got {sorted(all_pre)}")
if not cookie_gaps.get("_ga", {}).get("long_lived"):
    errors.append("_ga (400d) must be marked long_lived")
# Third-party detection off the site domain in capture-summary.json.
tp = [c for c in f["states"]["postaccept"]["storage"]["cookies"] if c["third_party"]]
if {c["name"] for c in tp} != {"third_party_id"}:
    errors.append(f"third-party cookie detection wrong: {[c['name'] for c in tp]}")

# --- per-category consent testing ---
tests = {c["scenario"]: c for c in s["category_tests"]}
if set(tests) != {"analytics", "advertising", "functional"}:
    errors.append(f"expected 3 category scenarios, got {sorted(tests)}")

# analytics granted: Meta Pixel (advertising) leaks through -> 1 violation.
an = tests.get("analytics", {})
if not an.get("configured"):
    errors.append("analytics scenario should be configured")
if [v["tracker"] for v in an.get("violations", [])] != ["Meta / Facebook Pixel"]:
    errors.append(f"analytics violations wrong: {[v['tracker'] for v in an.get('violations', [])]}")
if [e["tracker"] for e in an.get("expected_present", [])] != ["Google Analytics (GA4/UA)"]:
    errors.append("GA should be expected_present when analytics is granted")
# GTM is informational, reCAPTCHA is necessary: neither is a violation.
if any(v["tracker"] in ("Google Tag Manager", "reCAPTCHA") for v in an.get("violations", [])):
    errors.append("tag manager / necessary services must not count as category violations")
if [i["tracker"] for i in an.get("informational", [])] != ["Google Tag Manager"]:
    errors.append("GTM should be reported as informational")

# advertising granted: Meta Pixel is in the granted category -> clean pass.
ad = tests.get("advertising", {})
if not ad.get("configured") or ad.get("violations"):
    errors.append(f"advertising scenario should pass cleanly, got {ad.get('violations')}")

# THE CRITICAL CASE: nothing fired, but the panel could not be saved. Zero
# violations here must read as inconclusive, never as a pass.
fn = tests.get("functional", {})
if fn.get("configured"):
    errors.append("functional scenario must be inconclusive (save button was not found)")
if fn.get("violations"):
    errors.append("inconclusive scenario should not report violations")
if not fn.get("inconclusive_reason"):
    errors.append("inconclusive scenario must carry a reason")
if "functional" not in s["category_scenarios_inconclusive"]:
    errors.append("functional must be listed as inconclusive")
# Inconclusive violations must never reach the headline tally.
if any(v.get("granted_category") == "functional" for v in s["category_violations"]):
    errors.append("inconclusive scenarios must be excluded from category_violations")
if len(s["category_violations"]) != 1:
    errors.append(f"expected exactly 1 counted category violation, got {len(s['category_violations'])}")

if errors:
    print("ANALYZE FAILED:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("analyze output matches expectations (network gaps, tracker matrix, cookies, third-party, per-category)")
PY

echo
echo "== signature list coverage =="
python3 - "$SCRIPTS" <<'PY'
import json, os, sys
d = sys.argv[1]
load = lambda n: json.load(open(os.path.join(d, n), encoding="utf-8"))
keys = lambda m: {k for k in m if not k.startswith("_")}
trackers, cookies = keys(load("trackers.json")), keys(load("cookie_signatures.json"))
cats = load("tracker_categories.json")
mapped = {s for k, v in cats.items() if not k.startswith("_") for s in v}
allow = set(load("necessary_allowlist.json"))
problems = []
for missing in sorted((trackers | cookies) - mapped):
    problems.append(f"{missing!r} has no category in tracker_categories.json")
for extra in sorted(mapped - trackers - cookies):
    problems.append(f"{extra!r} is categorized but defined in no signature list")
for a in sorted(allow - mapped):
    problems.append(f"{a!r} is allowlisted but has no category")
if problems:
    print("SIGNATURE LISTS OUT OF SYNC:")
    for p in problems:
        print("  -", p)
    sys.exit(1)
print(f"{len(trackers | cookies)} services, all categorized and consistent")
PY

echo
echo "== report =="
if [ ! -d "$SCRIPTS/node_modules" ]; then
  echo "node_modules missing — run: (cd \"$SCRIPTS\" && npm install)" >&2
  echo "SKIPPED report generation (analyze passed)."
  exit 0
fi

node "$SCRIPTS/generate_report.js" "$WORK/findings.json" "Smoke Test Site" "https://site.test" \
  --out "$WORK/report.docx"

if [ ! -s "$WORK/report.docx" ]; then
  echo "REPORT FAILED: no .docx produced" >&2
  exit 1
fi
echo "report.docx generated ($(wc -c < "$WORK/report.docx") bytes)"

echo
echo "Smoke test passed."
