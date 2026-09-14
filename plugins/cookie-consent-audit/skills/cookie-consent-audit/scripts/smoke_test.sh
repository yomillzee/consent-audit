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

cp "$SCRIPTS/fixtures/"*.har "$WORK/"

echo "== analyze =="
python3 "$SCRIPTS/analyze_har.py" "$WORK"

python3 - "$WORK/findings.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))["summary"]

gaps = {g["tracker"]: g for g in s["consent_gaps"]}
expected_gaps = {"Google Analytics (GA4/UA)", "Google Tag Manager"}
expected_gated = {"Meta / Facebook Pixel", "Microsoft Clarity"}
expected_necessary = {"reCAPTCHA"}

errors = []
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

if errors:
    print("ANALYZE FAILED:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("analyze output matches expectations")
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
