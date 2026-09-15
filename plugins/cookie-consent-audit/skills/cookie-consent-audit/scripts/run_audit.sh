#!/usr/bin/env bash
# run_audit.sh — one-command cookie consent audit.
#
# Does the whole job: installs what it needs, captures the site in each consent
# state, analyzes the captures, and writes the Word report.
#
#   ./run_audit.sh https://example.com
#   ./run_audit.sh https://example.com "Example Inc"
#   ./run_audit.sh https://example.com "Example Inc" --skip-categories
#   ./run_audit.sh https://example.com "Example Inc" --runs 3
#   ./run_audit.sh https://example.com --discover 10
#   ./run_audit.sh https://example.com --proxy http://eu-exit:8080
#
# Anything after the site name is passed straight to capture_har.js, so
# --paths, --accept-selector, --skip-categories etc. all work.
#
# Requires Node 18+ and Python 3, and REAL internet access — it has to reach the
# site and the tracker domains it calls. It will not work behind a restrictive
# egress proxy (a locked-down CI runner, or a cloud dev container).
set -euo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

URL="${1:-}"
if [ -z "$URL" ]; then
  echo "Usage: $0 <url> [site name] [extra capture_har.js args...]" >&2
  exit 1
fi
shift
case "$URL" in http://*|https://*) ;; *) URL="https://$URL" ;; esac

# A site name is only cosmetic (it titles the report), so derive a sensible one
# rather than making it required.
SITE_NAME="${1:-}"
if [ -n "$SITE_NAME" ] && [ "${SITE_NAME#--}" = "$SITE_NAME" ]; then
  shift
else
  SITE_NAME=""
fi
# --runs is consumed here; every other flag goes straight through to the
# capture. Bash 4.4+ is assumed for the empty-array expansion below.
RUNS=1
CAPTURE_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --runs) RUNS="${2:-}"; shift 2 ;;
    --runs=*) RUNS="${1#--runs=}"; shift ;;
    *) CAPTURE_ARGS+=("$1"); shift ;;
  esac
done
case "$RUNS" in ''|*[!0-9]*) echo "--runs needs a whole number" >&2; exit 1 ;; esac
[ "$RUNS" -ge 1 ] || RUNS=1

DOMAIN="$(printf '%s' "$URL" | sed -E 's#^https?://##; s#/.*##; s#^www\.##')"
[ -n "$SITE_NAME" ] || SITE_NAME="$DOMAIN"

OUTDIR="./audit-${DOMAIN}-$(date +%Y%m%d-%H%M%S)"
REPORT="${SITE_NAME// /_}_Cookie_Consent_Review.docx"

echo "==> Auditing $URL  (report title: $SITE_NAME)"

# Idempotent: a no-op after the first run.
if [ ! -d "$SCRIPTS/node_modules" ]; then
  echo "==> Installing dependencies (first run only)"
  (cd "$SCRIPTS" && npm install --silent)
fi
if [ -z "${CONSENT_AUDIT_CHROMIUM:-}" ]; then
  echo "==> Ensuring Chromium is present (first run only)"
  (cd "$SCRIPTS" && npx --yes playwright install chromium >/dev/null)
fi

# capture_har.js exits non-zero if a state never loaded. Stopping there is the
# point: analyzing a capture that observed nothing produces a report that reads
# like a clean bill of health for a site that was never reached.
capture_failed() {
  echo >&2
  echo "Capture failed — see the errors above. Nothing was analyzed, because a" >&2
  echo "capture that never loaded the site would produce an empty (and therefore" >&2
  echo "falsely clean) report. Common causes:" >&2
  echo "  - no internet access, or an egress proxy blocking the site" >&2
  echo "  - the URL redirects somewhere unexpected, or is wrong" >&2
  echo "  - Chromium failed to start (try: npx playwright install chromium)" >&2
  exit 1
}

if [ "$RUNS" -gt 1 ]; then
  echo "==> Capturing consent states, $RUNS times"
  echo "    A gap seen in any run is real and cannot be unfound by repeating."
  echo "    Repeat runs are worth most on a site that looks clean, where a single"
  echo "    quiet capture is the weakest evidence in the report."
  for i in $(seq 1 "$RUNS"); do
    echo "--> Run $i of $RUNS"
    node "$SCRIPTS/capture_har.js" "$URL" --outdir "$OUTDIR/run-$i" ${CAPTURE_ARGS[@]+"${CAPTURE_ARGS[@]}"} || capture_failed
    # Left on stdout on purpose: an inconclusive run has to stay visible to
    # whatever is reading this log, not be swallowed by the merge.
    python3 "$SCRIPTS/analyze_har.py" "$OUTDIR/run-$i"
  done
  echo "==> Comparing runs"
  python3 "$SCRIPTS/merge_runs.py" "$OUTDIR"
else
  echo "==> Capturing consent states"
  node "$SCRIPTS/capture_har.js" "$URL" --outdir "$OUTDIR" ${CAPTURE_ARGS[@]+"${CAPTURE_ARGS[@]}"} || capture_failed
  echo "==> Analyzing"
  python3 "$SCRIPTS/analyze_har.py" "$OUTDIR"
fi

echo "==> Building report"
node "$SCRIPTS/generate_report.js" "$OUTDIR/findings.json" "$SITE_NAME" "$URL" --out "$REPORT"

echo
echo "Done."
echo "  Report:   $REPORT"
echo "  Raw data: $OUTDIR/findings.json"
