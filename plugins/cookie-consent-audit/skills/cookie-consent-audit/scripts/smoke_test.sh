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
# The headline gap list follows the evidence. GTM is deliberately absent: a tag
# container loading early is how consent defaults get established, so on that
# basis alone it is not a gap. Meta is present because per-category testing
# caught it firing while its own category was denied — which the Accept/Reject
# extremes alone had missed.
expected_gaps = {"Google Analytics (GA4/UA)", "Meta / Facebook Pixel"}
# Network-level gating across the three headline states. Meta belongs here AND
# in the gap list: it passed the extremes and failed the partial-consent case,
# which is exactly why per-category testing exists.
expected_gated = {"Meta / Facebook Pixel", "Microsoft Clarity"}
expected_necessary = {"reCAPTCHA"}

if set(gaps) != expected_gaps:
    errors.append(f"consent_gaps: expected {sorted(expected_gaps)}, got {sorted(gaps)}")
if set(s["trackers_correctly_gated"]) != expected_gated:
    errors.append(f"correctly_gated: expected {sorted(expected_gated)}, got {s['trackers_correctly_gated']}")
if set(s["necessary_services_active"]) != expected_necessary:
    errors.append(f"necessary: expected {sorted(expected_necessary)}, got {s['necessary_services_active']}")
if gaps.get("Google Analytics (GA4/UA)", {}).get("severity") != "high":
    errors.append("expected Google Analytics gap to be high severity")
if "Google Tag Manager" in gaps:
    errors.append("a tag container must not reach the headline gap list for loading early")

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

# --- technology inventory: the client-facing table ---
tech = {r["technology"]: r for r in s["technology_matrix"]}
if set(tech) != set(s["trackers_detected_total"]):
    errors.append("technology_matrix must cover every detected technology")
if any(r["vendor"] == "Unknown" for r in s["technology_matrix"]):
    errors.append(f"every detected service needs a vendors.json entry: "
                  f"{[r['technology'] for r in s['technology_matrix'] if r['vendor'] == 'Unknown']}")

# Per-page attribution: GA4 fires on both fixture pages, Clarity only on one.
ga = tech.get("Google Analytics (GA4/UA)", {})
if ga.get("pages_found") != 2:
    errors.append(f"GA4 should be found on 2 pages, got {ga.get('pages_found')}")
if tech.get("Microsoft Clarity", {}).get("pages_found") != 1:
    errors.append("Clarity should be found on 1 page")

# Consent mode: a denied ping and a granted hit must not read the same.
if ga.get("before_consent") != "Cookieless ping":
    errors.append(f"GA4 pre-consent should be a cookieless ping, got {ga.get('before_consent')!r}")
if ga.get("after_accept") != "Full":
    errors.append(f"GA4 post-accept should be a full hit, got {ga.get('after_accept')!r}")
if ga.get("after_reject") != "Blocked":
    errors.append(f"GA4 post-reject should be blocked, got {ga.get('after_reject')!r}")
# A cookieless ping is surfaced for review, never silently passed or failed.
if ga.get("status") != "amber":
    errors.append(f"a consent-mode ping should be amber for review, got {ga.get('status')!r}")

# Duplicate tag: two GTM container ids on one site.
dupes = {d["tracker"]: d for d in s["duplicate_tags"]}
if "Google Tag Manager" not in dupes:
    errors.append("two GTM container ids must be reported as a duplicate tag")
if sorted(dupes.get("Google Tag Manager", {}).get("ids", [])) != ["GTM-SECOND", "GTM-TEST"]:
    errors.append(f"duplicate ids wrong: {dupes.get('Google Tag Manager', {}).get('ids')}")
gtm = tech.get("Google Tag Manager", {})
if gtm.get("result") != "REVIEW REQUIRED":
    errors.append(f"GTM has a genuine duplicate container, so REVIEW REQUIRED; got {gtm.get('result')!r}")
if "repeated identifier" not in gtm.get("action", "").lower() and "remove the repeated" not in gtm.get("action", "").lower():
    errors.append(f"GTM's action should address the repeated identifier, got {gtm.get('action')!r}")

# Correctly gated trackers stay green with no action.
if tech.get("Meta / Facebook Pixel", {}).get("status") != "green":
    errors.append("a correctly gated tracker must be green")
if tech.get("reCAPTCHA", {}).get("status") != "green":
    errors.append("an allowlisted necessary service must be green")

# --- status bands, and the evidence rules behind them ---
counts = s["result_counts"]
if s["overall_status"] not in ("Healthy", "Minor Issues", "Action Required", "Significant Issues"):
    errors.append(f"unexpected overall_status {s['overall_status']!r}")
if s["overall_status"] == "Healthy":
    errors.append("a capture with known violations must not read Healthy")

by_tech = {f["technology"]: f for f in s["findings"]}

# Storage created before consent is the strongest evidence there is, so it
# must confirm rather than merely flag for review.
ga = by_tech.get("Google Analytics (GA4/UA)", {})
if ga.get("result") != "CONFIRMED GAP":
    errors.append(f"GA4 wrote _ga before consent; expected CONFIRMED GAP, got {ga.get('result')!r}")
if not any("_ga" in e for e in ga.get("evidence", [])):
    errors.append("a confirmed gap must cite the evidence behind it")

# A container loading early is how consent defaults get established. Calling
# that a violation tells a client to break the mechanism being audited.
gtm = by_tech.get("Google Tag Manager", {})
if gtm.get("result") == "CONFIRMED GAP":
    errors.append("a tag container loading before consent must not be a confirmed gap on that basis alone")

# Not recognising a domain says something about the signature list, not the site.
dom = by_tech.get("Unidentified third-party domains", {})
if dom and dom.get("result") != "REVIEW REQUIRED":
    errors.append(f"unidentified domains must be REVIEW REQUIRED, got {dom.get('result')!r}")

# One technology, one finding, however many symptoms it produced.
techs = [f["technology"] for f in s["findings"]]
if len(techs) != len(set(techs)):
    errors.append("each technology must produce exactly one root finding")

# Uncertainty must never be counted as failure.
if counts["confirmed"] != len([f for f in s["findings"] if f["result"] == "CONFIRMED GAP"]):
    errors.append("confirmed count must match the confirmed findings")
if any(f["result"] == "REVIEW REQUIRED" for f in s["findings"]) and s["overall_status"] == "Healthy":
    errors.append("review items must move the status off Healthy")

if errors:
    print("ANALYZE FAILED:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("analyze output matches expectations (network gaps, tracker matrix, cookies, third-party, per-category)")
PY

echo
echo "== failed capture is inconclusive, never a pass =="
# The dangerous case: the site never loaded, so nothing fired anywhere. Without
# an explicit usability check every gap list is empty and the pipeline happily
# reports a clean bill of health for a site it never reached.
FAILED="$WORK/failed"
mkdir -p "$FAILED"
cp "$SCRIPTS/fixtures/failed-capture/"* "$FAILED/"

python3 "$SCRIPTS/analyze_har.py" "$FAILED" > "$WORK/failed.stdout"

python3 - "$FAILED/findings.json" "$WORK/failed.stdout" <<'PY2'
import json, sys
f = json.load(open(sys.argv[1]))
s = f["summary"]
stdout = open(sys.argv[2], encoding="utf-8").read()

errors = []

if s["capture_usable"]:
    errors.append("a capture where every state failed to load must not be marked usable")
if sorted(s["states_inconclusive"]) != ["postaccept", "postreject", "pre"]:
    errors.append(f"all three states must be inconclusive, got {s['states_inconclusive']}")
if len(s["capture_errors"]) != 3:
    errors.append(f"expected 3 capture errors, got {len(s['capture_errors'])}")
if not all(e["error"] for e in s["capture_errors"]):
    errors.append("every capture error must carry a reason")
if not any("ERR_TUNNEL_CONNECTION_FAILED" in e["error"] for e in s["capture_errors"]):
    errors.append("the navigation error from capture-summary.json must be surfaced")
if s["consent_gaps_authoritative"]:
    errors.append("gap findings must not be authoritative when the capture failed")
# A score computed from nothing would be the same false reassurance in a
# friendlier format - a broken capture must yield no number at all.
if s["overall_status"] != "Inconclusive":
    errors.append(f"a failed capture must be graded Inconclusive, got {s['overall_status']!r}")
if "Tracking health" in stdout:
    errors.append("console must not print a health score for a failed capture")

# The empty findings themselves are expected - what must not happen is any of
# them being presented as a clean result.
if s["consent_gaps"]:
    errors.append("a capture that loaded nothing cannot produce gaps")
if s["trackers_detected_total"]:
    errors.append("a capture that loaded nothing cannot detect trackers")

# Per-state usability must be recorded, so a partial failure is attributable.
for st in ("pre", "postaccept", "postreject"):
    if f["states"][st].get("usable"):
        errors.append(f"state {st} must be marked unusable")
    if not f["states"][st].get("capture_error"):
        errors.append(f"state {st} must carry its capture error")

# A human reading the console must not walk away reassured.
if "No consent gaps found" in stdout:
    errors.append("console must not print the clean-result line for a failed capture")
if "CAPTURE INCONCLUSIVE" not in stdout:
    errors.append("console must announce the capture as inconclusive")
if "NOT a pass" not in stdout:
    errors.append("console must say explicitly that this is not a pass")

if errors:
    print("FAILED-CAPTURE HANDLING BROKEN:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("total capture failure reported as inconclusive, not as a clean result")
PY2

# A single bad state is enough to taint the verdict: the states that did load
# are still reported, but the run as a whole is no longer a pass.
PARTIAL="$WORK/partial"
mkdir -p "$PARTIAL"
cp "$SCRIPTS/fixtures/"*.har "$SCRIPTS/fixtures/"*.json "$PARTIAL/"
python3 - "$PARTIAL/capture-summary.json" <<'PY2'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["states"] = {
    "pre": {"action": "pre", "cmpMatch": None},
    "accept": {"action": "accept", "cmpMatch": {"matched": "#cky-btn-accept"}},
    "reject": {"action": "reject", "cmpMatch": {"matched": "#cky-btn-reject"},
               "error": "page.goto: net::ERR_ABORTED at https://site.test/"},
}
json.dump(d, open(p, "w"), indent=2)
PY2

python3 "$SCRIPTS/analyze_har.py" "$PARTIAL" > "$WORK/partial.stdout"

python3 - "$PARTIAL/findings.json" <<'PY2'
import json, sys
f = json.load(open(sys.argv[1]))
s = f["summary"]
errors = []
if s["capture_usable"]:
    errors.append("one failed state must make the whole capture inconclusive")
if s["states_inconclusive"] != ["postreject"]:
    errors.append(f"only postreject should be inconclusive, got {s['states_inconclusive']}")
if not f["states"]["pre"]["usable"] or not f["states"]["postaccept"]["usable"]:
    errors.append("states that loaded fine must stay usable")
# The good states still did their job, so real findings must survive.
if not s["consent_gaps"]:
    errors.append("findings from the states that did load must still be reported")
if errors:
    print("PARTIAL-FAILURE HANDLING BROKEN:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("partial capture failure taints the verdict while keeping real findings")
PY2

echo
echo "== a banner that was never clicked is not a pass =="
# The likeliest real-world false clean: auto-detection misses an unusual CMP,
# so accept/reject are just the pre-consent capture again. All three states
# agree, every gap list is empty, and it reads as perfect gating.
NOBANNER="$WORK/nobanner"
mkdir -p "$NOBANNER"
cp "$SCRIPTS/fixtures/"*.har "$SCRIPTS/fixtures/"*.json "$NOBANNER/"
python3 - "$NOBANNER/capture-summary.json" <<'PY2'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
for action in ("accept", "reject"):
    d["states"][action]["cmpMatch"] = None
json.dump(d, open(p, "w"), indent=2)
PY2

python3 "$SCRIPTS/analyze_har.py" "$NOBANNER" > "$WORK/nobanner.stdout"

python3 - "$NOBANNER/findings.json" "$WORK/nobanner.stdout" <<'PY2'
import json, sys
s = json.load(open(sys.argv[1]))["summary"]
stdout = open(sys.argv[2], encoding="utf-8").read()
errors = []

if s["consent_exercised"]:
    errors.append("a capture where no consent button was clicked must not count as exercised")
if sorted(s["consent_not_exercised_states"]) != ["accept", "reject"]:
    errors.append(f"both decision states should be flagged, got {s['consent_not_exercised_states']}")
if s["consent_gaps_authoritative"]:
    errors.append("findings cannot be authoritative when no consent choice was made")
# The pages loaded fine - this is a different failure from a dead capture.
if not s["capture_usable"]:
    errors.append("pages loaded, so the capture itself is usable; only consent was untested")
# The dangerous output: a confident score off an untested banner.
if s["overall_status"] != "Inconclusive":
    errors.append(f"no grade may be issued when consent was never exercised, got {s['overall_status']!r}")
if "No consent gaps found" in stdout:
    errors.append("console must not print the clean-result line when the banner was never clicked")
if "NO CONSENT BANNER WAS EXERCISED" not in stdout:
    errors.append("console must announce that no consent banner was exercised")
if "NOT a pass" not in stdout:
    errors.append("console must say explicitly that this is not a pass")

if errors:
    print("UNEXERCISED-BANNER HANDLING BROKEN:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("an unexercised consent banner is reported as inconclusive, not as clean gating")
PY2

echo
echo "== legacy tag detection =="
python3 - "$SCRIPTS" <<'PY2'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("ah", sys.argv[1] + "/analyze_har.py")
ah = importlib.util.module_from_spec(spec); spec.loader.exec_module(ah)

cases = [
    ("https://www.google-analytics.com/collect?v=1&tid=UA-12345-1", True, "UA measurement protocol"),
    ("https://www.google-analytics.com/analytics.js", True, "legacy analytics.js library"),
    ("https://www.google-analytics.com/g/collect?v=2&tid=G-TEST", False, "GA4 is current"),
    ("https://www.googletagmanager.com/gtm.js?id=GTM-TEST", False, "GTM is current"),
]
errors = []
for url, expect_legacy, label in cases:
    _, signals = ah.extract_signals(url)
    if ("legacy" in signals) != expect_legacy:
        errors.append(f"{label}: expected legacy={expect_legacy} for {url}")

# Consent mode states must be read off the gcs parameter, not guessed.
for url, expect in [("https://x/g/collect?gcs=G100", "consent_denied"),
                    ("https://x/g/collect?gcs=G111", "consent_granted")]:
    _, signals = ah.extract_signals(url)
    if expect not in signals:
        errors.append(f"expected {expect} from {url}, got {sorted(signals)}")

ids, _ = ah.extract_signals("https://www.googletagmanager.com/gtm.js?id=GTM-TEST")
if ids != {"GTM-TEST"}:
    errors.append(f"container id extraction wrong: {ids}")

if errors:
    print("LEGACY/SIGNAL DETECTION BROKEN:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("legacy UA, consent-mode and tag-id extraction all correct")
PY2

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
vendors = keys(load("vendors.json"))
problems = []
for missing in sorted((trackers | cookies) - vendors):
    problems.append(f"{missing!r} has no vendor/purpose in vendors.json")
for extra in sorted(vendors - trackers - cookies):
    problems.append(f"{extra!r} is in vendors.json but defined in no signature list")
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
echo "== false-positive guards =="
# These cover the two classifications most likely to send an agency after a
# non-problem. Asserted directly against the classifier rather than through a
# fixture capture, because what matters is the rule, not one sample.
python3 - "$SCRIPTS" <<'GUARDS'
import json, os, sys
sys.path.insert(0, sys.argv[1])
import analyze_har as A

fns = json.load(open(os.path.join(sys.argv[1], "cookie_functions.json")))
fail = []

# --- Google identifiers are not interchangeable -------------------------
# googletagmanager.com serves the container, GA4 and Google Ads alike, so an
# ordinary correct install presents three ids on one signature. Calling that a
# duplicate deployment advises removing a tag that is doing its job.
if A.duplicated_id_kinds(["GTM-MGKL2KSJ", "G-C4XR35FVF6", "AW-17997917321"]):
    fail.append("normal GTM + GA4 + Ads install reported as a duplicate deployment")

# ...while real duplication of one kind must still be caught.
if not A.duplicated_id_kinds(["GTM-AAAA", "GTM-BBBB"]):
    fail.append("two GTM containers not reported as duplicate")
if not A.duplicated_id_kinds(["G-AAAA", "G-BBBB", "GTM-X"]):
    fail.append("two GA4 measurement ids not reported as duplicate")

# --- cookies are judged by function, not by whose domain they sit on ----
# __cf_bm is Cloudflare bot management wherever it appears. On a vendor's
# subdomain it reads as that vendor's tracking cookie if judged by domain.
for name in ("__cf_bm", "_GRECAPTCHA", "AWSALB0001", "cf_clearance"):
    if A.classify_cookie_function(name, fns) != "security":
        fail.append(name + " not classified as a security cookie")
for name in ("cookieyes-consent", "OptanonConsent", "cky-action"):
    if A.classify_cookie_function(name, fns) != "consent":
        fail.append(name + " not classified as a consent-record cookie")

# ...and genuine tracking cookies must NOT be excused by this route.
for name in ("_ga", "_fbp", "__hstc", "hubspotutk", "_hjSessionUser", "_clck"):
    if A.classify_cookie_function(name, fns) is not None:
        fail.append(name + " wrongly classified as a non-consent cookie")

if fail:
    for f in fail:
        print("  FAIL:", f)
    sys.exit(1)
print("  Google identifier kinds distinguished; security/consent cookies separated from tracking")
GUARDS

echo "== a capture that observed nothing =="
# The most dangerous shape of all: the page returns 200, the banner is
# "clicked", and nothing whatsoever is observed. A bot challenge or block page
# looks exactly like this, and an empty finding list reads as a clean site.
BLOCKED="$(mktemp -d)"
python3 - "$BLOCKED" <<'BUILD'
import json, os, sys
d = sys.argv[1]
har = {"log": {"entries": [
    {"request": {"url": "https://site.test/"}, "response": {"status": 200}, "_resourceType": "document"}
]}}
storage = {"cookies": [], "local_storage": [], "session_storage": []}
for stem in ("pre", "postaccept", "postreject"):
    json.dump(har, open(os.path.join(d, stem + ".har"), "w"))
    json.dump(storage, open(os.path.join(d, stem + ".storage.json"), "w"))
json.dump({"url": "https://site.test/", "states": {
    "pre": {"action": "pre", "cmpMatch": None},
    "accept": {"action": "accept", "cmpMatch": {"matched": "CookieYes"}},
    "reject": {"action": "reject", "cmpMatch": {"matched": "CookieYes"}},
}}, open(os.path.join(d, "capture-summary.json"), "w"))
BUILD

STDOUT="$(python3 "$SCRIPTS/analyze_har.py" "$BLOCKED" 2>&1)"
python3 - "$BLOCKED/findings.json" "$STDOUT" <<'CHECK'
import json, sys
s = json.load(open(sys.argv[1]))["summary"]
stdout = sys.argv[2]
errors = []

if not s.get("observed_nothing"):
    errors.append("a capture with no trackers, cookies or third parties must be flagged as having observed nothing")
if s["overall_status"] != "Inconclusive":
    errors.append(f"observing nothing must not produce a grade, got {s['overall_status']!r}")
if s["overall_status"] == "Healthy":
    errors.append("a blocked page must never read as a healthy site")
if s["capture_usable"]:
    errors.append("a capture that observed nothing is not usable")
if "NOT A CLEAN RESULT" not in stdout:
    errors.append("the console must say plainly that this is not a clean result")

if errors:
    print("BLOCKED-CAPTURE CHECK FAILED:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("  a page that returns 200 but carries nothing is inconclusive, never Healthy")
CHECK
rm -rf "$BLOCKED"

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
