#!/usr/bin/env python3
"""
analyze_har.py — Classify network activity and client-side storage across
pre/post-accept/post-reject captures, and flag consent gaps.

This is a FULL-disclosure analysis: every tracker, every third-party domain and
every cookie observed is carried through to the output. The allowlist in
necessary_allowlist.json only changes how an item is LABELLED (so the headline
gap count stays legally meaningful) — it never removes anything from the report.

Usage:
    python analyze_har.py <outdir> [--trackers trackers.json] [--out findings.json]

<outdir> must contain pre.har, postaccept.har, postreject.har
(the same directory produced by capture_har.js). If capture_har.js also wrote
<state>.storage.json files, cookies and localStorage are analyzed too.
"""
import argparse
import json
import os
from collections import defaultdict
from urllib.parse import urlparse

DEFAULT_TRACKERS_PATH = os.path.join(os.path.dirname(__file__), "trackers.json")
DEFAULT_ALLOWLIST_PATH = os.path.join(os.path.dirname(__file__), "necessary_allowlist.json")
DEFAULT_COOKIE_SIGS_PATH = os.path.join(os.path.dirname(__file__), "cookie_signatures.json")
DEFAULT_CATEGORIES_PATH = os.path.join(os.path.dirname(__file__), "tracker_categories.json")

STATES = [("pre", "pre.har"), ("postaccept", "postaccept.har"), ("postreject", "postreject.har")]

# capture-summary.json keys each state by the action the capture performed,
# while the analyzer keys them by HAR stem. Map between the two so a
# navigation failure recorded at capture time is visible to the analysis.
STATE_ACTION = {"pre": "pre", "postaccept": "accept", "postreject": "reject"}

# A container tag loading is not itself tracking, so it is reported but not
# counted as a per-category violation; what it loads is judged on its own.
INFORMATIONAL_CATEGORIES = {"tag_manager"}

# Cookies living longer than this are called out; 13 months is the common
# regulator guidance ceiling, and 6 months is a widely used stricter bar.
LONG_LIVED_DAYS = 180

# Enough of the public suffix list to get first/third-party right for the
# multi-part TLDs that actually show up in client work.
TWO_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "co.nz", "co.za", "co.in", "co.kr", "co.il",
    "com.au", "com.br", "com.mx", "com.sg", "com.hk", "com.tr", "com.cn", "com.tw",
    "net.au", "org.au", "com.ar", "com.co",
}


def registrable_domain(host):
    """Best-effort eTLD+1. Used only to split first-party from third-party."""
    host = (host or "").lower().strip()
    # IP literals and single-label hosts (localhost) have no registrable domain;
    # truncating them would turn 127.0.0.1 into "0.1". Check the IPv6 bracket
    # form before stripping the port, since IPv6 literals contain colons.
    if host.startswith("["):
        return host.split("]")[0] + "]"
    host = host.split(":")[0].strip(".")
    parts = [p for p in host.split(".") if p]
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return host  # IPv4 literal
    if len(parts) < 2:
        return host
    if ".".join(parts[-2:]) in TWO_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def invert_categories(category_map):
    """{'analytics': ['GA4', ...]} -> {'GA4': 'analytics', ...}"""
    out = {}
    for category, services in (category_map or {}).items():
        if category.startswith("_"):
            continue
        for svc in services:
            out[svc] = category
    return out


def discover_category_states(outdir):
    """Find category-<name>.har captures written by capture_har.js."""
    if not os.path.isdir(outdir):
        return []
    found = []
    for fname in sorted(os.listdir(outdir)):
        if fname.startswith("category-") and fname.endswith(".har"):
            found.append((fname[len("category-"):-len(".har")], fname))
    return found


def load_json(path, default):
    if not path or not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def classify(value, trackers):
    """Match a URL or cookie domain against the tracker signature list."""
    for name, patterns in trackers.items():
        for pat in patterns:
            if pat in value:
                return name
    return None


def classify_cookie_name(name, cookie_sigs):
    """Match a cookie by NAME.

    Most analytics and ad platforms deliberately set FIRST-PARTY cookies (_ga,
    _fbp, _hjSessionUser), so matching on cookie domain alone misses the
    majority of real tracking cookies. A trailing '*' matches by prefix.
    """
    low = (name or "").lower()
    for service, patterns in cookie_sigs.items():
        if service.startswith("_"):  # skip _comment and similar metadata keys
            continue
        for pat in patterns:
            pl = pat.lower()
            if pl.endswith("*"):
                if low.startswith(pl[:-1]):
                    return service
            elif low == pl:
                return service
    return None


def analyze_storage(path, trackers, site_domain, cookie_sigs):
    """Cookies and web storage — the part HAR captures structurally cannot see."""
    raw = load_json(path, None)
    if raw is None:
        return {"available": False, "cookies": [], "local_storage": [], "session_storage": []}

    cookies = []
    for c in raw.get("cookies", []):
        domain = (c.get("domain") or "").lstrip(".")
        reg = registrable_domain(domain)
        expires_days = c.get("expires_days")
        cookies.append({
            **c,
            "registrable_domain": reg,
            "third_party": bool(site_domain) and reg != site_domain,
            # Name first: first-party tracking cookies are the common case and
            # only the name identifies them.
            "attributed_to": classify_cookie_name(c.get("name"), cookie_sigs) or classify(domain, trackers),
            "long_lived": expires_days is not None and expires_days > LONG_LIVED_DAYS,
        })

    local_storage = []
    for item in raw.get("local_storage", []):
        host = urlparse(item.get("origin", "")).netloc
        local_storage.append({**item, "third_party": bool(site_domain) and registrable_domain(host) != site_domain})

    return {
        "available": True,
        "cookies": cookies,
        "local_storage": local_storage,
        "session_storage": raw.get("session_storage", []),
        "cookie_count": len(cookies),
        "third_party_cookie_count": sum(1 for c in cookies if c["third_party"]),
        "long_lived_cookie_count": sum(1 for c in cookies if c["long_lived"]),
        "errors": raw.get("errors", []),
    }


def capture_error_for(summary_file, action):
    """The navigation error capture_har.js recorded for a state, if any."""
    return ((summary_file.get("states") or {}).get(action) or {}).get("error")


def state_is_usable(st):
    """Whether a state observed enough to support any conclusion.

    A capture-time navigation error, a missing HAR, or a HAR holding nothing
    but the failed top-level request with no storage snapshot all mean the
    page never loaded. That is "not tested" — it must never be read as
    "nothing fired", which would turn a broken capture into a clean bill of
    health. A failed navigation still leaves one entry in the HAR, so a lone
    request with no storage counts as no observation at all.
    """
    if st.get("capture_error") or st.get("error"):
        return False
    if st.get("requests", 0) <= 1 and not (st.get("storage") or {}).get("available"):
        return False
    return True


def analyze_file(path, trackers, site_domain):
    if not os.path.exists(path):
        return {
            "error": f"missing file: {path}", "requests": 0, "trackers": {},
            "tracker_examples": {}, "tracker_urls": {}, "unknown_domains": [],
            "all_domains": {}, "third_party_domains": {},
        }

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    entries = data.get("log", {}).get("entries", [])

    tracker_hits = defaultdict(list)
    domain_counts = defaultdict(int)
    classified_domains = set()

    for e in entries:
        url = e["request"]["url"]
        domain = urlparse(url).netloc
        domain_counts[domain] += 1
        name = classify(url, trackers)
        if name:
            tracker_hits[name].append(url)
            classified_domains.add(domain)

    # Every unclassified domain is kept. These are the undeclared third parties a
    # full audit exists to surface, so they are never truncated.
    unknown = sorted(
        ({"domain": d, "requests": domain_counts[d],
          "third_party": bool(site_domain) and registrable_domain(d) != site_domain}
         for d in domain_counts if d not in classified_domains),
        key=lambda r: (-r["requests"], r["domain"]),
    )

    third_party = {d: n for d, n in domain_counts.items()
                   if site_domain and registrable_domain(d) != site_domain}

    return {
        "requests": len(entries),
        "trackers": {k: len(v) for k, v in tracker_hits.items()},
        "tracker_examples": {k: v[0] for k, v in tracker_hits.items()},
        "tracker_urls": {k: sorted(set(v)) for k, v in tracker_hits.items()},
        "unknown_domains": unknown,
        "unknown_domain_count": len(unknown),
        "all_domains": dict(sorted(domain_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "third_party_domains": dict(sorted(third_party.items(), key=lambda kv: (-kv[1], kv[0]))),
    }


def build_findings(outdir, trackers, allowlist=None, site_url=None, cookie_sigs=None, category_map=None):
    allowlist = set(allowlist or ())
    cookie_sigs = cookie_sigs or {}
    service_category = invert_categories(category_map)

    summary_file = load_json(os.path.join(outdir, "capture-summary.json"), {})
    if not site_url:
        site_url = summary_file.get("url")
    site_domain = registrable_domain(urlparse(site_url).netloc) if site_url else None

    states = {}
    for state, fname in STATES:
        states[state] = analyze_file(os.path.join(outdir, fname), trackers, site_domain)
        states[state]["storage"] = analyze_storage(
            os.path.join(outdir, f"{state}.storage.json"), trackers, site_domain, cookie_sigs)
        states[state]["capture_error"] = capture_error_for(summary_file, STATE_ACTION[state])
        states[state]["usable"] = state_is_usable(states[state])

    category_states = discover_category_states(outdir)
    for cat, fname in category_states:
        key = f"category:{cat}"
        stem = fname[: -len(".har")]
        states[key] = analyze_file(os.path.join(outdir, fname), trackers, site_domain)
        states[key]["storage"] = analyze_storage(
            os.path.join(outdir, f"{stem}.storage.json"), trackers, site_domain, cookie_sigs)
        states[key]["category_config"] = load_json(os.path.join(outdir, f"{stem}.config.json"), None)
        states[key]["capture_error"] = capture_error_for(summary_file, f"category:{cat}")
        states[key]["usable"] = state_is_usable(states[key])

    all_trackers = set()
    for s in states.values():
        all_trackers.update(s.get("trackers", {}).keys())

    # Every tracker appears in the matrix with its full firing pattern. The
    # allowlist decides the classification, not whether the row exists.
    matrix, gaps, correctly_gated, necessary_active = [], [], [], []
    for t in sorted(all_trackers):
        in_pre = t in states["pre"].get("trackers", {})
        in_reject = t in states["postreject"].get("trackers", {})
        in_accept = t in states["postaccept"].get("trackers", {})
        allowlisted = t in allowlist

        if allowlisted:
            classification = "necessary (expected pre-consent)"
            severity = "review" if (in_pre or in_reject) else "none"
            necessary_active.append(t)
        elif in_pre:
            classification = "GAP - fired before consent"
            severity = "high"
            gaps.append({"tracker": t, "fired_pre_consent": True,
                         "fired_after_reject": in_reject, "severity": "high"})
        elif in_reject:
            classification = "GAP - fired after reject"
            severity = "medium"
            gaps.append({"tracker": t, "fired_pre_consent": False,
                         "fired_after_reject": True, "severity": "medium"})
        elif in_accept:
            classification = "correctly gated"
            severity = "none"
            correctly_gated.append(t)
        else:
            classification = "not observed"
            severity = "none"

        matrix.append({
            "tracker": t,
            "allowlisted_as_necessary": allowlisted,
            "pre_consent": in_pre,
            "post_accept": in_accept,
            "post_reject": in_reject,
            "requests": {k: states[k].get("trackers", {}).get(t, 0) for k, _ in STATES},
            "classification": classification,
            "severity": severity,
            "example_url": next((states[k].get("tracker_examples", {}).get(t)
                                 for k, _ in STATES if states[k].get("tracker_examples", {}).get(t)), None),
        })

    # Cookies present before any consent decision are a finding in their own
    # right, independent of whether a matching network request was seen.
    pre_cookies = states["pre"]["storage"].get("cookies", [])
    reject_cookies = states["postreject"]["storage"].get("cookies", [])
    def is_cookie_gap(c):
        if c["attributed_to"] in allowlist:
            return False  # labelled necessary; still listed in the full cookie tables
        return c["third_party"] or bool(c["attributed_to"])

    cookie_gaps = [c for c in pre_cookies if is_cookie_gap(c)]
    cookie_gaps_after_reject = [c for c in reject_cookies if is_cookie_gap(c)]

    # Union of every non-first-party domain seen in any state.
    all_third_party = defaultdict(lambda: {"pre": 0, "postaccept": 0, "postreject": 0, "tracker": None})
    for key, _ in STATES:
        for d, n in states[key].get("third_party_domains", {}).items():
            all_third_party[d][key] = n
            all_third_party[d]["tracker"] = all_third_party[d]["tracker"] or classify(d, trackers)

    # --- Per-category consent testing -------------------------------------
    # Each scenario granted exactly one category and denied the rest, so any
    # tracker belonging to a denied category that still fired is a violation.
    #
    # A scenario whose toggles could not be driven proves NOTHING: an empty
    # violation list there means "we could not test", never "it passed". Those
    # are marked inconclusive and excluded from the pass/fail tally.
    category_tests = []
    for cat, _ in category_states:
        st = states[f"category:{cat}"]
        cfg = st.get("category_config") or {}
        configured = bool(cfg.get("opened") and cfg.get("saved")
                          and cfg.get("target_applied") and not cfg.get("failures")
                          and st.get("usable"))

        violations, expected, informational, uncategorized = [], [], [], []
        for tracker, count in sorted(st.get("trackers", {}).items()):
            tcat = service_category.get(tracker)
            entry = {"tracker": tracker, "category": tcat or "uncategorized", "requests": count}
            if tracker in allowlist or tcat == "necessary":
                continue
            if tcat is None:
                uncategorized.append(entry)
            elif tcat in INFORMATIONAL_CATEGORIES:
                informational.append(entry)
            elif tcat == cat:
                expected.append(entry)
            else:
                violations.append({**entry, "granted_category": cat, "severity": "high"})

        category_tests.append({
            "scenario": cat,
            "granted": cat,
            "configured": configured,
            "inconclusive_reason": None if configured else (
                st.get("capture_error")
                or (None if st.get("usable") else "the page did not load in this scenario")
                or cfg.get("error")
                or ("; ".join(cfg.get("failures", [])) or None)
                or ("no configuration record was written for this scenario"
                    if not cfg else "preferences panel could not be reliably configured")),
            "requests": st.get("requests", 0),
            "trackers_detected": sorted(st.get("trackers", {})),
            "violations": violations,
            "expected_present": expected,
            "informational": informational,
            "uncategorized": uncategorized,
            "toggles": cfg.get("toggles", []),
            "cookies": st.get("storage", {}).get("cookies", []),
        })

    conclusive = [c for c in category_tests if c["configured"]]
    category_violations = [v for c in conclusive for v in c["violations"]]

    # A state that never loaded observed nothing. Surfacing that here keeps an
    # empty gap list from being presented downstream as a clean result.
    states_inconclusive = [k for k, _ in STATES if not states[k]["usable"]]
    capture_errors = [
        {"state": k,
         "action": STATE_ACTION[k],
         "error": (states[k].get("capture_error") or states[k].get("error")
                   or "no traffic captured and no storage snapshot")}
        for k in states_inconclusive
    ]
    capture_usable = not states_inconclusive

    summary = {
        "site_url": site_url,
        "site_domain": site_domain,
        "capture_usable": capture_usable,
        "states_inconclusive": states_inconclusive,
        "capture_errors": capture_errors,
        # The gap lists below describe only what was actually observed. With an
        # unusable capture they are evidence of nothing, so never report them
        # as a pass while this is false.
        "consent_gaps_authoritative": capture_usable,
        "pre_consent_request_count": states["pre"]["requests"],
        "post_accept_request_count": states["postaccept"]["requests"],
        "post_reject_request_count": states["postreject"]["requests"],
        "trackers_detected_total": sorted(all_trackers),
        "tracker_matrix": matrix,
        "trackers_correctly_gated": sorted(correctly_gated),
        "necessary_services_active": sorted(necessary_active),
        "consent_gaps": gaps,
        "cookie_counts": {k: states[k]["storage"].get("cookie_count", 0) for k, _ in STATES},
        "cookies_pre_consent": pre_cookies,
        "cookie_gaps_pre_consent": cookie_gaps,
        "cookie_gaps_after_reject": cookie_gaps_after_reject,
        "third_party_domains_all_states": dict(sorted(all_third_party.items())),
        "unknown_domain_counts": {k: states[k].get("unknown_domain_count", 0) for k, _ in STATES},
        "storage_captured": states["pre"]["storage"].get("available", False),
        "category_testing_performed": bool(category_tests),
        "category_tests": category_tests,
        "category_violations": category_violations,
        "category_scenarios_inconclusive": [c["scenario"] for c in category_tests if not c["configured"]],
        "tracker_categories": service_category,
    }

    return {"states": states, "summary": summary}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", help="Directory containing pre.har, postaccept.har, postreject.har")
    ap.add_argument("--trackers", default=DEFAULT_TRACKERS_PATH)
    ap.add_argument("--cookie-signatures", default=DEFAULT_COOKIE_SIGS_PATH,
                    help="JSON map of service name -> cookie name patterns (trailing * = prefix match)")
    ap.add_argument("--categories", default=DEFAULT_CATEGORIES_PATH,
                    help="JSON map of consent category -> service names, for per-category testing")
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST_PATH,
                    help="JSON array of tracker names LABELLED as necessary/expected pre-consent. "
                         "Affects labelling only — allowlisted services are still fully reported.")
    ap.add_argument("--site-url", default=None,
                    help="Site URL, for first/third-party classification (default: read from capture-summary.json)")
    ap.add_argument("--out", default=None, help="Output findings.json path (default: <outdir>/findings.json)")
    args = ap.parse_args()

    trackers = load_json(args.trackers, {})
    allowlist = set(load_json(args.allowlist, []))
    cookie_sigs = load_json(args.cookie_signatures, {})
    category_map = load_json(args.categories, {})
    findings = build_findings(args.outdir, trackers, allowlist, args.site_url, cookie_sigs, category_map)
    s = findings["summary"]

    out_path = args.out or os.path.join(args.outdir, "findings.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"Findings written to {out_path}")

    # Lead with this. Everything below describes what was observed, and if the
    # site never loaded then nothing was observed - an empty gap list would
    # otherwise read as a clean audit.
    if not s["capture_usable"]:
        print()
        print("=" * 72)
        print("CAPTURE INCONCLUSIVE - THIS RUN PROVES NOTHING")
        for e in s["capture_errors"]:
            print(f"  - state '{e['state']}' did not load: {e['error']}")
        print()
        print("An empty gap list below means 'not tested', NOT 'no trackers fired'.")
        print("Fix the capture and re-run before reporting any of these results.")
        print("=" * 72)
        print()

    print(f"Trackers detected: {s['trackers_detected_total']}")

    if s["consent_gaps"]:
        print("CONSENT GAPS FOUND:")
        for g in s["consent_gaps"]:
            print(f"  - {g['tracker']}: pre={g['fired_pre_consent']} "
                  f"post_reject={g['fired_after_reject']} severity={g['severity']}")
    elif s["capture_usable"]:
        print("No consent gaps found - all detected trackers were correctly gated behind Accept.")
    else:
        print("No consent gaps listed - because nothing was observed. This is NOT a pass.")

    if s["necessary_services_active"]:
        print(f"Necessary services active (reported, not counted as gaps): {s['necessary_services_active']}")

    if s["storage_captured"]:
        print(f"Cookies set: pre={s['cookie_counts']['pre']} "
              f"accept={s['cookie_counts']['postaccept']} reject={s['cookie_counts']['postreject']}")
        if s["cookie_gaps_pre_consent"]:
            print(f"  {len(s['cookie_gaps_pre_consent'])} tracking/third-party cookie(s) set BEFORE consent:")
            for c in s["cookie_gaps_pre_consent"]:
                label = c["attributed_to"] or c["registrable_domain"]
                life = "session" if c["session_cookie"] else f"{c['expires_days']}d"
                print(f"    - {c['name']} ({label}, {life})")
    else:
        print("No storage capture found - re-run capture_har.js to include cookies/localStorage.")

    print(f"Unclassified domains: pre={s['unknown_domain_counts']['pre']} "
          f"accept={s['unknown_domain_counts']['postaccept']} reject={s['unknown_domain_counts']['postreject']}")

    if s["category_testing_performed"]:
        print("\nPer-category consent testing:")
        for c in s["category_tests"]:
            if not c["configured"]:
                print(f"  - granted '{c['granted']}' only: INCONCLUSIVE "
                      f"({c['inconclusive_reason']}) - not counted as a pass")
                continue
            if c["violations"]:
                print(f"  - granted '{c['granted']}' only: {len(c['violations'])} VIOLATION(S)")
                for v in c["violations"]:
                    print(f"      {v['tracker']} ({v['category']}) fired with {v['requests']} request(s) "
                          f"while '{v['category']}' was denied")
            else:
                print(f"  - granted '{c['granted']}' only: OK, no denied-category trackers fired")
            if c["uncategorized"]:
                print(f"      note: uncategorized service(s) present, manual review: "
                      f"{', '.join(u['tracker'] for u in c['uncategorized'])}")
    else:
        print("\nPer-category consent testing: not performed "
              "(no per-category controls detected, or --skip-categories was used).")


if __name__ == "__main__":
    main()
