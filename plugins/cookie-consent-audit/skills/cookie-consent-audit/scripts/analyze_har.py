#!/usr/bin/env python3
"""
analyze_har.py — Classify network activity across pre/post-accept/post-reject
HAR captures against a generic tracker signature list, and flag consent gaps.

Usage:
    python analyze_har.py <outdir> [--trackers trackers.json] [--out findings.json]

<outdir> must contain pre.har, postaccept.har, postreject.har
(the same directory produced by capture_har.js).
"""
import argparse
import json
import os
from collections import defaultdict
from urllib.parse import urlparse

DEFAULT_TRACKERS_PATH = os.path.join(os.path.dirname(__file__), "trackers.json")
DEFAULT_ALLOWLIST_PATH = os.path.join(os.path.dirname(__file__), "necessary_allowlist.json")


def load_trackers(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_allowlist(path):
    if not path or not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return set(json.load(f))


def classify(url, trackers):
    for name, patterns in trackers.items():
        for pat in patterns:
            if pat in url:
                return name
    return None


def analyze_file(path, trackers):
    if not os.path.exists(path):
        return {"error": f"missing file: {path}", "requests": 0, "trackers": {}, "unknown_domains": []}

    data = json.load(open(path, encoding="utf-8"))
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

    unknown_domains = sorted(
        [d for d in domain_counts if d not in classified_domains],
        key=lambda d: -domain_counts[d],
    )

    return {
        "requests": len(entries),
        "trackers": {k: len(v) for k, v in tracker_hits.items()},
        "tracker_examples": {k: v[0] for k, v in tracker_hits.items()},
        "unknown_domains": unknown_domains[:20],  # cap for readability
        "all_domains": dict(domain_counts),
    }


def build_findings(outdir, trackers, allowlist=None):
    allowlist = allowlist or set()
    states = {}
    for state, fname in [("pre", "pre.har"), ("postaccept", "postaccept.har"), ("postreject", "postreject.har")]:
        states[state] = analyze_file(os.path.join(outdir, fname), trackers)

    all_trackers = set()
    for s in states.values():
        all_trackers.update(s.get("trackers", {}).keys())

    # Gap analysis: for each tracker, check whether it fired somewhere it
    # shouldn't have (pre-consent or after rejection). Trackers in the
    # necessary-services allowlist (e.g. anti-spam, security, payments) are
    # EXPECTED to run pre-consent under most consent frameworks, so they're
    # reported separately rather than flagged as compliance gaps.
    gaps = []
    correctly_gated = []
    necessary_active = []
    for t in sorted(all_trackers):
        in_pre = t in states["pre"].get("trackers", {})
        in_reject = t in states["postreject"].get("trackers", {})
        in_accept = t in states["postaccept"].get("trackers", {})

        if t in allowlist:
            if in_pre or in_reject or in_accept:
                necessary_active.append(t)
            continue

        if in_pre or in_reject:
            gaps.append({
                "tracker": t,
                "fired_pre_consent": in_pre,
                "fired_after_reject": in_reject,
                "severity": "high" if in_pre else "medium",
            })
        elif in_accept:
            correctly_gated.append(t)

    summary = {
        "pre_consent_request_count": states["pre"]["requests"],
        "post_accept_request_count": states["postaccept"]["requests"],
        "post_reject_request_count": states["postreject"]["requests"],
        "trackers_detected_total": sorted(all_trackers),
        "trackers_correctly_gated": sorted(correctly_gated),
        "necessary_services_active": sorted(necessary_active),
        "consent_gaps": gaps,
    }

    return {"states": states, "summary": summary}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir", help="Directory containing pre.har, postaccept.har, postreject.har")
    ap.add_argument("--trackers", default=DEFAULT_TRACKERS_PATH)
    ap.add_argument("--allowlist", default=DEFAULT_ALLOWLIST_PATH, help="JSON array of tracker names treated as necessary/expected pre-consent (default: necessary_allowlist.json)")
    ap.add_argument("--out", default=None, help="Output findings.json path (default: <outdir>/findings.json)")
    args = ap.parse_args()

    trackers = load_trackers(args.trackers)
    allowlist = load_allowlist(args.allowlist)
    findings = build_findings(args.outdir, trackers, allowlist)

    out_path = args.out or os.path.join(args.outdir, "findings.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print(f"Findings written to {out_path}")
    print(f"Trackers detected: {findings['summary']['trackers_detected_total']}")
    if findings["summary"]["consent_gaps"]:
        print("CONSENT GAPS FOUND:")
        for g in findings["summary"]["consent_gaps"]:
            print(f"  - {g['tracker']}: pre={g['fired_pre_consent']} post_reject={g['fired_after_reject']} severity={g['severity']}")
    else:
        print("No consent gaps found — all detected trackers were correctly gated behind Accept.")


if __name__ == "__main__":
    main()
