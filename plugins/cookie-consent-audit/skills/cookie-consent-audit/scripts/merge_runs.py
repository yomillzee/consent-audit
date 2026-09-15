#!/usr/bin/env python3
"""merge_runs.py — combine several capture runs into one findings file.

A single capture answers "what happened that time". Repeating it and comparing
answers a more useful question: which findings are stable, and which only show
up sometimes.

The evidence is asymmetric, and the whole design follows from that. A tracker
seen firing before consent in ANY run really did fire before consent — repeating
the capture cannot unfind it. A tracker absent from every run is much weaker
evidence: it may simply not have fired during those particular windows. So
repeat runs are worth most on sites that come back clean, which is exactly where
a false negative would be most damaging. An intermittent finding is itself a
finding: a tag that gates correctly only sometimes is broken.

The run with the most consent gaps becomes the base, so derived figures (health
score, deductions, the technology matrix) stay internally consistent with one
another rather than being stitched together across runs. Anything seen in
another run but missing from the base is reported separately rather than
silently dropped.

Usage:
  python3 merge_runs.py <outdir>      # reads <outdir>/run-1/findings.json, ...
"""
import json
import os
import sys
from collections import Counter


def load_runs(outdir):
    runs = []
    for i in range(1, 1000):
        path = os.path.join(outdir, f"run-{i}", "findings.json")
        if not os.path.exists(path):
            break
        with open(path, encoding="utf-8") as fh:
            runs.append((i, json.load(fh)))
    return runs


def cookie_key(c):
    return (c.get("name", ""), c.get("registrable_domain", ""))


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        sys.exit(1)
    outdir = sys.argv[1]

    runs = load_runs(outdir)
    if not runs:
        print(f"No run-N/findings.json files under {outdir}", file=sys.stderr)
        sys.exit(1)
    if len(runs) == 1:
        # Nothing to compare; pass the single run through unchanged so the rest
        # of the pipeline does not need to care how many runs there were.
        with open(os.path.join(outdir, "findings.json"), "w", encoding="utf-8") as fh:
            json.dump(runs[0][1], fh, indent=2)
        print("Only one run present; wrote it through unchanged.")
        return

    total = len(runs)

    # Base: the worst run we saw. Reporting the mildest would understate the
    # site, and averaging would invent a run that never happened.
    base_idx, base = max(runs, key=lambda r: (
        len(r[1]["summary"].get("consent_gaps", [])),
        len(r[1]["summary"].get("trackers_detected_total", [])),
    ))

    gap_counts = Counter()
    tracker_counts = Counter()
    cookie_counts = Counter()
    violation_counts = Counter()
    for _, r in runs:
        s = r["summary"]
        for g in s.get("consent_gaps", []):
            gap_counts[g["tracker"]] += 1
        for t in s.get("trackers_detected_total", []):
            tracker_counts[t] += 1
        for c in s.get("cookie_gaps_pre_consent", []):
            cookie_counts[cookie_key(c)] += 1
        for v in s.get("category_violations", []):
            violation_counts[(v.get("tracker", ""), v.get("scenario", v.get("granted", "")))] += 1

    base_gap_names = {g["tracker"] for g in base["summary"].get("consent_gaps", [])}

    def rows(counter, label):
        return [
            {label: k if isinstance(k, str) else " / ".join(x for x in k if x),
             "seen_in": n, "of": total, "stable": n == total}
            for k, n in sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
        ]

    unstable = sorted(
        {k for k, n in gap_counts.items() if n < total}
        | {(k if isinstance(k, str) else k[0]) for k, n in violation_counts.items() if n < total}
    )

    base["summary"]["multi_run"] = {
        "runs": total,
        "base_run": base_idx,
        "gap_stability": rows(gap_counts, "tracker"),
        "tracker_stability": rows(tracker_counts, "tracker"),
        "cookie_stability": rows(cookie_counts, "cookie"),
        "violation_stability": rows(violation_counts, "violation"),
        # Seen as a gap somewhere, but not in the run being reported. Kept
        # visible: it fired before consent at least once, which is the finding.
        "gaps_only_in_other_runs": sorted(n for n in gap_counts if n not in base_gap_names),
        "unstable": unstable,
    }

    with open(os.path.join(outdir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(base, fh, indent=2)

    print(f"Merged {total} runs (reporting run {base_idx}, the one with the most gaps).")
    for row in rows(gap_counts, "tracker"):
        mark = "stable" if row["stable"] else "INTERMITTENT"
        print(f"  {row['tracker']}: gap in {row['seen_in']}/{total} runs [{mark}]")
    extra = base["summary"]["multi_run"]["gaps_only_in_other_runs"]
    if extra:
        print(f"  Also seen as a gap in other runs but not the reported one: {', '.join(extra)}")
    if unstable:
        print("  Intermittent findings are still findings: a tag that gates correctly")
        print("  only sometimes is broken. They are reported, not averaged away.")


if __name__ == "__main__":
    main()
