"""Compare existing acceptance summaries to same-route, same-task baseline rows.

Usage: python compare_acceptance.py sources/acceptance_verified_summary.csv
Output: CSV on stdout. Positive change means more hits per eligible canary.
Rows are descriptive comparisons, not paired trials or population estimates.
"""
import argparse
import csv
import sys
from fractions import Fraction


def read_rows(stream):
    reader = csv.DictReader(stream)
    fields = {"config", "task_type", "label", "eligible_canaries",
              "relay_canary_hits", "provider_canary_hits"}
    missing = fields.difference(reader.fieldnames or [])
    if missing:
        raise ValueError(f"missing columns: {sorted(missing)}")
    data = {}
    for row in reader:
        route, sep, gate = row["config"].partition("-")
        key = route, row["task_type"], row["label"], gate
        if not sep or not all(key) or key in data:
            raise ValueError(f"line {reader.line_num}: invalid or duplicate group")
        n, relay, provider = (int(row[f]) for f in
                              ("eligible_canaries", "relay_canary_hits", "provider_canary_hits"))
        if not (0 <= relay <= n and 0 <= provider <= n):
            raise ValueError(f"line {reader.line_num}: invalid canary counts")
        data[key] = n, relay, provider
    if not data:
        raise ValueError("empty input")
    return data


def comparisons(data):
    for (route, task, label, gate), (n, *hits) in data.items():
        if gate == "none":
            continue
        baseline = data.get((route, task, label, "none"))
        for i, recipient in enumerate(("relay", "provider")):
            base_n, base_hits = (baseline[0], baseline[i + 1]) if baseline else ("", "")
            delta = ""
            if n == 0:
                status = "no_eligible_canaries"
            elif baseline is None:
                status = "missing_baseline"
            elif base_n == 0:
                status = "no_eligible_baseline"
            else:
                status = "comparable_group"
                delta = f"{float(100 * (Fraction(hits[i], n) - Fraction(base_hits, base_n))):.2f}"
            yield (route, task, label, gate, recipient, hits[i], n, base_hits, base_n, status, delta)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary")
    args = parser.parse_args()
    try:
        with open(args.summary, encoding="utf-8-sig", newline="") as stream:
            data = read_rows(stream)
    except (ValueError, OSError, csv.Error) as exc:
        parser.exit(2, f"invalid summary: {exc}\n")
    writer = csv.writer(sys.stdout)
    writer.writerow(("route", "task_type", "label", "gate", "recipient", "hits", "eligible",
                     "baseline_hits", "baseline_eligible", "status", "change_percentage_points"))
    writer.writerows(comparisons(data))


if __name__ == "__main__":
    main()
