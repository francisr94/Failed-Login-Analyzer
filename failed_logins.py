#!/usr/bin/env python3
"""Flag repeated failed logins (Windows Event ID 4625) in a Splunk CSV export."""

import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta

TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
)


def parse_time(value):
    value = value.strip()
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    raise ValueError(f"Unrecognized time format: {value!r}")


def load_events(path, time_field, account_field, source_field):
    events = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        needed = (time_field, account_field, source_field)
        missing = [c for c in needed if c not in (reader.fieldnames or [])]
        if missing:
            sys.exit(f"Missing column(s): {missing}. Found: {reader.fieldnames}")
        for row in reader:
            lines = row[account_field].strip().splitlines()
            account = lines[-1].strip() if lines else ""
            source = row[source_field].strip()
            events.append((parse_time(row[time_field]), account, source))
    return events


def detect(events, window, threshold, include_machine):
    groups = defaultdict(list)
    for when, account, source in events:
        if not include_machine and account.endswith("$"):
            continue
        groups[(account, source)].append(when)

    findings = []
    for (account, source), times in groups.items():
        times.sort()
        start, best, best_start = 0, 0, times[0]
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            if end - start + 1 > best:
                best = end - start + 1
                best_start = times[start]
        if best >= threshold:
            findings.append(
                {
                    "account": account,
                    "source": source,
                    "total": len(times),
                    "max_in_window": best,
                    "window_start": best_start,
                }
            )
    return sorted(findings, key=lambda f: -f["max_in_window"])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("csv_path", help="Splunk CSV export")
    p.add_argument("--threshold", type=int, default=5, help="failures in the window to flag")
    p.add_argument("--window", type=int, default=5, help="window size in minutes")
    p.add_argument("--include-machine-accounts", action="store_true",
                   help="include accounts ending in $ (excluded by default)")
    p.add_argument("--time-field", default="_time")
    p.add_argument("--account-field", default="target_account")
    p.add_argument("--source-field", default="Source_Network_Address")
    args = p.parse_args()

    events = load_events(args.csv_path, args.time_field, args.account_field, args.source_field)
    findings = detect(events, timedelta(minutes=args.window), args.threshold,
                      args.include_machine_accounts)

    print(f"Events read: {len(events)}")
    print(f"Flagged ({args.threshold}+ failures within {args.window} min):\n")
    if not findings:
        print("None.")
        return
    print(f"{'ACCOUNT':<20}{'SOURCE':<18}{'MAX IN WINDOW':<15}{'TOTAL':<8}WINDOW STARTS")
    for f in findings:
        print(f"{f['account']:<20}{f['source']:<18}{f['max_in_window']:<15}"
              f"{f['total']:<8}{f['window_start']}")


if __name__ == "__main__":
    main()
