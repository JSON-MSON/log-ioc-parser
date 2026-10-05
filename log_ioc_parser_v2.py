#!/usr/bin/env python3
"""
log_ioc_parser_v2.py — extracts IPs and targeted usernames behind failed
SSH logins, with optional structured JSON output.
"""
import re
import sys
import json
import argparse
from collections import Counter

IP_USER_PATTERN = re.compile(r'Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)')
THRESHOLD = 5

def parse_log(path):
    counts = Counter()
    events = []
    with open(path) as f:
        for line in f:
            match = IP_USER_PATTERN.search(line)
            if match:
                user, ip = match.group(1), match.group(2)
                counts[ip] += 1
                events.append({"user": user, "ip": ip})
    return counts, events

def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from an auth.log file")
    parser.add_argument("logfile", help="Path to the auth.log file")
    parser.add_argument("--json", action="store_true", help="Output as JSON instead of a table")
    args = parser.parse_args()

    counts, events = parse_log(args.logfile)

    if args.json:
        print(json.dumps({"summary": dict(counts), "events": events}, indent=2))
    else:
        print("IP address        Failed attempts")
        print("-" * 35)
        for ip, count in counts.most_common():
            flag = "  <-- FLAGGED" if count > THRESHOLD else ""
            print(f"{ip:<18} {count}{flag}")

if __name__ == "__main__":
    main()
