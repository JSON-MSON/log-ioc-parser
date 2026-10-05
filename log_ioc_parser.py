#!/usr/bin/env python3
"""
log_ioc_parser.py — extracts IP addresses behind failed SSH logins
from an auth.log file, and flags any exceeding a brute-force threshold.
"""
import re
import sys
from collections import Counter

IP_PATTERN = re.compile(r'Failed password.*from (\d+\.\d+\.\d+\.\d+)')
THRESHOLD = 5  # flag any source IP with more failures than this

def parse_log(path):
    counts = Counter()
    with open(path) as f:
        for line in f:
            match = IP_PATTERN.search(line)
            if match:
                counts[match.group(1)] += 1
    return counts

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-auth.log>")
        sys.exit(1)

    counts = parse_log(sys.argv[1])

    print("IP address        Failed attempts")
    print("-" * 35)
    for ip, count in counts.most_common():
        flag = "  <-- FLAGGED" if count > THRESHOLD else ""
        print(f"{ip:<18} {count}{flag}")

if __name__ == "__main__":
    main()
