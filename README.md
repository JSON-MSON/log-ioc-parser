# Python Log-Parsing / IOC Extraction

## What this demonstrates

Security automation using nothing but Python's standard library — parsing unstructured authentication log text into structured, actionable data, and validating that the parser's output is actually correct rather than just plausible-looking.

## Environment

- **Target:** Ubuntu Server VM, using real `/var/log/auth.log` data accumulated from this lab's earlier projects (Hydra brute-force traffic, manual failed-login tests)
- **Language:** Python 3.14, standard library only (`re`, `sys`, `collections.Counter`)

## Process

### 1. Write the parser

```python
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
```

**What the regex is actually doing:** `Failed password.*from (\d+\.\d+\.\d+\.\d+)` matches any line containing "Failed password," followed by anything, followed by "from" and a captured IP address. The parentheses define a **capture group** — the specific part of the match `match.group(1)` extracts, rather than the entire matched line.

### 2. Run it against real data

```bash
sudo python3 log_ioc_parser.py /var/log/auth.log
```

Initial result:
```
IP address        Failed attempts
-----------------------------------
192.168.81.128     192  <-- FLAGGED
192.168.192.1      2
```

Correctly identifies the Kali attacker VM's IP as exceeding the brute-force threshold, from real Hydra traffic generated in an earlier project.

### 3. Validate the count independently — and find a real methodology bug

Cross-checking against a manual count should be straightforward:

```bash
sudo grep -c "Failed password.*from 192.168.81.128" /var/log/auth.log
```

This returned **193** — one more than the script's 192. Re-running both commands back-to-back produced **193 / 194** — the discrepancy wasn't fixed, and the absolute numbers kept climbing between checks.

**Root cause:** `sudo` logs its own invocations to `auth.log`, including the full command line. Since the search command's own text (`Failed password.*from 192.168.81.128`) matches the regex pattern it's searching for, every `sudo grep` check was writing a new line to the log that would itself match the *next* check — a self-referential feedback loop where the act of measuring was actively changing what was being measured.

### 4. Fix the validation methodology — compare against a frozen snapshot

```bash
sudo cp /var/log/auth.log /tmp/auth_snapshot.log
sudo chmod 644 /tmp/auth_snapshot.log
```

Re-validated against the static copy, with no further `sudo` needed on either side (removing any risk of the same self-logging effect recurring):

```bash
python3 log_ioc_parser.py /tmp/auth_snapshot.log
grep -c "Failed password.*from 192.168.81.128" /tmp/auth_snapshot.log
```

Result: **195 / 195** — exact match, confirming the parser was correct the entire time. The discrepancy was never a bug in the script; it was a bug in how the validation itself was being performed.

## Key finding

The parser's logic was right on the first run. What actually needed debugging was the *validation method*, not the code being validated — a live, actively-growing log file being checked against a command that itself writes matching lines back into that same file will never produce a stable comparison, no matter how many times it's re-run. Freezing a snapshot before comparing is the fix, and it's a genuinely reusable lesson for auditing or IOC-extraction work against any live log source, not just this specific script.

## Files in this repo

- `log_ioc_parser.py` — the parser script
- `log_ioc_output.txt` — validated output run against the frozen snapshot
- `auth_snapshot.log` — the frozen log snapshot used for the final validated run

## What I'd do differently in production

- Never validate a script's output against a live, actively-written log using a command that could itself write matching content back into that log — snapshot first, always.
- Extend the IOC extraction beyond source IPs to also capture targeted usernames, which would help distinguish a scattershot brute-force attempt from a more targeted credential-stuffing attempt against a specific known account.
- Output results as structured JSON or CSV rather than a printed table, so the script's output could feed directly into another tool (a SIEM ingestion pipeline, a blocklist generator) rather than only being human-readable.
