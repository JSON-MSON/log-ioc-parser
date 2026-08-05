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

- `log_ioc_parser.py` — the original parser script (IP extraction only)
- `log_ioc_output.txt` — validated output run against the frozen snapshot
- `auth_snapshot.log` — the frozen log snapshot used for the final validated run
- `log_ioc_parser_v2.py` — upgraded parser with username capture and structured JSON output (see addendum below)
- `log_ioc_output_table.txt` — v2's human-readable table output
- `log_ioc_output.json` — v2's structured JSON output
- `screenshots/` — see below

## Screenshots

![JSON output validity confirmation](screenshots/json-validation.png)

## What I'd do differently in production

- Never validate a script's output against a live, actively-written log using a command that could itself write matching content back into that log — snapshot first, always.

---

## Addendum: Structured Output + Targeted-Username Capture

### What this adds

The original script only extracted source IPs. This upgrade captures the **targeted username** alongside each IP, and adds an optional **structured JSON output mode** — the difference between a script whose output is only readable by a human, and one whose output could feed directly into another tool.

### The regex change

```python
IP_USER_PATTERN = re.compile(r'Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)')
```
`\S+` — one or more non-whitespace characters — captures the username. Unlike an IP address, a username has no fixed, predictable character pattern to match against directly, so "anything that isn't whitespace" is the right level of generality here.

### Proper CLI argument handling with `argparse`

```python
parser = argparse.ArgumentParser(description="Extract IOCs from an auth.log file")
parser.add_argument("logfile", help="Path to the auth.log file")
parser.add_argument("--json", action="store_true", help="Output as JSON instead of a table")
args = parser.parse_args()
```
Replaces manually checking `sys.argv`'s length from the original script — `argparse` handles `--help` output and invalid-argument errors automatically, and `action="store_true"` makes `--json` a simple on/off flag with no value of its own required.

### Validated as genuinely well-formed, not just visually plausible

```bash
python3 log_ioc_parser_v2.py auth_snapshot.log --json | python3 -m json.tool > /dev/null && echo "VALID JSON"
```
`json.tool` errors loudly on malformed JSON rather than silently accepting it — confirmed `VALID JSON` before treating the output as a real, usable artifact.

### Key finding

Both table and JSON modes were tested against the same frozen snapshot from the original project (rebuilt fresh, since `/tmp` doesn't persist across reboots — a small but real reminder that anything living outside the actual repo needs to be treated as disposable). The two output modes' summary counts match each other exactly, confirming the new JSON path isn't a separate, potentially-diverging code path — it's the same underlying data, just serialized differently depending on whether a human or another program is the intended consumer.

---

## Addendum: Phishing Email Header Analysis

### What this adds

A foundational SOC Level 1 skill with no infrastructure dependency of its own — reading raw email authentication headers to assess whether a message is genuinely from who it claims to be. Same underlying discipline as this repo's log parsing: extracting a reliable signal from unstructured raw text rather than trusting a client's summary of it.

### The header

A real email, own inbox, redacted where personally identifying:

```
ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@action1.com header.s=action1 header.b=kR3Zmv3F; spf=pass (google.com: domain of support=action1.com__...@...bnc.salesforce.com designates 35.85.98.200 as permitted sender) smtp.mailfrom="support=action1.com__...@...bnc.salesforce.com"; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=action1.com

Received: from smtp-....core2.sfdc-lywfpd.mta.salesforce.com (...[35.85.98.200]) by mx.google.com ...
Received-SPF: pass (google.com: ... designates 35.85.98.200 as permitted sender) client-ip=35.85.98.200;
DKIM-Signature: v=1; a=rsa-sha256; d=action1.com; s=action1; ...
Received: from [127.0.0.1] (helo=eaas-10.eaas.emailinfra.svc.cluster.local) by mx1.core2.sfdc-lywfpd.mta.salesforce.com ...

From: Action1 Support <support@action1.com>
```

### Analysis

All three checks pass — but the more interesting finding is *why*, not just that they do. The SPF envelope sender (`Return-Path`/`smtp.mailfrom`) is a long, machine-generated `bnc.salesforce.com` address, not `action1.com` — because this was sent through Salesforce's transactional infrastructure on Action1's behalf (confirmed throughout via the `X-SFDC-*` headers), a standard pattern for companies outsourcing outbound mail to an ESP rather than running their own servers.

That mismatch looks suspicious in isolation, but DMARC doesn't require SPF's domain to align — it accepts alignment through **either** SPF or DKIM. The `DKIM-Signature` shows `d=action1.com`, signed directly by Action1's own domain and matching the visible `From:` exactly. That DKIM alignment is what carries the `dmarc=pass` despite SPF's domain mismatch — a spoofed message impersonating `action1.com` wouldn't have a valid DKIM signature from `action1.com` to fall back on, and would fail both, which Action1's own `p=REJECT` policy is specifically written to catch.

Tracing `Received:` bottom-up confirms a consistent path: Salesforce's internal mail system → Salesforce's outbound MTA → Google, arriving from `35.85.98.200` — the exact IP SPF authorized. No discrepancy between claimed and actual origin at any hop.

### Key finding

A clean pass is only meaningful once you can explain *why* it passed, not just read the verdict. The SPF/DKIM domain divergence here is a textbook third-party-ESP pattern, correctly resolved by DMARC's either/or alignment logic rather than being a red flag — the same reasoning, applied to a message that actually failed these checks, is what would justify quarantine or rejection instead.