# Python Log-Parsing / IOC Extraction

## What this demonstrates

Security automation using nothing but Python's standard library — parsing unstructured authentication log text into structured, actionable data, and validating that the parser's output is actually correct rather than just plausible-looking. Identifying values are replaced or redacted.

## Environment

- **Target:** Ubuntu Server VM, using real `/var/log/auth.log` data accumulated from this lab's earlier projects (Hydra brute-force traffic, manual failed-login tests)
- **Language:** Python 3, standard library only (`re`, `sys`, `collections.Counter`; v2 adds `json` and `argparse`)

## Key findings

Three things this project established, each backed by evidence in the sections below.

**A stable number is not a correct one.** Two problems lay behind the count, and only the first was caught at the time. A live log checked with a command that writes matching lines into that same log can never give a stable comparison; freezing a snapshot fixed that. The second went unnoticed: both sides of the comparison used a pattern that also matches `sudo`'s own logged command text, so the frozen file kept three false positives instead of removing them. A check that shares the original's blind spot is not independent of it.

**Two output modes should be checked against each other.** The table and JSON modes were run against the same frozen snapshot and their summary counts compared, confirming the JSON output is the same data serialized differently, not a second implementation that could drift.

**A clean authentication pass is only meaningful once you can explain why it passed.** The analyzed message's SPF and DKIM domains differ, the usual pattern when a third-party email service provider (ESP) sends on a company's behalf, and DMARC passes because only one of them needs to align. The same reasoning, applied to a message that fails, is what justifies quarantine or rejection.

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

**What the regex does:** `Failed password.*from (\d+\.\d+\.\d+\.\d+)` matches any line containing "Failed password", then anything, then "from" and an IP address. The parentheses make a **capture group**: `match.group(1)` returns only that part of the match, not the whole line.

### 2. Run it against real data

```bash
sudo python3 log_ioc_parser.py /var/log/auth.log
```

Initial result:
```
IP address        Failed attempts
-----------------------------------
198.51.100.128     192  <-- FLAGGED
203.0.113.1        2
```

The Kali Linux VM's IP is correctly flagged as over the brute-force threshold, from real Hydra traffic generated in an earlier project. The second address, `203.0.113.1`, is this lab's own MacBook Air reaching the target over the hypervisor's NAT network during a package-install window; its two "failures" are a single mistyped username, not an attack.

### 3. Cross-check the count, and find a methodology bug

A manual count should have been a simple cross-check:

```bash
sudo grep -c "Failed password.*from 198.51.100.128" /var/log/auth.log
```

It returned one more than the script. A back-to-back re-run of both commands gave a new pair, each count one higher than before: the counts kept climbing.

**Root cause:** `sudo` logs each invocation to `auth.log`, full command line included. The search command's own text (`Failed password.*from 198.51.100.128`) matches the pattern it searches for, so every `sudo grep` check wrote a new matching line for the *next* check to count. The measurement was changing what it measured.

### 4. Fix the validation methodology — compare against a frozen snapshot

```bash
sudo cp /var/log/auth.log /tmp/auth_snapshot.log
sudo chmod 644 /tmp/auth_snapshot.log
```

Re-validated against the static copy, with no `sudo` on either side, so the self-logging could not recur:

```bash
python3 log_ioc_parser.py /tmp/auth_snapshot.log
grep -c "Failed password.*from 198.51.100.128" /tmp/auth_snapshot.log
```

Result: **195 / 195** — an exact match, which looked like confirmation and was not.

Both sides use the same pattern on the same file, so both count the three logged `sudo` command lines that contain it. Freezing the snapshot stopped the count moving; it did not remove the contamination already inside it. Separating genuine `sshd` failures from logged `sudo` invocations gives the real figure:

```bash
grep "sshd" auth_snapshot.log | grep -c "Failed password.*from 198.51.100.128"        # 192
grep "sudo:.*COMMAND=" auth_snapshot.log | grep -c "Failed password.*from 198.51.100.128"   # 3
```

**192 genuine SSH authentication failures**, plus the three logged search commands. The snapshot committed to this repo reproduces both figures, so the correction is checkable rather than asserted.

## Files in this repo

- `log_ioc_parser.py` — the original parser script (IP extraction only)
- `log_ioc_output.txt` — the original run against the frozen snapshot, showing the inflated 195; kept as the record the correction above refers to
- `auth_snapshot.log` — the frozen log snapshot used for the final validated run
- `log_ioc_parser_v2.py` — upgraded parser with username capture and structured JSON output (see addendum below)
- `log_ioc_output_table.txt` — v2's human-readable table output
- `log_ioc_output.json` — v2's structured JSON output
- `screenshots/` — each image is shown inline in the section that produced it

## What I'd do differently in production

- Never validate against a live log with a command that can write matching lines into it. Snapshot first.
- A snapshot is necessary but not sufficient: match on the originating process (`sshd`), not message text alone, so a search command's logged invocation cannot count as an authentication failure.
- Check the snapshot's own integrity. Two records in this copy are cut off and run into a later entry: the record after the 2026-07-23 power-off message stops after its timestamp and host and runs into a 16:16 entry on 2026-07-24 (nothing is logged between 22:57 on the 23rd and 16:16 on the 24th), and a 22:09 `Connection closed` line on 2026-07-23 stops mid-message and runs into a 22:15 line. Neither affects the failed-password counts, but a parser that assumes one record per line would misread both.

---

## Addendum: Structured Output + Targeted-Username Capture

### What this adds

The original script extracted only source IPs. This version also captures the **targeted username** for each IP and adds an optional **JSON output mode**, so its output can feed another tool rather than only a human reader.

### The regex change

```python
IP_USER_PATTERN = re.compile(r'Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)')
```
`\S+` (one or more non-whitespace characters) captures the username. Unlike an IP address, a username has no fixed format to match, so "anything but whitespace" is general enough.

**A known limitation.** This pattern does not match `Failed password for invalid user <name> from`, because "invalid user" inserts two extra tokens before the username. Against the committed snapshot, that silently drops two failures from `203.0.113.1`, removing that address from the output entirely. The count for the primary attacker (192) is correct, but partly by coincidence: the same strictness that misses "invalid user" lines also excludes the `sudo` command lines that inflated the original v1 comparison. The dropped "invalid user" lines surfaced by comparing v1's output with v2's. A production version would match on the originating process and handle the "invalid user" form explicitly.

### Proper CLI argument handling with `argparse`

```python
parser = argparse.ArgumentParser(description="Extract IOCs from an auth.log file")
parser.add_argument("logfile", help="Path to the auth.log file")
parser.add_argument("--json", action="store_true", help="Output as JSON instead of a table")
args = parser.parse_args()
```
This replaces the original script's manual `sys.argv` length check: `argparse` handles `--help` and invalid arguments automatically, and `action="store_true"` makes `--json` an on/off flag that takes no value.

### Validated as well-formed, not just plausible-looking

```bash
python3 log_ioc_parser_v2.py auth_snapshot.log --json | python3 -m json.tool > /dev/null && echo "VALID JSON"
```
`json.tool` exits with an error on malformed JSON instead of accepting it; the check printed `VALID JSON` before the output was treated as usable.

![JSON output validity confirmation](screenshots/json-validation.png)

## Addendum: Email Authentication Header Analysis

### What this adds

Reading raw email authentication headers to judge whether a message really comes from its claimed sender: a core SOC Level 1 skill that needs no lab infrastructure. It is the same discipline as the log parsing above, getting a reliable signal from raw text instead of trusting a client's summary.

### The headers

A real email from my own inbox; an excerpt of its headers:

```
ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@action1.com header.s=action1; spf=pass (google.com: domain of support=action1.com__...@...bnc.salesforce.com designates 35.85.98.200 as permitted sender) smtp.mailfrom="support=action1.com__...@...bnc.salesforce.com"; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=action1.com

Received: from <Salesforce outbound MTA> (...[35.85.98.200]) by mx.google.com ...
Received-SPF: pass (google.com: ... designates 35.85.98.200 as permitted sender) client-ip=35.85.98.200;
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=action1.com; s=action1; ...
Received: from [127.0.0.1] (helo=<Salesforce internal mail node>) by <Salesforce outbound MTA> ...

From: Action1 Support <support@action1.com>

X-SFDC-Domain-Auth-Status: Active
X-SFDC-ORGTYPE: ACTIVE
X-SFDC-App: coreapp
X-SFDC-EmailCategory: apiSingleMailViaApex
X-SFDC-Interface: internal
```

### Analysis

All three checks pass; the more useful finding is *why*. The SPF envelope sender (`smtp.mailfrom`) is a long, machine-generated `bnc.salesforce.com` address, not `action1.com`, because Salesforce's transactional infrastructure sent the message on Action1's behalf, as the `X-SFDC-*` headers show. This is the standard pattern for a company that outsources outbound mail to an ESP rather than running its own servers.

The mismatch looks suspicious in isolation, but DMARC does not require SPF's domain to align; alignment through **either** SPF or DKIM is enough ([RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html), the current DMARC specification). The `DKIM-Signature` carries `d=action1.com`, Action1's own domain, which matches the visible `From:` exactly. That alignment carries the `dmarc=pass`. A message spoofing `action1.com` would have no valid `action1.com` DKIM signature to fall back on and would fail both alignment checks — the case Action1's `p=REJECT` policy exists to catch.

Read bottom-up, the `Received:` headers show a consistent path — Salesforce's internal mail node → Salesforce's outbound MTA → Google — arriving from `35.85.98.200`, the exact IP SPF authorized. Claimed and actual origin agree at every hop.

