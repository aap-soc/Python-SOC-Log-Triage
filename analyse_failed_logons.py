#!/usr/bin/env python3
"""
analyse_failed_logons.py
Count Windows failed-logon (Event ID 4625) events per account from a Splunk
CSV export and flag accounts that may be under a brute-force attempt.
A small SOC log-triage helper.

Usage:  python3 analyse_failed_logons.py failed_logons.csv
"""
import csv
import re
import sys
from collections import Counter

# Path to the Splunk CSV export (default: failed_logons.csv in this folder)
path = sys.argv[1] if len(sys.argv) > 1 else "failed_logons.csv"

# Flag any account with more than this many failures
THRESHOLD = 5

counts = Counter()

with open(path, newline="", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)
    for row in reader:
        # Splunk usually extracts an Account_Name field for 4625 events
        account = (row.get("Account_Name") or "").strip()

        # Fallback: parse the account from the raw event text if the column is missing
        if not account:
            raw = row.get("_raw", "")
            names = re.findall(r"Account Name:\s*(\S+)", raw)
            account = names[-1] if names else ""   # last one = the account that failed

        if account and account != "-":
            counts[account] += 1

# Report, most failures first
print("Failed logons (Event ID 4625) per account:\n")
for account, n in counts.most_common():
    flag = "   <-- POSSIBLE BRUTE FORCE" if n > THRESHOLD else ""
    print(f"  {account:<25} {n}{flag}")

print(f"\nTotal failed logons analysed: {sum(counts.values())}")
