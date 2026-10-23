#!/usr/bin/env python3
"""
Low-and-slow SSH brute-force detector.

Wazuh's built-in brute-force rule fires on ~8 failures within 2 minutes, so an
attacker who spaces out their guesses never triggers it. This script reads the
full auth log and flags any IP with many failures regardless of how far apart
they are, catching the slow attacks a short time-window rule misses.
"""
from datetime import datetime

THRESHOLD = 10            # minimum failures before we alert
SLOW_SPAN_MINUTES = 10    # spread wider than this = stealthy, evades short-window rules

attempts = {}

with open("auth.log") as log_file:
    for line in log_file:
        if "Failed password" in line and "from" in line:
            parts = line.split()
            ip = parts[parts.index("from") + 1]
            timestamp = datetime.fromisoformat(parts[0])
            attempts.setdefault(ip, []).append(timestamp)

print("=== Brute-force hunt ===")
for ip, times in attempts.items():
    count = len(times)
    span_minutes = (max(times) - min(times)).total_seconds() / 60
    if count >= THRESHOLD:
        if span_minutes > SLOW_SPAN_MINUTES:
            print(f"[LOW-AND-SLOW] {ip} - {count} failures over {span_minutes:.0f} min (evades real-time rules)")
        else:
            print(f"[FAST BRUTE FORCE] {ip} - {count} failures in {span_minutes:.1f} min")