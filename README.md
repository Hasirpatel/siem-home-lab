# Home Lab SIEM: Detecting Low-and-Slow Brute-Force Attacks

A Wazuh SIEM home lab plus a Python detector that catches the SSH brute-force
attacks that short time-window rules miss.

**Key result:** I ran a slow brute-force attack (one guess every ~40 seconds)
against a monitored Linux host. It made **38 failed logins over ~46 hours**.
Wazuh's built-in brute-force rule (5712) **never fired**, because it only looks
at ~8 failures within a 2-minute window. My Python detector flagged the attacker
immediately.

```
=== Brute-force hunt ===
[LOW-AND-SLOW] 192.168.149.139 - 38 failures over 2736 min (evades real-time rules)
```

---

## The lab

Four VMs on an isolated VMware NAT network, built in VMware Workstation:

| VM | Role |
|----|------|
| Ubuntu Server 24.04 | Wazuh manager + indexer + dashboard (all-in-one) |
| Ubuntu Server 24.04 | Target, runs the Wazuh agent |
| Kali Linux | Attacker (Hydra) |
| Windows (optional) | Second target |

The target's agent ships its SSH logs to the Wazuh manager, which checks them
against built-in and custom rules.

## What I built

**1. A custom Wazuh rule** (`local_rules.xml`) that raises a level-10 alert on
any failed SSH login to the `root` account, mapped to MITRE ATT&CK **T1110
(Brute Force)**. Validated with `wazuh-logtest` before deploying.

**2. A Python detector** (`detector.py`) that reads the auth log, counts failed
logins per source IP, measures the time span of each IP's attempts, and
classifies them:
- **LOW-AND-SLOW** — many failures spread over a long period (evades real-time
  rules). This is the gap Wazuh misses.
- **FAST BRUTE FORCE** — many failures in a short burst.

## The blind spot it addresses

Wazuh's brute-force correlation rule needs roughly **8 failures within 2
minutes**. An attacker who waits ~40 seconds between guesses stays under that
threshold forever. In my test:

- 38 real attack attempts were made.
- Every one was logged by Wazuh.
- **Wazuh raised no brute-force alert** (rule 5712 returned no results).
- My detector caught it by looking at the full 24-hour+ window instead of a
  2-minute one.

## How to run the detector

```bash
sudo cp /var/log/auth.log .
python3 detector.py
```

Standard library only, Python 3.9+.

## Screenshots

| File | Shows |
|------|-------|
| `01-dashboard.png` | Wazuh dashboard overview |
| `02-agent-events.png` | Target agent sending authentication events |
| `06-logtest.png` | Custom rule 100010 validated in wazuh-logtest |
| `07-custom-rule.png` | Custom rule firing on a real attack |
| `08-slow-failures.png` | Slow-attack failures logged ~40s apart |
| `09-no-bruteforce.png` | Wazuh raised **no** brute-force alert for the slow attack |
| `10-detector.png` | Python detector flagging the low-and-slow attacker |

## What I'd improve next

- **Count collapsed lines:** syslog folds repeated failures into
  `message repeated N times`, so the true attempt count is higher than the line
  count. Parse that N and add it.
- **Password spraying:** detect one IP trying many different usernames.
- **Success-after-failure:** alert when a login succeeds right after a burst of
  failures (possible compromise).
- **GeoIP / reputation** enrichment on flagged IPs.
- Feed detector output back into Wazuh as custom events.

## What I learned

- Deploying and administering a Wazuh SIEM with multi-host agents.
- Writing and testing custom correlation rules mapped to MITRE ATT&CK.
- That a SIEM is only as good as its detection logic — time-window rules have
  real blind spots, and you have to test what a SIEM *misses*, not just what it
  catches.
- Handling messy real-world log data (false matches from a substring filter,
  collapsed duplicate lines, mixed timestamp formats).
