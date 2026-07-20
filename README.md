# 🔥 FirewallX-Core

A Python-based intelligent firewall system combining:

- Firewall rules
- Intrusion Detection System (IDS)
- Intrusion Prevention System (IPS)
- Threat scoring engine
- Time-based behavior analysis
- Adaptive automated response

---

# 🚀 Project Vision

Build a lightweight, intelligent, and adaptive firewall system that evolves from:

**Rule-based filtering → Behavior-based detection → Automated prevention → Adaptive IPS**

---

# 🧠 System Architecture

## 🔄 Flow Diagram

```text
Packet Arrives
      ↓
IP Check
      ↓
Extract src_ip, dst_ip, protocol, port
      ↓
Whitelist Check
      ↓
Detection Engine
  - Rate Detection
  - Port Scan Detection
  - Host Sweep Detection
      ↓
Threat Scoring Engine
      ↓
Threat Classification
 LOW → MEDIUM → HIGH → CRITICAL
      ↓
Decision Engine (IPS)
      ↓
Firewall Enforcement
      ↓
Quarantine / Permanent Block
      ↓
Logging + Monitoring
```

---

## 🧩 System Pipeline

```text
Capture → Detect → Score → Decide → Act → Recover → Log
```

---

# ⚙️ Features

## 🔐 Firewall
- IP-based blocking
- Port-based blocking
- Config-driven rules
- Windows Firewall integration

---

## 🛡️ IDS (Detection)
- Rate anomaly detection
- Port scan detection
- Host sweep detection
- Retry-aware traffic analysis
- Sliding time-window behavioral analysis

---

## 🚨 IPS (Prevention)
- Automatic blocking at CRITICAL threat level
- Temporary quarantine enforcement
- Automatic unblock after timeout
- Permanent block for repeat offenders

---

## 📊 Threat Intelligence
- Dynamic threat scoring per IP
- Multi-factor threat scoring
- Threat severity classification:
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL

---

## ⏳ Time-Based Intelligence
- Threat score decay
- Inactive attacker cleanup
- Time-based quarantine expiration

---

## ✅ Trust Controls
- Whitelist support
- CIDR/network whitelist support
- Self-protection safeguard
- Trusted traffic bypass

---

# 📂 Project Structure

```text
FirewallX-Core/
│
├── src/
│   ├── firewall_engine.py    # capture, detection, threat scoring, entrypoint
│   ├── enforce_firewall.py   # Windows Firewall (netsh) enforcement
│   ├── logger.py             # file logging
│   └── list_interfaces.py    # helper: list NIC names for settings.json
│
├── config/
│   ├── settings.example.json # template - copy to settings.json
│   ├── settings.json         # your local config (gitignored, not committed)
│   └── rules.json            # static block/whitelist rules
│
├── archive/                  # early Day 1-3 prototype scripts, kept for history
├── logs/                     # runtime log output (gitignored)
├── requirements.txt
└── README.md
```

---

# ⚙️ Configuration

`config/rules.json` — static block/whitelist rules:

```json
{
  "block_ips": [],
  "block_ports": [443],
  "whitelist_ips": [
    "8.8.8.8",
    "1.1.1.1"
  ]
}
```

`config/settings.json` — detection thresholds, quarantine timing, lab networks, and
which NIC to capture on. Copy `config/settings.example.json` to get started (see
Quick Start below); this file is gitignored since it typically contains your own
local network ranges.

---

# ▶️ Quick Start

**Prerequisites:** Windows, Python 3.10+, [Npcap](https://npcap.com/) installed
(required by Scapy for packet capture), and an Administrator terminal (firewall
rule changes require elevation).

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create your local config from the template
copy config\settings.example.json config\settings.json

# 3. Find your network interface name
cd src
py list_interfaces.py

# 4. Put that interface name into config/settings.json -> "network_interface",
#    and set "lab_networks" to the subnet(s) you want to monitor

# 5. Run (as Administrator)
py firewall_engine.py
```

---

# 📖 Reading the Output

Every processed packet prints one line:
`[DIRECTION][ALLOWED|BLOCKED] PROTO src_ip -> dst_ip PORT:n`

Detection alerts layer on top of that:

| Tag | Meaning | Threat score |
|---|---|---|
| `[RATE ALERT]` | One source hit many distinct dest/port combinations quickly | +2 |
| `[SCAN ALERT]` | Many distinct ports seen from one source | +3 |
| `[HOST SWEEP ALERT]` | One source contacted many different destinations | +2 |
| `[PAYLOAD ALERT]` | Packet contents matched a known-bad pattern | +5 |
| `[WARNING]` | Threat score crossed the HIGH threshold | — |
| `[CRITICAL]` / `[QUARANTINE]` | Threat score crossed CRITICAL — IP auto-blocked via Windows Firewall and quarantined | — |
| `[RELEASE]` | Quarantine expired, block rule removed | — |
| `[PERMANENT BLOCK]` | Repeat offender (3rd offense) — blocked with no auto-release | — |

Everything printed to console is also appended to `logs/firewall.log`.

---

# 🧪 Testing & Validation

Tested against a real attacker, not just theory: a Windows 11 host running
FirewallX-Core, and a Kali Linux VM (VirtualBox) acting as attacker, both on
a VirtualBox **Host-Only network** (`192.168.56.0/24` — Windows
`192.168.56.104`, Kali `192.168.56.101`). Three steps tell the whole story —
detect, block, verify, recover:

| # | Scenario | Command (attacker) | Expected result | Config reference | Result |
|---|---|---|---|---|---|
| 1 | Port scan detected | `nmap -Pn -p 1-1000 <target>` | `[RATE ALERT] Diverse high traffic from <attacker>` in the log | `detection.rate_threshold = 10` | ✅ Pass — see below |
| 2 | Auto-block + quarantine | re-run the scan until the threat score crosses 15 | `[WARNING]` → `[CRITICAL]` → `[QUARANTINE]`; a `FirewallX_<attacker-ip>` rule appears in `netsh advfirewall firewall show rule name=all` | `threat_thresholds.critical = 15`, `quarantine.first_offense = 300` | ✅ Pass — see below |
| 3 | Block verified + auto-release | from Kali, confirm traffic now fails (`curl`/ping timing out); wait for quarantine to expire; confirm it succeeds again | Attacker traffic dropped during quarantine; `[RELEASE]` logged and traffic resumes | `quarantine.first_offense = 300` | ✅ Pass — see below |

## Test 1 — Port scan detected

```
$ nmap -Pn -p 1-1000 192.168.56.104
```
```text
2026-07-20 20:06:12 | [RATE ALERT] Diverse high traffic from 192.168.56.101
2026-07-20 20:06:24 | [WARNING] High threat detected from 192.168.56.101
```

**Why `[RATE ALERT]` and not `[SCAN ALERT]` here:** both machines fall inside
`lab_networks`, so the engine classifies this traffic as `LAB`, and the
port-scan detector (`check_port_scan`) only runs on `INBOUND` traffic from a
*non-private* IP — a scan from a same-subnet lab machine is scored by the
rate/diversity detector instead. Same underlying signal (many ports hit
quickly), different code path.

## Test 2 — Auto-block + quarantine (with adaptive escalation, bonus)

Repeating the scan pushed the score past CRITICAL, and the engine created a
real Windows Firewall rule with no manual step:

```text
2026-07-20 20:15:31 | [CRITICAL] Blocking 192.168.56.101 (offense #1)
2026-07-20 20:15:31 | [QUARANTINE] 192.168.56.101 isolated for 300 seconds
```
```
$ netsh advfirewall firewall show rule name="FirewallX_192.168.56.101"
Rule Name:    FirewallX_192.168.56.101
Direction:    Out
RemoteIP:     192.168.56.101/32
Action:       Block
```

Triggering a second offense after release also demonstrated the **adaptive
escalation** policy documented in Day 19 — quarantine duration jumped from
300s to 900s automatically:

```text
2026-07-20 20:24:14 | [CRITICAL] Blocking 192.168.56.101 (offense #2)
2026-07-20 20:24:14 | [QUARANTINE] 192.168.56.101 isolated for 900 seconds
```

## Test 3 — Block verified + auto-release

While quarantined, both sides independently confirmed traffic was actually
dropped (not just logged):

```
# On Kali:
$ curl -v --max-time 5 http://192.168.56.104
*   Trying 192.168.56.104:80...
* Connection timed out after 5003 milliseconds
```
```
# On Windows, at the same moment:
PS> Test-NetConnection -ComputerName 192.168.56.101
PingSucceeded : False
```

And it released itself automatically once the timer expired — no manual
unblock:

```text
2026-07-20 20:21:05 | [RELEASE] Unblocked 192.168.56.101 after quarantine expiry
```
`netsh` confirms the rule was actually removed at that point, not just
logged as removed.

## Lab setup notes (for anyone reproducing this)

Getting the VM traffic visible to the capture took a few real fixes, worth
recording in case you hit the same things:

1. **Wi-Fi-bridged VM didn't work at all.** With the Kali VM's adapter set to
   "Bridged" on the host's Wi-Fi NIC, zero attacker packets ever reached the
   capture — common consumer Wi-Fi APs only relay unicast frames for their
   one associated MAC address, and a bridged VM injects traffic under a
   different (spoofed) MAC. ARP/DHCP broadcasts got through; actual TCP
   scans did not.
2. **Switched to VirtualBox Host-Only networking** instead — a private
   virtual network between host and VM that never touches the Wi-Fi AP.
   More reliable for this kind of local attacker/target testing in general.
3. **IP mismatch after switching:** the Kali VM picked up `192.168.56.101`,
   but Windows' Host-Only adapter was still statically set to an old
   `10.0.2.1` from earlier, unrelated testing — two different subnets on
   the same virtual wire, so nothing could reach anything. Fixed by setting
   the Windows adapter back to the `192.168.56.0/24` range.
4. **Blocking silently failed the first time** even after all of the above —
   detection and scoring worked, but no `netsh` rule appeared. Cause: the
   terminal running `firewall_engine.py` was VS Code's integrated terminal,
   which is **not elevated** even if VS Code itself has admin rights.
   `netsh advfirewall firewall add rule` requires an actual Administrator
   terminal (right-click → "Run as administrator").
5. Threat scores/offender counts live only in memory — restarting the
   engine resets them, so a fresh terminal means re-running the scan to
   build the score back up.

(Other detectors — host sweep, payload matching, permanent-block escalation —
use the same mechanism under the hood; these 3 steps are enough to prove the
pipeline end-to-end without repeating the same demo six times.)

---

# 📅 Development Journey

## ✅ Day 1–10 — Foundation
Built core firewall engine:

- Packet sniffing using Scapy
- IP and port filtering
- Logging system
- Modular code structure
- Basic IDS detection framework

---

## ✅ Day 11 — IPS Introduction
Implemented:

- Threat severity classification
- Automatic blocking logic
- Firewall enforcement integration

FirewallX evolved from IDS → IPS.

---

## ✅ Day 12 — Threat Decay Engine
Implemented:

- Threat score decay
- LAST_ACTIVITY tracking
- Automatic cleanup of inactive attackers
- Detection threshold tuning

Result:
Reduced stale threat accumulation.

---

## ✅ Day 13 — Whitelist System
Implemented:

- Trusted IP whitelist
- Detection bypass for trusted traffic
- Reduced false positives

---

## ✅ Day 14 — CIDR Whitelist Support
Implemented:

- Network/subnet whitelisting
- CIDR support
- Flexible trusted network definitions

Example:

```text
192.168.1.0/24
10.0.0.0/8
```

---

## ✅ Day 15 — Sliding Window IDS
Implemented:

- Sliding time-window behavioral detection
- Recent activity tracking
- Auto-expiration of stale detection entries

Result:
Improved detection accuracy.

---

## ✅ Day 16 — Retry-Aware IDS Logic
Problem:
Normal blocked HTTPS traffic caused repeated application retries.

This created:
- False RATE alerts
- Threat score inflation
- Noise in logs

Fix:
Added retry-aware detection logic.

Result:
Normal retry behavior no longer treated as attacks.

---

## ✅ Day 17 — False Positive Reduction
Implemented:

- Reduced noisy host sweep detection
- Reduced retry spam
- Improved signal quality
- Safer detection thresholds

Result:
Cleaner IDS alerts.

---

## ✅ Day 18 — Automated Response System
Implemented:

- Automatic Windows Firewall blocking
- Temporary quarantine system
- Auto-unblock after timeout
- Duplicate rule prevention
- Self-block prevention

Example:

```text
[THREAT] 130.211.115.4 Score=15 Level=CRITICAL
[CRITICAL] Blocking 130.211.115.4
[QUARANTINE] 130.211.115.4 isolated for 300 seconds
```

Result:
FirewallX became active IPS.

---

## ✅ Day 19 — Adaptive IPS Escalation
Implemented:

- Persistent offender tracking
- Adaptive quarantine durations
- Permanent attacker blacklist
- Dynamic quarantine release
- Permanent offender skip logic

Escalation policy:

```text
1st offense → 300 sec quarantine
2nd offense → 900 sec quarantine
3rd offense → permanent block
```

False positive tuning:

- Ignore local machine outbound browsing traffic
- Ignore safe response ports:
  - 53 (DNS)
  - 80 (HTTP)
  - 443 (HTTPS)
- Improved inbound scan validation

Result:
FirewallX became adaptive IPS.

---

# 📌 Current Status

```text
✔ Firewall
✔ IDS
✔ IPS
✔ Threat Scoring
✔ Threat Decay
✔ Whitelist
✔ CIDR Trust
✔ Automated Quarantine
✔ Adaptive Escalation
✔ Permanent Blocking
✔ False Positive Tuning
✔ Stable
```

---

# 🔄 Future Roadmap

Planned enhancements:

- Persistent attacker reputation storage
- Config-driven detection thresholds
- Dashboard / UI monitoring
- Packet payload inspection
- SIEM / log export integration
- Cross-platform firewall enforcement
- Threat intelligence feed integration

---

# 🧠 Key Learnings

Lessons from building FirewallX:

- Detection without tuning creates false positives
- Real-world traffic is noisy
- Static rules alone are insufficient
- Time-based behavior analysis improves accuracy
- Prevention requires safeguards
- Adaptive response is stronger than fixed response

---

# 🚀 Long-Term Goal

Evolve FirewallX into:

- Production-grade lightweight endpoint firewall
- Real-time monitoring platform
- Intelligent adaptive IPS security agent
