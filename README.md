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
│   ├── firewall_engine.py
│   ├── enforce_firewall.py
│   └── logger.py
│
├── config/
│   └── rules.json
│
├── logs/
│
└── README.md
```

---

# ⚙️ Configuration

Example `config/rules.json`

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

---

# ▶️ How to Run

```bash
cd src
py firewall_engine.py
```

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
