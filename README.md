# 🔥 FirewallX-Core

A Python-based intelligent firewall system combining:

* Firewall rules
* Intrusion Detection System (IDS)
* Intrusion Prevention System (IPS)
* Threat scoring engine
* Time-based behavior analysis

---

## 🚀 Project Vision

Build a **lightweight, intelligent, and adaptive firewall system**
that evolves from rule-based filtering → behavior-based security.

---

# 🧠 System Architecture

## 🔄 Flow Diagram

```text
Packet Arrives
      ↓
IP Check
      ↓
Extract src_ip, dst_ip, port
      ↓
Whitelist Check
      ↓
Run Detection Engine
  - Rate Detection
  - Port Scan Detection
  - Host Sweep Detection
      ↓
Threat Scoring
      ↓
Threat Level (LOW → CRITICAL)
      ↓
Decision Engine (IPS)
      ↓
Firewall Enforcement
      ↓
Logging + Output
```

---

## 🧩 System Pipeline

```text
Capture → Detect → Score → Decide → Act → Log
```

---

# ⚙️ Features

## 🔐 Firewall

* Block traffic based on IP and Port
* Config-driven rules

## 🛡️ IDS (Detection)

* Rate anomaly detection
* Port scan detection
* Host sweep detection

## 🚨 IPS (Prevention)

* Auto block at CRITICAL level
* Warning system at HIGH level

## 📊 Threat Scoring

* Dynamic score per IP
* Multi-factor scoring

## ⏳ Time-based Decay

* Score reduces over time
* Prevents stale threats

## ✅ Whitelist System

* Trusted IPs bypass detection
* Reduces false positives

---

# 📂 Project Structure

```text
src/
 ├── firewall_engine.py
 ├── enforce_firewall.py
 ├── logger.py

config/
 └── rules.json
```

---

# ⚙️ Configuration

```json
{
  "block_ips": [],
  "block_ports": [443],
  "whitelist_ips": ["8.8.8.8", "1.1.1.1"]
}
```

---

# ▶️ How to Run

```bash
py firewall_engine.py
```

---

# 📅 Daily Progress Log

## 🟢 Day 1 – Day 10 (Foundation Phase)

* Built basic firewall using Scapy
* Implemented packet sniffing and parsing
* Added IP and port-based blocking
* Created logging system
* Structured project into modules
* Introduced basic detection logic

---

## ✅ Day 11

* Implemented IPS (auto blocking system)
* Added threat levels (LOW → CRITICAL)
* Integrated firewall enforcement

---

## ✅ Day 12

* Implemented time-based threat decay
* Added LAST_ACTIVITY tracking
* Implemented cleanup of inactive IPs
* Tuned detection thresholds
* Reduced false positives
* Stabilized scoring system

---

## ✅ Day 13

* Implemented whitelist system
* Added trusted IP filtering
* Skipped detection for trusted traffic
* Reduced noise from normal traffic
* Improved overall system accuracy

## ✅ Day 14

* Added CIDR/network whitelist support
* Implemented subnet-based trusted traffic filtering
* Added support for both single IPs and IP ranges
* Improved whitelist flexibility for real-world networks
* Validated IPS safeguard against self-blocking


✅ Day 15
Added sliding time-window detection logic
Upgraded host sweep detection to recent-behavior analysis
Upgraded port scan detection to recent-behavior analysis
Added automatic expiration of old tracking entries
Reduced infinite alert spam from long-lived memory
Improved behavioral accuracy of IDS detections
---


## ✅ Day 16 – Retry-Aware IDS Logic

### Problem Identified
The firewall was correctly blocking HTTPS traffic on port 443, but normal application retry behavior created excessive repeated traffic.

This caused:
- False RATE ALERT triggers
- Unnecessary threat score escalation
- Misclassification of normal retry traffic as suspicious activity


### Day 17 – IDS False Positive Reduction
- Removed outbound host sweep detection to avoid flagging normal browsing as reconnaissance
- Added retry cooldown suppression to reduce repeated retry alert spam
- Preserved inbound scan detection and threat scoring
- Improved signal quality for real suspicious traffic


## Day 18 - Automated Response System

FirewallX now supports active automated response, moving beyond passive IDS detection.

### Features Added
- Threat scoring engine
- Threat severity classification
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL
- Automatic Windows Firewall blocking for critical threats
- Temporary quarantine system (300 seconds)
- Automatic unblock after quarantine expiry
- Duplicate firewall rule prevention
- Self-protection safeguard (prevents blocking local machine)
- Threat score decay over time

### Detection Logic
FirewallX evaluates suspicious traffic and increases threat score based on behavior:

- Port scan detection
- Host sweep / reconnaissance detection
- High traffic rate anomalies
- Repeated connection retry detection

Once a source reaches CRITICAL level:

```text
[THREAT] 130.211.115.4 Score=15 Level=CRITICAL
[CRITICAL] Blocking 130.211.115.4
[QUARANTINE] 130.211.115.4 isolated for 300 seconds
```

After quarantine timeout:

```text
[RELEASE 🔓] Block rule removed for 130.211.115.4
[RELEASE] Unblocked 130.211.115.4 after quarantine expiry
```

### Impact
FirewallX now behaves like a lightweight IPS (Intrusion Prevention System), not just a passive IDS.



---

### Improvements Implemented

#### Retry-Aware Rate Detection
Upgraded rate detection logic to distinguish between:

**Normal retry behavior**
- Same destination IP
- Same destination port
- Repeated connection retries

vs

**Suspicious burst behavior**
- Multiple destinations
- Multiple ports
- Diverse traffic patterns

Now repeated retries are classified as:

```text
[RETRY] Repeated traffic <src_ip> -> <dst_ip> PORT:<port>
# 🔄 Upcoming Work

* Whitelist IP ranges (CIDR support)
* Config-based tuning system
* Logging improvements
* Dashboard / visualization

---

# 🧠 Key Learnings

* Detection without tuning causes false positives
* Real systems require balance (not strict rules)
* Behavior + time + trust = effective security

---

# 📌 Current Status

```text
✔ Firewall
✔ IDS
✔ IPS
✔ Decay
✔ Whitelist
✔ Stable
```

---

# 🚀 Future Goal

* Real-time monitoring tool
* Dashboard-based firewall
* Deployable lightweight security system

---
