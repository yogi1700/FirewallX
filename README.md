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

---

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
