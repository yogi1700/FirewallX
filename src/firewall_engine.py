# Full Day 16 FirewallX-Core firewall_engine.py
# Copy-paste ready consolidated implementation

import json
import time
import socket
import ipaddress
from scapy.all import sniff, IP, TCP, UDP
from enforce_firewall import enforce_ip_block
from logger import write_log

# ---------- Dynamic Local IP Detection ----------
def get_local_ip():
    """Detect local machine IP dynamically"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

LOCAL_IP = get_local_ip()
print(f"[INFO] Local IP detected: {LOCAL_IP}")
MONITORED_IPS = {LOCAL_IP}

# ---------- Load Rules ----------
try:
    with open("../config/rules.json", "r") as f:
        rules = json.load(f)
except Exception as e:
    print(f"[ERROR] Failed to load rules.json: {e}")
    rules = {"block_ips": [], "block_ports": [], "whitelist_ips": []}

BLOCK_IPS = rules.get("block_ips", [])
BLOCK_PORTS = rules.get("block_ports", [])
WHITELIST_IPS = set(rules.get("whitelist_ips", []))

# ---------- Threat System ----------
THREAT_SCORE = {}
AUTO_BLOCKED = {}
LAST_ACTIVITY = {}
MAX_SCORE = 20
DECAY_INTERVAL = 10
DECAY_AMOUNT = 1
LAST_DECAY_RUN = 0
DECAY_CHECK_INTERVAL = 3

# ---------- Detection Config ----------
SCAN_PORTS = {}
SCAN_THRESHOLD = 5
PORT_SCAN_WINDOW = 10
DST_TRACKING = {}
DST_THRESHOLD = 6
HOST_SWEEP_WINDOW = 10
RATE_TRACKER = {}
RATE_THRESHOLD = 10
TIME_WINDOW = 5
RETRY_THRESHOLD = 8
COMMON_SAFE_PORTS = {53}

# ---------- Alert Cooldowns ----------
RATE_LAST = {}
SCAN_LAST = {}
HOST_LAST = {}
COOLDOWN = 3

# ---------- Cooldown Helper ----------
def allow_alert(store, ip):
    """Prevent repeated alert spam"""
    now = time.time()
    last = store.get(ip, 0)
    if now - last > COOLDOWN:
        store[ip] = now
        return True
    return False

# ---------- Whitelist Check ----------
def is_whitelisted(ip):
    """Support single IP and CIDR whitelist entries"""
    for entry in WHITELIST_IPS:
        try:
            if "/" not in entry:
                if ip == entry:
                    return True
            else:
                network = ipaddress.ip_network(entry, strict=False)
                if ipaddress.ip_address(ip) in network:
                    return True
        except ValueError:
            continue
    return False

# ---------- Threat Scoring ----------
def update_threat_score(src_ip, score):
    """Update threat score and apply IPS logic"""
    new_score = THREAT_SCORE.get(src_ip, 0) + score
    THREAT_SCORE[src_ip] = min(new_score, MAX_SCORE)
    LAST_ACTIVITY[src_ip] = time.time()
    current = THREAT_SCORE[src_ip]

    level = "LOW"
    if current >= 15:
        level = "CRITICAL"
    elif current >= 10:
        level = "HIGH"
    elif current >= 5:
        level = "MEDIUM"

    print(f"[THREAT] {src_ip} Score={current} Level={level}")

    if level == "HIGH":
        msg = f"[WARNING] High threat detected from {src_ip}"
        print(msg)
        write_log(msg)
    elif level == "CRITICAL":
        if src_ip in AUTO_BLOCKED:
            return
        if src_ip == LOCAL_IP:
            print("[SAFEGUARD] Skipping self-block")
            return
        AUTO_BLOCKED[src_ip] = True
        msg = f"[CRITICAL] Blocking {src_ip}"
        print(msg)
        write_log(msg)
        enforce_ip_block(src_ip)

# ---------- Threat Decay ----------
def apply_decay():
    """Reduce stale threat scores over time"""
    now = time.time()
    for ip in list(THREAT_SCORE.keys()):
        last = LAST_ACTIVITY.get(ip, now)
        if now - last > DECAY_INTERVAL:
            if THREAT_SCORE[ip] > 0:
                THREAT_SCORE[ip] -= DECAY_AMOUNT
                print(f"[DECAY] {ip} Score -> {THREAT_SCORE[ip]}")
            if THREAT_SCORE[ip] <= 0:
                print(f"[CLEANUP] Removing {ip}")
                THREAT_SCORE.pop(ip, None)
                LAST_ACTIVITY.pop(ip, None)
                AUTO_BLOCKED.pop(ip, None)
                RATE_LAST.pop(ip, None)
                SCAN_LAST.pop(ip, None)
                HOST_LAST.pop(ip, None)

# ---------- Retry-aware Rate Detection ----------
def check_rate_limit(src_ip, dst_ip, port):
    """Detect suspicious traffic bursts while ignoring retry storms"""
    now = time.time()
    RATE_TRACKER.setdefault(src_ip, [])

    RATE_TRACKER[src_ip] = [
        (t, d, p)
        for (t, d, p) in RATE_TRACKER[src_ip]
        if now - t <= TIME_WINDOW
    ]

    RATE_TRACKER[src_ip].append((now, dst_ip, port))

    retry_count = sum(
        1
        for (_, d, p) in RATE_TRACKER[src_ip]
        if d == dst_ip and p == port
    )

    if retry_count >= RETRY_THRESHOLD:
        print(f"[RETRY] Repeated traffic {src_ip} -> {dst_ip} PORT:{port}")
        return

    unique_patterns = {
        (d, p)
        for (_, d, p) in RATE_TRACKER[src_ip]
    }

    if len(unique_patterns) >= RATE_THRESHOLD and allow_alert(RATE_LAST, src_ip):
        msg = f"[RATE ALERT] Diverse high traffic from {src_ip}"
        print(msg)
        write_log(msg)
        update_threat_score(src_ip, 2)

# ---------- Port Scan Detection ----------
def check_port_scan(src_ip, port):
    """Detect rapid access to multiple ports"""
    if port in COMMON_SAFE_PORTS:
        return
    now = time.time()
    SCAN_PORTS.setdefault(src_ip, [])
    SCAN_PORTS[src_ip] = [
        (t, p) for (t, p) in SCAN_PORTS[src_ip]
        if now - t <= PORT_SCAN_WINDOW
    ]
    SCAN_PORTS[src_ip].append((now, port))
    unique_ports = {p for (_, p) in SCAN_PORTS[src_ip]}
    if len(unique_ports) >= SCAN_THRESHOLD and allow_alert(SCAN_LAST, src_ip):
        msg = f"[SCAN ALERT] Port scan from {src_ip} ({len(unique_ports)} recent ports)"
        print(msg)
        write_log(msg)
        update_threat_score(src_ip, 3)

# ---------- Host Sweep Detection ----------
def check_host_sweep(src_ip, dst_ip):
    """Detect rapid access to multiple destinations"""
    now = time.time()
    DST_TRACKING.setdefault(src_ip, [])
    DST_TRACKING[src_ip] = [
        (t, d) for (t, d) in DST_TRACKING[src_ip]
        if now - t <= HOST_SWEEP_WINDOW
    ]
    DST_TRACKING[src_ip].append((now, dst_ip))
    unique_dsts = {d for (_, d) in DST_TRACKING[src_ip]}
    if len(unique_dsts) >= DST_THRESHOLD and allow_alert(HOST_LAST, src_ip):
        msg = f"[HOST SWEEP ALERT] Recon from {src_ip} ({len(unique_dsts)} recent destinations)"
        print(msg)
        write_log(msg)
        update_threat_score(src_ip, 2)

# ---------- Rule Checks ----------
def check_ip_rule(src_ip):
    return src_ip in BLOCK_IPS

def check_port_rule(port):
    return port in BLOCK_PORTS

# ---------- Packet Processing Engine ----------
def process_packet(packet):
    global LAST_DECAY_RUN
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    src_white = is_whitelisted(src_ip)
    dst_white = is_whitelisted(dst_ip)
    if src_white or dst_white:
        trusted_ip = src_ip if src_white else dst_ip
        print(f"[WHITELIST] Trusted IP skipped: {trusted_ip}")
        return

    protocol = "OTHER"
    port = ""
    if packet.haslayer(TCP):
        protocol = "TCP"
        port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol = "UDP"
        port = packet[UDP].dport

    if src_ip in MONITORED_IPS:
        check_rate_limit(src_ip, dst_ip, port)
        if port:
            check_port_scan(src_ip, port)
        check_host_sweep(src_ip, dst_ip)

    if check_ip_rule(src_ip):
        msg = f"[BLOCKED:IP] {src_ip} -> {dst_ip}"
        print(msg)
        write_log(msg)
        enforce_ip_block(src_ip)
    elif check_port_rule(port):
        msg = f"[BLOCKED:PORT] {protocol} {src_ip} -> {dst_ip} PORT:{port}"
        print(msg)
        write_log(msg)
    else:
        msg = f"[ALLOWED] {protocol} {src_ip} -> {dst_ip} PORT:{port}"
        print(msg)
        write_log(msg)

    now = time.time()
    if now - LAST_DECAY_RUN > DECAY_CHECK_INTERVAL:
        apply_decay()
        LAST_DECAY_RUN = now

# ---------- Start Packet Capture ----------
sniff(filter="ip", prn=process_packet)

# ---------- Session Summary ----------
print("\n--- Summary ---")
print("Scan Tracking:", {k: len(v) for k, v in SCAN_PORTS.items()})
print("Destination Tracking:", {k: len(v) for k, v in DST_TRACKING.items()})
print(
    "Rate Tracking:",
    {
        k: len({(d, p) for (_, d, p) in v})
        for k, v in RATE_TRACKER.items()
    }
)
print("Threat Scores:", THREAT_SCORE)
