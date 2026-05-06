import json
import time
import socket
import ipaddress
from scapy.all import sniff, IP, TCP, UDP
from enforce_firewall import enforce_ip_block
from logger import write_log


# ---------- Dynamic Local IP Detection ----------
def get_local_ip():
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
with open("../config/rules.json", "r") as f:
    rules = json.load(f)

BLOCK_IPS = rules["block_ips"]
BLOCK_PORTS = rules["block_ports"]

# ----------Whitelisted IPs -------
WHITELIST_IPS = set(rules.get("whitelist_ips", []))


# ---------- Threat System ----------
THREAT_SCORE = {}
AUTO_BLOCKED = set()
LAST_ACTIVITY = {}

MAX_SCORE = 20

DECAY_INTERVAL = 10
DECAY_AMOUNT = 1

LAST_DECAY_RUN = 0
DECAY_CHECK_INTERVAL = 3


# ---------- Detection Config ----------
SCAN_PORTS = {}
SCAN_THRESHOLD = 5

DST_TRACKING = {}
DST_THRESHOLD = 6

RATE_TRACKER = {}
RATE_THRESHOLD = 10
TIME_WINDOW = 5

COMMON_SAFE_PORTS = {80, 443, 53}


# ---------- Cooldown ----------
RATE_LAST = {}
SCAN_LAST = {}
HOST_LAST = {}
COOLDOWN = 3


def allow_alert(store, ip):
    now = time.time()
    last = store.get(ip, 0)

    if now - last > COOLDOWN:
        store[ip] = now
        return True
    return False


# ----- Checking Whitelisted IPs --------
def is_whitelisted(ip):
    """
    Support:
    - Single IP whitelist
    - CIDR/network whitelist
    """

    for entry in WHITELIST_IPS:

        # Single IP
        if "/" not in entry:
            if ip == entry:
                return True

        # CIDR / subnet
        else:
            network = ipaddress.ip_network(entry, strict=False)

            if ipaddress.ip_address(ip) in network:
                return True

    return False

# ---------- Threat Scoring ----------
def update_threat_score(src_ip, score):

    new_score = THREAT_SCORE.get(src_ip, 0) + score
    THREAT_SCORE[src_ip] = min(new_score, MAX_SCORE)

    LAST_ACTIVITY[src_ip] = time.time()

    score = THREAT_SCORE[src_ip]

    level = "LOW"
    if score >= 15:
        level = "CRITICAL"
    elif score >= 10:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"

    print(f"[THREAT] {src_ip} Score={score} Level={level}")

    # ---------- IPS ----------
    if level == "HIGH":
        msg = f"[WARNING] High threat detected from {src_ip}"
        print(msg)
        write_log(msg)

    elif level == "CRITICAL" and src_ip not in AUTO_BLOCKED:

        if src_ip == LOCAL_IP:
            print("[SAFEGUARD] Skipping self-block")
            return

        AUTO_BLOCKED.add(src_ip)

        msg = f"[CRITICAL] Blocking {src_ip}"
        print(msg)
        write_log(msg)

        enforce_ip_block(src_ip)


# ---------- Decay Engine ----------
def apply_decay():

    now = time.time()

    for ip in list(THREAT_SCORE.keys()):

        last = LAST_ACTIVITY.get(ip, now)

        if now - last > DECAY_INTERVAL:

            if THREAT_SCORE[ip] > 0:
                THREAT_SCORE[ip] -= DECAY_AMOUNT
                print(f"[DECAY] {ip} Score → {THREAT_SCORE[ip]}")

            if THREAT_SCORE[ip] <= 0:
                print(f"[CLEANUP] Removing {ip}")
                THREAT_SCORE.pop(ip, None)
                LAST_ACTIVITY.pop(ip, None)


# ---------- Rate Detection ----------
def check_rate_limit(src_ip):

    now = time.time()
    RATE_TRACKER.setdefault(src_ip, [])

    RATE_TRACKER[src_ip] = [
        t for t in RATE_TRACKER[src_ip]
        if now - t <= TIME_WINDOW
    ]

    RATE_TRACKER[src_ip].append(now)

    if len(RATE_TRACKER[src_ip]) >= RATE_THRESHOLD:
        if allow_alert(RATE_LAST, src_ip):
            msg = f"[RATE ALERT] High traffic from {src_ip}"
            print(msg)
            write_log(msg)

            update_threat_score(src_ip, 2)


# ---------- Port Scan ----------
def check_port_scan(src_ip, port):

    if port in COMMON_SAFE_PORTS:
        return

    SCAN_PORTS.setdefault(src_ip, set()).add(port)

    if len(SCAN_PORTS[src_ip]) >= SCAN_THRESHOLD:
        if allow_alert(SCAN_LAST, src_ip):
            msg = f"[SCAN ALERT] Port scan from {src_ip}"
            print(msg)
            write_log(msg)

            update_threat_score(src_ip, 3)


# ---------- Host Sweep ----------
def check_host_sweep(src_ip, dst_ip):

    DST_TRACKING.setdefault(src_ip, set()).add(dst_ip)

    if len(DST_TRACKING[src_ip]) >= DST_THRESHOLD:
        if allow_alert(HOST_LAST, src_ip):
            msg = f"[HOST SWEEP ALERT] Recon from {src_ip}"
            print(msg)
            write_log(msg)

            update_threat_score(src_ip, 2)


# ---------- Rule Checks ----------
def check_ip_rule(src_ip):
    return src_ip in BLOCK_IPS


def check_port_rule(port):
    return port in BLOCK_PORTS


# ---------- Packet Engine ----------
def process_packet(packet):

    global LAST_DECAY_RUN

    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Skip trusted traffic early
    if is_whitelisted(src_ip) or is_whitelisted(dst_ip):
        print(f"[WHITELIST] Skipping trusted IP {src_ip} -> {dst_ip}")
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
        check_rate_limit(src_ip)

        if port:
            check_port_scan(src_ip, port)

        check_host_sweep(src_ip, dst_ip)

    # ---------- Firewall ----------
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

    # ---------- Decay ----------
    now = time.time()
    if now - LAST_DECAY_RUN > DECAY_CHECK_INTERVAL:
        apply_decay()
        LAST_DECAY_RUN = now


# ---------- Start ----------
sniff(prn=process_packet)


# ---------- Summary ----------
print("\n--- Summary ---")
print("Scan Tracking:", SCAN_PORTS)
print("Destination Tracking:", DST_TRACKING)
print("Rate Tracking:", {k: len(v) for k, v in RATE_TRACKER.items()})
print("Threat Scores:", THREAT_SCORE)