import json
import sys
import time
import socket
import subprocess
import threading
import ipaddress
from pathlib import Path

from scapy.all import sniff, IP, TCP, UDP, Raw

from enforce_firewall import enforce_ip_block, remove_ip_block
from logger import write_log

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)

# ---------------- PROJECT PATHS ----------------

BASE_DIR = Path(__file__).resolve().parent.parent

CONFIG_DIR = BASE_DIR / "config"
LOG_DIR = BASE_DIR / "logs"

SETTINGS_FILE = CONFIG_DIR / "settings.json"
RULES_FILE = CONFIG_DIR / "rules.json"

REQUIRED_SETTINGS_KEYS = [
    "lab_networks",
    "safe_ports",
    "threat_thresholds",
    "quarantine",
    "max_threat_score",
    "cooldown_seconds",
    "payload_patterns",
    "detection"
]


# ---------------- LOCAL IP ----------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


# ---------------- HELPERS ----------------
def allow_alert(store, key):
    now = time.time()
    last = store.get(key, 0)

    if now - last > COOLDOWN:
        store[key] = now
        return True

    return False


def is_whitelisted(ip):
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


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_lab_ip(ip):
    for network in LAB_NETWORKS:
        if ip.startswith(network):
            return True

    return False


def get_packet_direction(src_ip, dst_ip):

    if is_lab_ip(src_ip) and is_lab_ip(dst_ip):
        return "LAB"

    if src_ip == LOCAL_IP:
        return "OUTBOUND"

    if dst_ip == LOCAL_IP:
        return "INBOUND"

    return "UNKNOWN"


# ---------------- THREAT ENGINE ----------------
def update_threat_score(src_ip, score):
    if src_ip in PERMANENT_BLOCKED:
        return

    new_score = THREAT_SCORE.get(src_ip, 0) + score
    THREAT_SCORE[src_ip] = min(new_score, MAX_SCORE)
    LAST_ACTIVITY[src_ip] = time.time()

    current = THREAT_SCORE[src_ip]

    level = "LOW"

    if current >= CRITICAL_THRESHOLD:
        level = "CRITICAL"

    elif current >= HIGH_THRESHOLD:
        level = "HIGH"

    elif current >= MEDIUM_THRESHOLD:
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

        OFFENDER_COUNT[src_ip] = OFFENDER_COUNT.get(src_ip, 0) + 1
        offenses = OFFENDER_COUNT[src_ip]

        duration = get_quarantine_duration(src_ip)

        if duration is None:
            PERMANENT_BLOCKED.add(src_ip)

            msg = f"[PERMANENT BLOCK] {src_ip} after {offenses} offenses"
            print(msg)
            write_log(msg)

            enforce_ip_block(src_ip)
            return

        AUTO_BLOCKED[src_ip] = True

        QUARANTINE[src_ip] = {
            "blocked_at": time.time(),
            "duration": duration
        }

        msg = f"[CRITICAL] Blocking {src_ip} (offense #{offenses})"
        print(msg)
        write_log(msg)

        qmsg = f"[QUARANTINE] {src_ip} isolated for {duration} seconds"
        print(qmsg)
        write_log(qmsg)

        enforce_ip_block(src_ip)


# ---------------- DECAY ----------------
def apply_decay():
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
                RATE_LAST.pop(ip, None)
                SCAN_LAST.pop(ip, None)
                HOST_LAST.pop(ip, None)
                RETRY_LAST.pop(ip, None)


# ---------------- QUARANTINE RELEASE ----------------
def release_expired_quarantine():
    now = time.time()

    for ip in list(QUARANTINE.keys()):
        data = QUARANTINE[ip]
        blocked_at = data["blocked_at"]
        duration = data["duration"]

        if now - blocked_at >= duration:
            remove_ip_block(ip)

            msg = f"[RELEASE] Unblocked {ip} after quarantine expiry"
            print(msg)
            write_log(msg)

            QUARANTINE.pop(ip, None)
            AUTO_BLOCKED.pop(ip, None)


def get_quarantine_duration(ip):
    offenses = OFFENDER_COUNT.get(ip, 0)

    if offenses == 1:
        return FIRST_OFFENSE_TIME

    elif offenses == 2:
        return SECOND_OFFENSE_TIME

    elif offenses >= PERMANENT_BLOCK_AFTER:
        return None

    return None


# ---------------- RATE DETECTION ----------------
def check_rate_limit(src_ip, dst_ip, port):
    if port in COMMON_SAFE_PORTS:
        return

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
        retry_key = f"{src_ip}:{dst_ip}:{port}"

        if allow_alert(RETRY_LAST, retry_key):
            msg = f"[RETRY] Repeated traffic {src_ip} -> {dst_ip} PORT:{port}"
            print(msg)
            write_log(msg)

        return

    unique_patterns = {(d, p) for (_, d, p) in RATE_TRACKER[src_ip]}

    if len(unique_patterns) >= RATE_THRESHOLD:
        if allow_alert(RATE_LAST, src_ip):
            msg = f"[RATE ALERT] Diverse high traffic from {src_ip}"
            print(msg)
            write_log(msg)
            update_threat_score(src_ip, 2)


# ---------------- PORT SCAN DETECTION ----------------
def check_port_scan(src_ip, port):
    if port in COMMON_SAFE_PORTS:
        return

    now = time.time()
    SCAN_PORTS.setdefault(src_ip, [])

    SCAN_PORTS[src_ip] = [
        (t, p)
        for (t, p) in SCAN_PORTS[src_ip]
        if now - t <= PORT_SCAN_WINDOW
    ]

    SCAN_PORTS[src_ip].append((now, port))

    unique_ports = {p for (_, p) in SCAN_PORTS[src_ip]}

    if len(unique_ports) >= SCAN_THRESHOLD:
        if allow_alert(SCAN_LAST, src_ip):
            msg = f"[SCAN ALERT] Port scan from {src_ip} ({len(unique_ports)} recent ports)"
            print(msg)
            write_log(msg)
            update_threat_score(src_ip, 3)


# ---------------- HOST SWEEP DETECTION ----------------
def check_host_sweep(src_ip, dst_ip, port):
    if port in COMMON_SAFE_PORTS:
        return

    now = time.time()
    DST_TRACKING.setdefault(src_ip, [])

    DST_TRACKING[src_ip] = [
        (t, d)
        for (t, d) in DST_TRACKING[src_ip]
        if now - t <= HOST_SWEEP_WINDOW
    ]

    DST_TRACKING[src_ip].append((now, dst_ip))

    unique_dsts = {d for (_, d) in DST_TRACKING[src_ip]}

    if len(unique_dsts) >= DST_THRESHOLD:
        if allow_alert(HOST_LAST, src_ip):
            msg = f"[HOST SWEEP ALERT] Recon from {src_ip} ({len(unique_dsts)} recent destinations)"
            print(msg)
            write_log(msg)
            update_threat_score(src_ip, 2)


# ---------------- PAYLOAD INSPECTION ----------------
def inspect_payload(packet, src_ip):

    if not packet.haslayer(Raw):
        return

    try:
        payload = packet[Raw].load.decode(errors="ignore").lower()

        if DEBUG_PAYLOADS:
            debug_payload = payload[:200].encode("unicode_escape").decode("ascii")
            print(f"[DEBUG PAYLOAD] {debug_payload}")

        if len(payload) > 5000:
            return

        for pattern in SUSPICIOUS_PATTERNS:

            if pattern in payload:

                msg = f"[PAYLOAD ALERT] Suspicious pattern '{pattern}' from {src_ip}"

                print(msg)
                write_log(msg)

                update_threat_score(src_ip, 5)

                return

    except Exception as e:
        print(f"[PAYLOAD ERROR] {e}")


# ---------------- RULE CHECKS ----------------
def check_ip_rule(src_ip):
    return src_ip in BLOCK_IPS


def check_port_rule(port):
    return port in BLOCK_PORTS


def process_packet(packet):
    global LAST_DECAY_RUN

    if not packet.haslayer(IP):
        return

    PACKET_STATS["ip_seen"] += 1

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Ignore traffic outside lab environment
    if not (is_lab_ip(src_ip) or is_lab_ip(dst_ip)):
        PACKET_STATS["ignored_outside_lab"] += 1
        return

    PACKET_STATS["processed"] += 1

    # Skip permanently blocked attackers
    if src_ip in PERMANENT_BLOCKED:
        return

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

    direction = get_packet_direction(src_ip, dst_ip)

    # OUTBOUND/LAB ANALYSIS
    if direction in ("OUTBOUND", "LAB"):

        check_rate_limit(src_ip, dst_ip, port)

        check_host_sweep(src_ip, dst_ip, port)

        inspect_payload(packet, src_ip)

    # INBOUND ANALYSIS
    elif direction == "INBOUND":
        if not is_private_ip(src_ip):
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport

                # Ignore normal service responses
                if src_port not in COMMON_SAFE_PORTS:
                    check_port_scan(src_ip, src_port)
            inspect_payload(packet, src_ip)

    # RULE ENFORCEMENT
    if check_ip_rule(src_ip):
        PACKET_STATS["blocked_ip"] += 1
        msg = f"[{direction}][BLOCKED:IP] {src_ip} -> {dst_ip}"
        print(msg)
        write_log(msg)
        enforce_ip_block(src_ip)

    elif check_port_rule(port):
        PACKET_STATS["blocked_port"] += 1
        msg = f"[{direction}][BLOCKED:PORT] {protocol} {src_ip} -> {dst_ip} PORT:{port}"
        print(msg)
        write_log(msg)

    else:
        PACKET_STATS["allowed"] += 1
        msg = f"[{direction}][ALLOWED] {protocol} {src_ip} -> {dst_ip} PORT:{port}"
        if LOG_ALLOWED_TRAFFIC:
            print(msg)
            write_log(msg)

    now = time.time()

    if now - LAST_DECAY_RUN > DECAY_CHECK_INTERVAL:
        apply_decay()
        release_expired_quarantine()
        LAST_DECAY_RUN = now


def load_config():
    try:
        with open(SETTINGS_FILE, "r") as f:
            loaded_settings = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load settings.json: {e}")
        print(f"[HINT] Copy config/settings.example.json to {SETTINGS_FILE}")
        sys.exit(1)

    for key in REQUIRED_SETTINGS_KEYS:
        if key not in loaded_settings:
            raise ValueError(f"Missing settings key: {key}")

    try:
        with open(RULES_FILE, "r") as f:
            loaded_rules = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load rules.json: {e}")
        loaded_rules = {
            "block_ips": [],
            "block_ports": [],
            "whitelist_ips": []
        }

    return loaded_settings, loaded_rules


def run():
    """Load config, initialize threat-tracking state, and start packet capture."""
    global LOCAL_IP, settings, rules
    global BLOCK_IPS, BLOCK_PORTS, WHITELIST_IPS
    global THREAT_SCORE, AUTO_BLOCKED, QUARANTINE, LAST_ACTIVITY, PACKET_STATS
    global OFFENDER_COUNT, PERMANENT_BLOCKED
    global MAX_SCORE, DECAY_INTERVAL, DECAY_AMOUNT, DECAY_CHECK_INTERVAL, LAST_DECAY_RUN
    global QUARANTINE_SETTINGS, FIRST_OFFENSE_TIME, SECOND_OFFENSE_TIME, PERMANENT_BLOCK_AFTER
    global SCAN_PORTS, SCAN_THRESHOLD, PORT_SCAN_WINDOW
    global DST_TRACKING, DST_THRESHOLD, HOST_SWEEP_WINDOW
    global RATE_TRACKER, RATE_THRESHOLD, TIME_WINDOW, RETRY_THRESHOLD
    global COMMON_SAFE_PORTS, SUSPICIOUS_PATTERNS, DEBUG_PAYLOADS, LOG_ALLOWED_TRAFFIC
    global RATE_LAST, SCAN_LAST, HOST_LAST, RETRY_LAST, COOLDOWN
    global LAB_NETWORKS, THREAT_THRESHOLDS, MEDIUM_THRESHOLD, HIGH_THRESHOLD, CRITICAL_THRESHOLD

    LOCAL_IP = get_local_ip()
    print(f"[INFO] Local IP detected: {LOCAL_IP}")

    settings, rules = load_config()

    BLOCK_IPS = rules.get("block_ips", [])
    BLOCK_PORTS = rules.get("block_ports", [])
    WHITELIST_IPS = set(rules.get("whitelist_ips", []))

    # ---------------- THREAT STATE ----------------
    THREAT_SCORE = {}
    AUTO_BLOCKED = {}
    QUARANTINE = {}
    LAST_ACTIVITY = {}
    PACKET_STATS = {
        "ip_seen": 0,
        "processed": 0,
        "ignored_outside_lab": 0,
        "allowed": 0,
        "blocked_ip": 0,
        "blocked_port": 0,
    }

    OFFENDER_COUNT = {}
    PERMANENT_BLOCKED = set()

    MAX_SCORE = settings["max_threat_score"]

    DECAY_INTERVAL = settings["decay"]["interval"]
    DECAY_AMOUNT = settings["decay"]["amount"]
    DECAY_CHECK_INTERVAL = settings["decay"]["check_interval"]

    LAST_DECAY_RUN = 0

    QUARANTINE_SETTINGS = settings["quarantine"]

    FIRST_OFFENSE_TIME = QUARANTINE_SETTINGS["first_offense"]
    SECOND_OFFENSE_TIME = QUARANTINE_SETTINGS["second_offense"]
    PERMANENT_BLOCK_AFTER = settings["permanent_block_after"]

    # ---------------- DETECTION CONFIG ----------------
    SCAN_PORTS = {}

    SCAN_THRESHOLD = settings["detection"]["scan_threshold"]
    PORT_SCAN_WINDOW = settings["detection"]["port_scan_window"]

    DST_TRACKING = {}

    DST_THRESHOLD = settings["detection"]["host_sweep_threshold"]
    HOST_SWEEP_WINDOW = settings["detection"]["host_sweep_window"]

    RATE_TRACKER = {}

    RATE_THRESHOLD = settings["detection"]["rate_threshold"]
    TIME_WINDOW = settings["detection"]["time_window"]
    RETRY_THRESHOLD = settings["detection"]["retry_threshold"]

    COMMON_SAFE_PORTS = set(settings["safe_ports"])

    SUSPICIOUS_PATTERNS = settings["payload_patterns"]
    DEBUG_PAYLOADS = settings.get("debug_payloads", False)
    LOG_ALLOWED_TRAFFIC = settings.get("log_allowed_traffic", False)

    # ---------------- ALERT COOLDOWNS ----------------
    RATE_LAST = {}
    SCAN_LAST = {}
    HOST_LAST = {}
    RETRY_LAST = {}

    COOLDOWN = settings["cooldown_seconds"]

    # ---------------- LAB NETWORKS ----------------
    LAB_NETWORKS = settings["lab_networks"]

    # ---------------- THREAT THRESHOLDS ----------------
    THREAT_THRESHOLDS = settings["threat_thresholds"]

    MEDIUM_THRESHOLD = THREAT_THRESHOLDS["medium"]
    HIGH_THRESHOLD = THREAT_THRESHOLDS["high"]
    CRITICAL_THRESHOLD = THREAT_THRESHOLDS["critical"]

    # ---------------- START ENGINE ----------------
    iface = settings.get("network_interface") or None

    if iface:
        print(f"[INFO] Capturing on {iface}")
    else:
        print("[INFO] No network_interface set in settings.json - capturing on default interface")
        print("[HINT] Run `python list_interfaces.py` to see available interface names")

    try:
        sniff(
            iface=iface,
            filter="ip",
            prn=process_packet,
            store=False
        )
    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user")
    except Exception as e:
        print(f"\n[ERROR] Capture stopped: {e}")

    # ---------------- SUMMARY ----------------
    print("\n--- Summary ---")
    print("Packet Stats:", PACKET_STATS)
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


if __name__ == "__main__":
    run()
