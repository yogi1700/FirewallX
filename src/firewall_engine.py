import json
import time
import socket
import ipaddress
from scapy.all import sniff, IP, TCP, UDP
from enforce_firewall import enforce_ip_block
from logger import write_log


# ---------- Dynamic Local IP Detection ----------
def get_local_ip():
    """
    Detect local machine IP dynamically
    """

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

# ---------- Whitelist ----------
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

DST_TRACKING = {}
DST_THRESHOLD = 6

RATE_TRACKER = {}
RATE_THRESHOLD = 10
TIME_WINDOW = 5

# ---------- Detection Windows ----------
PORT_SCAN_WINDOW = 10
HOST_SWEEP_WINDOW = 10

# ---------- Safe Ports ----------
# Ignore very common ports for scan detection
COMMON_SAFE_PORTS = {53}


# ---------- Alert Cooldowns ----------
RATE_LAST = {}
SCAN_LAST = {}
HOST_LAST = {}

COOLDOWN = 3


# ---------- Cooldown Helper ----------
def allow_alert(store, ip):
    """
    Prevent repeated alert spam
    """

    now = time.time()

    last = store.get(ip, 0)

    if now - last > COOLDOWN:

        store[ip] = now

        return True

    return False


# ---------- Whitelist Check ----------
def is_whitelisted(ip):
    """
    Support:
    - Single IP whitelist
    - CIDR/network whitelist
    """

    for entry in WHITELIST_IPS:

        # ---------- Single IP ----------
        if "/" not in entry:

            if ip == entry:
                return True

        # ---------- CIDR / Network ----------
        else:

            network = ipaddress.ip_network(entry, strict=False)

            if ipaddress.ip_address(ip) in network:
                return True

    return False


# ---------- Threat Scoring ----------
def update_threat_score(src_ip, score):
    """
    Update threat score and apply IPS logic
    """

    new_score = THREAT_SCORE.get(src_ip, 0) + score

    # ---------- Score Cap ----------
    THREAT_SCORE[src_ip] = min(new_score, MAX_SCORE)

    LAST_ACTIVITY[src_ip] = time.time()

    score = THREAT_SCORE[src_ip]

    # ---------- Threat Level ----------
    level = "LOW"

    if score >= 15:
        level = "CRITICAL"

    elif score >= 10:
        level = "HIGH"

    elif score >= 5:
        level = "MEDIUM"

    print(f"[THREAT] {src_ip} Score={score} Level={level}")

    # ---------- IPS Actions ----------
    if level == "HIGH":

        msg = f"[WARNING] High threat detected from {src_ip}"

        print(msg)

        write_log(msg)

    elif level == "CRITICAL":

        # ---------- Prevent repeated blocks ----------
        if src_ip in AUTO_BLOCKED:
            return

        # ---------- Self Protection ----------
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
    """
    Slowly reduce old threat scores
    """

    now = time.time()

    for ip in list(THREAT_SCORE.keys()):

        last = LAST_ACTIVITY.get(ip, now)

        # ---------- Reduce stale scores ----------
        if now - last > DECAY_INTERVAL:

            if THREAT_SCORE[ip] > 0:

                THREAT_SCORE[ip] -= DECAY_AMOUNT

                print(
                    f"[DECAY] {ip} Score -> {THREAT_SCORE[ip]}"
                )

            # ---------- Cleanup ----------
            if THREAT_SCORE[ip] <= 0:

                print(f"[CLEANUP] Removing {ip}")

                THREAT_SCORE.pop(ip, None)

                LAST_ACTIVITY.pop(ip, None)


# ---------- Rate Detection ----------
def check_rate_limit(src_ip):
    """
    Detect excessive traffic in short time
    """

    now = time.time()

    RATE_TRACKER.setdefault(src_ip, [])

    # ---------- Remove old timestamps ----------
    RATE_TRACKER[src_ip] = [
        t for t in RATE_TRACKER[src_ip]
        if now - t <= TIME_WINDOW
    ]

    # ---------- Add latest packet ----------
    RATE_TRACKER[src_ip].append(now)

    # ---------- Trigger alert ----------
    if len(RATE_TRACKER[src_ip]) >= RATE_THRESHOLD:

        if allow_alert(RATE_LAST, src_ip):

            msg = (
                f"[RATE ALERT] High traffic from {src_ip}"
            )

            print(msg)

            write_log(msg)

            update_threat_score(src_ip, 2)


# ---------- Port Scan Detection ----------
def check_port_scan(src_ip, port):
    """
    Detect rapid access to multiple ports
    within a short time window
    """

    # ---------- Ignore safe ports ----------
    if port in COMMON_SAFE_PORTS:
        return

    now = time.time()

    SCAN_PORTS.setdefault(src_ip, [])

    # ---------- Remove expired entries ----------
    SCAN_PORTS[src_ip] = [
        (t, p)
        for (t, p) in SCAN_PORTS[src_ip]
        if now - t <= PORT_SCAN_WINDOW
    ]

    # ---------- Add latest event ----------
    SCAN_PORTS[src_ip].append((now, port))

    # ---------- Recent unique ports ----------
    unique_ports = {
        p for (_, p) in SCAN_PORTS[src_ip]
    }

    # ---------- Trigger alert ----------
    if len(unique_ports) >= SCAN_THRESHOLD:

        if allow_alert(SCAN_LAST, src_ip):

            msg = (
                f"[SCAN ALERT] Port scan from {src_ip} "
                f"({len(unique_ports)} recent ports)"
            )

            print(msg)

            write_log(msg)

            update_threat_score(src_ip, 3)

    # ---------- Cleanup empty entries ----------
    if not SCAN_PORTS[src_ip]:
        SCAN_PORTS.pop(src_ip, None)


# ---------- Host Sweep Detection ----------
def check_host_sweep(src_ip, dst_ip):
    """
    Detect rapid access to multiple hosts
    within a short time window
    """

    now = time.time()

    DST_TRACKING.setdefault(src_ip, [])

    # ---------- Remove expired entries ----------
    DST_TRACKING[src_ip] = [
        (t, d)
        for (t, d) in DST_TRACKING[src_ip]
        if now - t <= HOST_SWEEP_WINDOW
    ]

    # ---------- Add latest destination ----------
    DST_TRACKING[src_ip].append((now, dst_ip))

    # ---------- Recent unique destinations ----------
    unique_dsts = {
        d for (_, d) in DST_TRACKING[src_ip]
    }

    # ---------- Trigger alert ----------
    if len(unique_dsts) >= DST_THRESHOLD:

        if allow_alert(HOST_LAST, src_ip):

            msg = (
                f"[HOST SWEEP ALERT] Recon from {src_ip} "
                f"({len(unique_dsts)} recent destinations)"
            )

            print(msg)

            write_log(msg)

            update_threat_score(src_ip, 2)

    # ---------- Cleanup empty entries ----------
    if not DST_TRACKING[src_ip]:
        DST_TRACKING.pop(src_ip, None)


# ---------- IP Rule Check ----------
def check_ip_rule(src_ip):
    """
    Check blocked IP rules
    """

    return src_ip in BLOCK_IPS


# ---------- Port Rule Check ----------
def check_port_rule(port):
    """
    Check blocked port rules
    """

    return port in BLOCK_PORTS


# ---------- Packet Processing Engine ----------
def process_packet(packet):
    """
    Main packet analysis pipeline
    """

    global LAST_DECAY_RUN

    # ---------- Ignore non-IP traffic ----------
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # ---------- Whitelist Bypass ----------
    if is_whitelisted(src_ip) or is_whitelisted(dst_ip):

        trusted_ip = (
            src_ip
            if is_whitelisted(src_ip)
            else dst_ip
        )

        print(
            f"[WHITELIST] Trusted IP skipped: {trusted_ip}"
        )

        return

    protocol = "OTHER"
    port = ""

    # ---------- TCP ----------
    if packet.haslayer(TCP):

        protocol = "TCP"

        port = packet[TCP].dport

    # ---------- UDP ----------
    elif packet.haslayer(UDP):

        protocol = "UDP"

        port = packet[UDP].dport

    # ---------- IDS Detection ----------
    if src_ip in MONITORED_IPS:

        check_rate_limit(src_ip)

        if port:
            check_port_scan(src_ip, port)

        check_host_sweep(src_ip, dst_ip)

    # ---------- Firewall Rules ----------
    if check_ip_rule(src_ip):

        msg = (
            f"[BLOCKED:IP] {src_ip} -> {dst_ip}"
        )

        print(msg)

        write_log(msg)

        enforce_ip_block(src_ip)

    elif check_port_rule(port):

        msg = (
            f"[BLOCKED:PORT] "
            f"{protocol} {src_ip} -> {dst_ip} "
            f"PORT:{port}"
        )

        print(msg)

        write_log(msg)

    else:

        msg = (
            f"[ALLOWED] "
            f"{protocol} {src_ip} -> {dst_ip} "
            f"PORT:{port}"
        )

        print(msg)

        write_log(msg)

    # ---------- Controlled Decay ----------
    now = time.time()

    if now - LAST_DECAY_RUN > DECAY_CHECK_INTERVAL:

        apply_decay()

        LAST_DECAY_RUN = now


# ---------- Start Packet Capture ----------
sniff(prn=process_packet)


# ---------- Session Summary ----------
print("\n--- Summary ---")

print(
    "Scan Tracking:",
    {k: len(v) for k, v in SCAN_PORTS.items()}
)

print(
    "Destination Tracking:",
    {k: len(v) for k, v in DST_TRACKING.items()}
)

print(
    "Rate Tracking:",
    {k: len(v) for k, v in RATE_TRACKER.items()}
)

print(
    "Threat Scores:",
    THREAT_SCORE
)