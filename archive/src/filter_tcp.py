from scapy.all import sniff, IP

# Change this to any IP you want to block
BLOCK_IP = "192.168.1.100"

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip == BLOCK_IP:
            print(f"BLOCKED ❌ | SRC: {src_ip} → DST: {dst_ip}")
        else:
            print(f"ALLOWED ✅ | SRC: {src_ip} → DST: {dst_ip}")

sniff(prn=process_packet, count=20)
