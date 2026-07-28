"""Whitelisted traffic must be logged to file, not just printed to
console - see the README's "Reading the Output" section. Uses a real
scapy IP packet (not a hand-rolled mock) so the test exercises the
same object shape process_packet() actually receives at runtime."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from scapy.all import IP

import firewall_engine as fe


def _reset_state(whitelist_ips):
    fe.PACKET_STATS = {
        "ip_seen": 0, "processed": 0, "ignored_outside_lab": 0,
        "allowed": 0, "blocked_ip": 0, "blocked_port": 0,
    }
    fe.PERMANENT_BLOCKED = set()
    fe.WHITELIST_IPS = whitelist_ips
    fe.LAB_NETWORKS = ["203.0.113."]
    fe.LOCAL_IP = "203.0.113.100"


def test_whitelisted_traffic_is_written_to_log(monkeypatch):
    _reset_state({"203.0.113.5"})

    logged = []
    monkeypatch.setattr(fe, "write_log", lambda msg: logged.append(msg))

    packet = IP(src="203.0.113.5", dst="203.0.113.100")
    fe.process_packet(packet)

    assert len(logged) == 1
    assert "[WHITELIST]" in logged[0]
    assert "203.0.113.5" in logged[0]


def test_non_whitelisted_traffic_does_not_hit_the_whitelist_log_path(monkeypatch):
    _reset_state({"203.0.113.5"})

    logged = []
    monkeypatch.setattr(fe, "write_log", lambda msg: logged.append(msg))

    # outside lab_networks entirely, so this returns at the
    # "ignored_outside_lab" check - before the whitelist branch could
    # possibly fire either way
    packet = IP(src="198.51.100.9", dst="198.51.100.100")
    fe.process_packet(packet)

    assert logged == []
