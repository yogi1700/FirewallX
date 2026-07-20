"""Print available network interfaces so you can set `network_interface`
in config/settings.json (see config/settings.example.json)."""

from scapy.all import get_if_list, get_if_addr

if __name__ == "__main__":
    for name in get_if_list():
        try:
            addr = get_if_addr(name)
        except Exception:
            addr = "?"
        print(f"{name}  ({addr})")
