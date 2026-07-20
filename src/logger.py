from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent.parent / "logs" / "firewall.log"

def write_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {message}\n")
