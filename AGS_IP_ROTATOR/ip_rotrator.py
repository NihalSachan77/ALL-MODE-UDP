#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════
#  AGS IP ROTATOR — Tor Mode (Fast)
#  Author: AGS
# ═══════════════════════════════════════════════════════════════════════════

import time
import os
import sys
import subprocess
import requests

try:
    from stem import Signal
    from stem.control import Controller
except ImportError:
    print("[!] stem ইনস্টল করছি...")
    subprocess.run([sys.executable, "-m", "pip", "install", "stem", "requests[socks]"])
    from stem import Signal
    from stem.control import Controller


# ── CONFIG ──
ROTATE_INTERVAL = 12        # সেকেন্ড — প্রতি ১২s পরপর IP চেঞ্জ
TOR_SOCKS_PORT  = 9050
TOR_CONTROL_PORT = 9051
CHECK_URL       = "https://api.ipify.org?format=json"


def get_tor_session():
    s = requests.Session()
    s.proxies = {
        "http":  "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050",
    }
    return s


def current_ip():
    try:
        r = get_tor_session().get(CHECK_URL, timeout=10)
        return r.json().get("ip", "?")
    except Exception as e:
        return f"ERR"


def renew_tor_ip():
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            # Tor নিজে থেকে circuit বিল্ড করতে সময় দে
            time.sleep(1.5)
        return True
    except Exception as e:
        print(f"[!] NEWNYM failed: {e}")
        return False


def main():
    print()
    print("═" * 60)
    print("  ⚡ AGS IP ROTATOR — Tor Mode (FAST)")
    print("═" * 60)
    print(f"  Interval   : {ROTATE_INTERVAL}s")
    print(f"  Tor SOCKS  : 127.0.0.1:{TOR_SOCKS_PORT}")
    print(f"  ControlPort: {TOR_CONTROL_PORT}")
    print("═" * 60)
    print()

    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as c:
            c.authenticate()
    except Exception as e:
        print(f"[!] Tor ControlPort এ কানেক্ট করা যাচ্ছে না: {e}")
        print("[!] Termux এ টার্মিনালে চালাও: tor")
        sys.exit(1)

    # প্রাথমিক IP দেখাও
    print(f"[0] Current IP: {current_ip()}\n")

    count = 0
    while True:
        count += 1
        t0 = time.time()

        old_ip = current_ip()
        renew_tor_ip()
        new_ip = current_ip()

        elapsed = time.time() - t0
        changed = "✓" if old_ip != new_ip else "✗"

        print(f"[{count:04d}] {changed}  {old_ip:<18} →  {new_ip:<18}  ({elapsed:.1f}s)")

        sleep_for = max(0.5, ROTATE_INTERVAL - elapsed)
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()