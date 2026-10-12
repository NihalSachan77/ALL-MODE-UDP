# -*- coding: utf-8 -*-
"""
test_mode.py — StartMatch capture analyzer
Ei tool tomar captures/ folder er LW/BR/CS .bin file analyze korbe
ar MODE_START_BYTE verify korbe.

Usage:
    python test_mode.py
    python test_mode.py captures/startmatch_LW_*.bin captures/startmatch_BR_*.bin
"""

import os
import sys
import glob
import struct


CAPTURE_DIR = "captures"


def hexdump_first(data: bytes, n: int = 32):
    """Ei data er first n byte hex-এ দেখাও, 16 per line."""
    out = []
    for i in range(0, min(n, len(data)), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{i:04x}  {hx:<48}  {ascii_repr}")
    return "\n".join(out)


def find_first_diff(a: bytes, b: bytes):
    """Dui bytes er prothom different byte er index return koro."""
    limit = min(len(a), len(b))
    for i in range(limit):
        if a[i] != b[i]:
            return i, a[i], b[i]
    if len(a) != len(b):
        return limit, (a[limit] if len(a) > limit else None), (b[limit] if len(b) > limit else None)
    return None, None, None


def all_diff_positions(a: bytes, b: bytes, max_show: int = 20):
    """Sob diff index return koro."""
    diffs = []
    limit = min(len(a), len(b))
    for i in range(limit):
        if a[i] != b[i]:
            diffs.append((i, a[i], b[i]))
            if len(diffs) >= max_show:
                break
    return diffs


def read_file(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def pick_latest(pattern: str):
    """Pattern e match kora sob file theke latest ta return koro."""
    files = glob.glob(pattern)
    if not files:
        return None
    files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return files[0]


def auto_discover():
    """captures/ folder e LW/BR/CS file auto khujo."""
    result = {}
    for mode in ("LW", "BR", "CS"):
        latest = pick_latest(os.path.join(CAPTURE_DIR, f"startmatch_{mode}_*.bin"))
        if latest:
            result[mode] = latest
    return result


def analyze():
    print("=" * 70)
    print("  AGS COMMUNITY — StartMatch Mode Byte Analyzer")
    print("=" * 70)
    print()

    # ---- File discover ----
    if len(sys.argv) >= 3:
        # Custom paths
        files = {}
        for arg in sys.argv[1:]:
            name = os.path.basename(arg).upper()
            for mode in ("LW", "BR", "CS"):
                if f"_{mode}_" in name or name.startswith(mode):
                    files[mode] = arg
                    break
        if not files:
            print("[-] Could not detect mode from filenames. Give paths like: startmatch_LW_*.bin")
            return
    else:
        files = auto_discover()

    if not files:
        print(f"[-] No capture files found in '{CAPTURE_DIR}/'")
        print()
        print("Ki korbe:")
        print("  1. Main.py te capture block add koro (age pathiyechi)")
        print("  2. Server restart, dashboard theke LW mode start koro")
        print("  3. Dashboard theke BR mode click koro (3-4 sec wait)")
        print("  4. Dashboard theke CS mode click koro (3-4 sec wait)")
        print("  5. Ei tool abar chalao")
        return

    print(f"[+] Found {len(files)} capture(s):")
    for m, p in files.items():
        size = os.path.getsize(p)
        print(f"    {m}: {p} ({size} bytes)")
    print()

    # ---- Load ----
    data = {}
    for m, p in files.items():
        try:
            data[m] = read_file(p)
        except Exception as e:
            print(f"[-] Failed to read {p}: {e}")
    if not data:
        return

    # ---- Header dump ----
    print("─" * 70)
    print("  FIRST 32 BYTES (hex)")
    print("─" * 70)
    for m in ("LW", "BR", "CS"):
        if m in data:
            print(f"\n[{m}]  first byte pair: {data[m][:2].hex()}")
            print(hexdump_first(data[m], 32))
    print()

    # ---- Compare with LW baseline ----
    if "LW" not in data:
        print("[!] No LW baseline — analysis limited")
        return

    lw = data["LW"]
    print("─" * 70)
    print("  DIFF vs LW baseline (first 20 differences)")
    print("─" * 70)

    mode_bytes = {"LW": lw[1] if len(lw) >= 2 and lw[0] == 0x08 else None}

    for m in ("BR", "CS"):
        if m not in data:
            continue
        other = data[m]
        print(f"\n[{m}] vs [LW]")
        print(f"  size: LW={len(lw)}  {m}={len(other)}  delta={len(other) - len(lw)}")

        diffs = all_diff_positions(lw, other, max_show=20)
        if not diffs:
            print("  (identical)")
            continue

        for idx, lw_b, ot_b in diffs:
            print(f"  offset 0x{idx:04x}: LW=0x{lw_b:02x}  {m}=0x{ot_b:02x}")

        # Mode byte detect
        if len(other) >= 2 and other[0] == 0x08:
            mode_bytes[m] = other[1]
            print(f"  → {m} mode byte (offset 0x01): 0x{other[1]:02x}")

    # ---- Verdict ----
    print()
    print("=" * 70)
    print("  VERDICT — MODE_START_BYTE")
    print("=" * 70)
    print()

    all_good = True
    for m in ("LW", "BR", "CS"):
        if m in mode_bytes and mode_bytes[m] is not None:
            print(f"    \"{m}\": 0x{mode_bytes[m]:02x},")
        else:
            print(f"    \"{m}\": ???  (capture missing or malformed)")
            all_good = False

    print()
    if all_good:
        print("[+] Sob mode byte detect hoyeche. Copy koro upore theke,")
        print("    tarpor Main.py te MODE_START_BYTE update koro.")
    else:
        print("[!] Kichu mode missing. LW/BR/CS sob capture koro age.")

    print()
    print("─" * 70)
    print("  FIRST FIELD ANALYSIS (protobuf wire type)")
    print("─" * 70)
    for m in ("LW", "BR", "CS"):
        if m not in data:
            continue
        d = data[m]
        if len(d) >= 2 and d[0] == 0x08:
            print(f"  [{m}] tag=0x{d[0]:02x} (field=1, varint)  value=0x{d[1]:02x} ({d[1]})")
        else:
            print(f"  [{m}] unexpected first byte: 0x{d[0]:02x}")
    print()
    print("Done.")


if __name__ == "__main__":
    try:
        analyze()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        import traceback
        traceback.print_exc()