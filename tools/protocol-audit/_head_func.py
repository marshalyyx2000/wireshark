# -*- coding: utf-8 -*-
"""Print the head-building function body of a reference source (GBK)."""
import io
import re
import sys

KEYS = ("Set_PacketHead", "Set_Packet_Head", "Set_PacketHeadEx", "SetHead",
        "MakeHead", "Pack_Head", "SendHead", "Set_Packet_Head_Net")


def main() -> int:
    path = sys.argv[1]
    ctx = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    text = io.open(path, encoding="gbk", errors="replace").read().splitlines()
    printed = set()
    for i, line in enumerate(text):
        if any(k in line for k in KEYS) and "(" in line and ";" not in line:
            start = i
            end = min(len(text), i + ctx)
            for j in range(i, len(text)):
                if text[j].strip() == "}" and j > i + 3:
                    end = j + 1
                    break
            if start in printed:
                continue
            printed.add(start)
            print(f"--- {path}:{start+1} ---")
            for j in range(start, end):
                print(f"{j+1:5d}|{text[j]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
