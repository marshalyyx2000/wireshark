"""Classify every vendor in APCI.md by its first few frame bytes."""
import io
import re
from pathlib import Path

p = Path("tools/protocol-audit/audit/APCI.md")
lines = io.open(p, encoding="utf-8", errors="replace").read().splitlines()

sections = []
cur = None
for line in lines:
    m = re.match(r"^## (\S+)\s+\((\d+) 字节, 来自 (\S+)\)", line)
    if m:
        cur = {"name": m.group(1), "len": int(m.group(2)), "src": m.group(3), "bytes": []}
        sections.append(cur)
        continue
    if cur is None:
        continue
    m = re.match(r"^([0-9A-F]{2}): (\S+)\s*(?://\s*(.*))?$", line)
    if m:
        cur["bytes"].append((m.group(2), (m.group(3) or "").strip()))

print(f"{'vendor':26s} {'len':>4s}  head")
for s in sections:
    head = " ".join(b for b, _ in s["bytes"][:8])
    print(f"{s['name']:26s} {s['len']:4d}  {head}")
print(f"\ntotal {len(sections)}")
