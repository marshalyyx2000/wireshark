"""Print APCI.md sections for the requested vendors."""
import io
import sys
from pathlib import Path

p = Path("tools/protocol-audit/audit/APCI.md")
text = io.open(p, encoding="utf-8", errors="replace").read().splitlines()
want = set(sys.argv[1:])
cur = None
buf = []
for line in text:
    if line.startswith("## "):
        if cur in want:
            print("\n".join(buf))
        cur = line[3:].split()[0].rstrip("(")
        buf = [line]
    else:
        buf.append(line)
if cur in want:
    print("\n".join(buf))
