"""Dump detailed framing facts for selected vendors."""
import json
import sys
from pathlib import Path

AUDIT = Path("tools/protocol-audit/audit")
for v in sys.argv[1:]:
    f = AUDIT / f"{v}.frames.json"
    print("=" * 70)
    print(v)
    if not f.exists():
        print("  no frames json")
        continue
    d = json.loads(f.read_text(encoding="utf-8"))
    for k, val in d.items():
        if k == "raw_snippets":
            continue
        print(f"  {k} = {val}")
