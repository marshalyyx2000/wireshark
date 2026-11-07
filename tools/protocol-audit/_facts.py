"""Dump compact facts for remaining vendors from audit JSON."""
import json
import sys
from pathlib import Path

A = Path("tools/protocol-audit/audit")
names = sys.argv[1:]
for n in names:
    f = A / f"{n}.json"
    if not f.exists():
        print(f"{n}: MISSING")
        continue
    d = json.loads(f.read_text(encoding="utf-8"))
    keys = ("vendor", "kind", "transport", "ports", "length_field", "cot_bytes",
            "asdu_start", "frame", "notes", "checksum", "sources")
    print("=" * 60)
    print(n)
    for k, v in d.items():
        if k in ("raw_snippets", "files"):
            continue
        s = repr(v)
        if len(s) > 260:
            s = s[:260] + "..."
        print(f"  {k} = {s}")
