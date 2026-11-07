"""Print framing summary for the remaining 103-family vendors."""
import json
from pathlib import Path

AUDIT = Path("tools/protocol-audit/audit")
TODO = ["ABB103", "ABB_COM_101", "ALSTOM_103_COM", "BP103", "NR_103_NET",
        "SIEMENS_103_COM", "SJ103", "SZNR_103_TCP", "WGL3000",
        "NR103_RCS9793", "NZ_NET103", "SF_CSFM103_TCP"]

for v in TODO:
    f = AUDIT / f"{v}.frames.json"
    if not f.exists():
        print(f"{v:22s} NO-FRAMES")
        continue
    d = json.loads(f.read_text(encoding="utf-8"))
    socks = ",".join(d["sockets"]) or "-"
    print(f"{v:22s} socks={socks:18s} asdu_start={d['asdu_start_candidates']} "
          f"len_off={d['len_field_offsets'][:4]}")
