# -*- coding: utf-8 -*-
"""Register every spec-generated dissector source in CMakeLists and the minimal list."""
import io
import json
from pathlib import Path

ROOT = Path(r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark")
DISS = ROOT / "epan" / "dissectors"

SPECS = ["vendor-spec.json", "dfr-spec.json", "generic-spec.json"]

CM = DISS / "CMakeLists.txt"
MIN = DISS / "minimal-dissectors.txt"

cm = io.open(CM, encoding="utf-8").read()
mn = io.open(MIN, encoding="utf-8").read()

added_cm, added_mn = [], []
for spec in SPECS:
    data = json.loads(io.open(ROOT / "tools" / "protocol-audit" / spec, encoding="utf-8").read())
    for v in data["vendors"]:
        name = f"packet-{v['short']}.c"
        if name not in cm:
            cm = cm.replace(
                "\t${CMAKE_CURRENT_SOURCE_DIR}/packet-lbd_lubo_tcp.c\n",
                "\t${CMAKE_CURRENT_SOURCE_DIR}/packet-lbd_lubo_tcp.c\n"
                f"\t${{CMAKE_CURRENT_SOURCE_DIR}}/{name}\n", 1)
            added_cm.append(name)
        if name not in mn:
            mn = mn.replace("packet-lbd_lubo_tcp.c\n",
                            f"packet-lbd_lubo_tcp.c\n{name}\n", 1)
            added_mn.append(name)

io.open(CM, "w", encoding="utf-8", newline="").write(cm)
io.open(MIN, "w", encoding="utf-8", newline="").write(mn)
print("cmake added:", added_cm)
print("minimal added:", added_mn)
