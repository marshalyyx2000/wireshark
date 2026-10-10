#!/usr/bin/env python3
from pathlib import Path
import re

root = Path(__file__).resolve().parents[2] / "ui" / "qt"
files = [
    root / "io_graph_dialog.cpp",
    root / "plot_dialog.cpp",
    root / "tcp_stream_dialog.cpp",
]
for p in files:
    t = p.read_text(encoding="utf-8")
    orig = t
    if '#include "qt5_compat.h"' not in t:
        if '#include "config.h"' in t:
            t = t.replace('#include "config.h"', '#include "config.h"\n#include "qt5_compat.h"', 1)
        else:
            t = '#include "qt5_compat.h"\n' + t
    t = re.sub(r"\((Qt::Align[^)]+)\)\.toInt\(\)", r"ws_alignment_to_int(\1)", t)
    t = re.sub(r"Qt::Alignment::fromInt\(([^)]+)\)", r"ws_alignment_from_int(\1)", t)
    t = t.replace(
        "contextAction->data().canConvert<Qt::Alignment::Int>()",
        "contextAction->data().canConvert<int>()",
    )
    t = t.replace(
        "contextAction->data().value<Qt::Alignment::Int>()",
        "contextAction->data().toInt()",
    )
    if t != orig:
        p.write_text(t, encoding="utf-8", newline="\n")
        print("patched", p.name)
    else:
        print("no change", p.name)
