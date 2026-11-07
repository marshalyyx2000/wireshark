# -*- coding: utf-8 -*-
"""Show a line range of a GBK reference source."""
import io
import sys

p = sys.argv[1]
start = int(sys.argv[2])
end = int(sys.argv[3])
t = io.open(p, encoding="gbk", errors="replace").read().splitlines()
for i in range(start - 1, min(end, len(t))):
    print(f"{i+1:5d}|{t[i]}")
