#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""严格检验 v5_hi/v6_hi 命中注册键 vs 同值域随机基线"""
import csv, struct, random
random.seed(42)
rows = list(csv.DictReader(open("outputs/event_table_named.csv", encoding="utf-8")))
def n(r, k):
    try: return int(r[k])
    except (KeyError, ValueError): return None

b = open("decoded/ML00000000.data", "rb").read(); N = len(b)
reg = set()
o = 0xde034
while o + 8 <= N:
    a = struct.unpack_from("<I", b, o)[0]
    c = struct.unpack_from("<I", b, o+4)[0]
    if 1 <= a <= 400000 and 1 <= c <= 200000:
        reg.add(a)
    o += 8
print("注册键数:", len(reg))

v5h = [n(r, "v5") >> 16 for r in rows]
v6h = [n(r, "v6") >> 16 for r in rows]
print("v5_hi 值域: %d..%d" % (min(v5h), max(v5h)))
v6n = [x for x in v6h if x != 65535]
print("v6_hi 值域(非哨兵): %d..%d" % (min(v6n), max(v6n)))

for name, vals in [("v5_hi", v5h), ("v6_hi非哨兵", v6n)]:
    lo, hi = min(vals), max(vals)
    N_R = 20000
    hits = sum(1 for _ in range(N_R) if random.randint(lo, hi) in reg)
    base = hits / N_R
    actual = sum(1 for v in vals if v in reg) / len(vals)
    sig = "显著（确证）" if actual > base + 0.05 else "不显著（疑似密度巧合）"
    print("随机基线 %s（值域 %d..%d）: %.1f%%" % (name, lo, hi, base*100))
    print("  实际命中率: %.1f%% -> %s" % (actual*100, sig))
