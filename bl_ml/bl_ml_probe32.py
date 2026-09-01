#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe32.py — 验证事件表其余字段是否含俱乐部 ID，以支撑「玩家队预算闭合」。

假设：转会记录可能含 源队(from) / 目的队(to) 两个俱乐部 ID。
若 v4 或 v5 落在合理俱乐部 ID 区间（如 1..700 / 1..2000），则可作为筛选键。
同时观察是否存在「单存档内恒定值」的字段（可能即玩家队 ID 或联赛 ID）。
"""
import struct, os
from collections import Counter

BASE = "decoded"
SAMPLES = [
    ("ML0",  "ML00000000.data"),
    ("ML1",  "ML00000001.data"),
    ("ML13", "ML00000013.data"),
]
STEP = 0x24

def locate_table(path, need=50):
    b = open(path, "rb").read(); n = len(b)
    cand = set()
    for off in range(0, n - STEP):
        y = struct.unpack_from("<H", b, off)[0]; mo = b[off+2]; da = b[off+3]
        if 2000 <= y <= 2100 and 1 <= mo <= 12 and 1 <= da <= 31:
            cand.add(off)
    for start in sorted(cand):
        cnt = 0; o = start
        while o + 4 <= n:
            y = struct.unpack_from("<H", b, o)[0]; mo = b[o+2]; da = b[o+3]
            if not (2000 <= y <= 2100 and 1 <= mo <= 12 and 1 <= da <= 31):
                break
            cnt += 1; o += STEP
        if cnt >= need and abs(start - 0x3299B0) > 0x10000:
            return start
    return None

def parse(path):
    start = locate_table(path)
    if start is None: return []
    b = open(path, "rb").read(); recs = []; off = start
    for _ in range(200):
        if off + STEP > len(b): break
        v = struct.unpack_from("<9I", b, off); off += STEP
        if v[1] > 0x7FFFFFFF or v[7] > 0x7FFFFFFF: break
        recs.append(v)
    return recs

for tag, fn in SAMPLES:
    recs = parse(os.path.join(BASE, fn))
    cols = {k: Counter() for k in (3,4,5,6,8)}   # v3..v8 idx -> v[idx]
    for v in recs:
        for k in (3,4,5,6,8):
            cols[k][v[k]] += 1
    print(f"=== {tag} (n={len(recs)}) ===")
    for k in (3,4,5,6,8):
        c = cols[k]
        vals = list(c.keys())
        est_team = all(1 <= x <= 10000 for x in vals) and len(vals) > 5
        print(f"  v{k}: 唯一值={len(vals)} 范围[{min(vals)}-{max(vals)}] "
              f"{'<-候选俱乐部ID' if est_team else ''}")
        # 显示出现最多的几个
        top = c.most_common(6)
        print(f"       高频: {top}")
    # 是否某字段在单存档内恒定（候选玩家队/联赛）
    for k in (3,4,5,6,8):
        if len(cols[k]) == 1:
            print(f"  >> v{k} 全档恒定 = {list(cols[k].keys())[0]}  (可能是玩家队/联赛 ID)")
    print()
