#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe41: 在 ML 存档 (decoded/ML00000000.data) 中扫描 stride-312 球员表
(数据 240 + appearance 72), 名字在条目内 0x36 (UTF-8), 并测 f2_hi 覆盖率。
理论: ML 存档内嵌本宇宙球员库, 事件 f2_hi 应直接是该表 player id。
"""
import struct, os, csv

BASE = os.path.dirname(os.path.abspath(__file__))
ML = os.path.join(BASE, "decoded", "ML00000000.data")
b = open(ML, "rb").read()
N = len(b)

DATA, APPEAR, STRIDE = 240, 72, 312
NAME_OFF, NAME_LEN = 0x36, 61
SENTINEL = 0x80000000

def read_name(off):
    raw = b[off + NAME_OFF: off + NAME_OFF + NAME_LEN]
    z = raw.split(b"\x00", 1)[0]
    try:
        return z.decode("utf-8")
    except Exception:
        return z.decode("latin1", "replace")

# 扫描: 从各起点找 stride-312 且 dataID==appearRef 的最长连续段 (候选球员表)
def find_best_stride():
    best = 0; best_start = -1
    # 也尝试不以 0x7C 为起点的各种起点
    for start in range(0, 4_000_000, 4):
        cnt = 0; off = start
        while off + STRIDE <= N:
            pid = struct.unpack_from("<I", b, off)[0]
            aid = struct.unpack_from("<I", b, off + DATA)[0]
            if pid != 0 and pid == aid and pid < SENTINEL:
                cnt += 1
                off += STRIDE
            else:
                break
        if cnt > best:
            best = cnt; best_start = start
            if best > 20000:
                break
    return best, best_start

print("扫描 ML 存档中的 stride-312 球员表 (限前 4MB 起点)...")
best, best_start = find_best_stride()
print(f"最长连续段: count={best} @ {hex(best_start) if best_start>=0 else 'none'}")

id2name = {}
if best_start >= 0 and best > 1000:
    off = best_start
    while off + STRIDE <= N:
        pid = struct.unpack_from("<I", b, off)[0]
        aid = struct.unpack_from("<I", b, off + DATA)[0]
        if pid != 0 and pid == aid and pid < SENTINEL and pid not in id2name:
            id2name[pid] = read_name(off)
        off += STRIDE

vals = list(id2name.keys())
print(f"ML 球员表 (id->name) 条数: {len(id2name)}  范围: min={min(vals) if vals else None} max={max(vals) if vals else None}")

# 读事件表 f2_hi
csvp = os.path.join(BASE, "outputs", "event_table_clean.csv")
f2 = []
with open(csvp, encoding="utf-8") as f:
    r = csv.DictReader(f)
    for row in r:
        try:
            f2.append(int(row["f2_hi(player_id)"]))
        except (KeyError, ValueError):
            pass
f2 = [x for x in f2 if x != 0]
print(f"\n事件表 f2_hi: {len(f2)} 条, 范围 {min(f2)}..{max(f2)}")
present = [x for x in f2 if x in id2name]
print(f"f2_hi 命中 ML 球员表: {len(present)} / {len(f2)} = {100*len(present)/max(1,len(f2)):.1f}%")
if present:
    print("命中样本:")
    for x in present[:20]:
        print(f"   f2_hi={x} -> {id2name[x]!r}")
