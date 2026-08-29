#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe40: 建立 EDIT id->name 映射 (UTF-8 正确解码), 并测试与 ML 事件表 f2_hi 的交集覆盖度。
若覆盖度高, 说明 f2_hi 就是数据库球员 ID, route A 直接闭合。
"""
import struct, os, csv

BASE = os.path.dirname(os.path.abspath(__file__))
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
b = open(EDIT, "rb").read()
N = len(b)

DATA, APPEAR, STRIDE = 240, 72, 312
BASE_OFF, NAME_OFF, NAME_LEN = 0x7C, 0x36, 61
SENTINEL = 0x80000000

def read_name(off):
    raw = b[off + NAME_OFF: off + NAME_OFF + NAME_LEN]
    z = raw.split(b"\x00", 1)[0]
    try:
        return z.decode("utf-8")
    except Exception:
        return z.decode("latin1", "replace")

# 建立 id->name (排除 0 与哨兵)
id2name = {}
off = BASE_OFF
while off + STRIDE <= N:
    pid = struct.unpack_from("<I", b, off)[0]
    aid = struct.unpack_from("<I", b, off + DATA)[0]
    if pid != 0 and pid == aid and pid != SENTINEL and pid not in id2name:
        id2name[pid] = read_name(off)
    off += STRIDE

vals = list(id2name.keys())
print(f"EDIT 有效 (id->name) 条数: {len(id2name)}")
print(f"EDIT id 范围: min={min(vals)} max={max(vals)}")

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
print(f"\n事件表 f2_hi 条数: {len(f2)}  范围: min={min(f2)} max={max(f2)}")

# 交集
present = [x for x in f2 if x in id2name]
missing = [x for x in f2 if x not in id2name]
print(f"f2_hi 命中 EDIT 数据库: {len(present)} / {len(f2)}  = {100*len(present)/max(1,len(f2)):.1f}%")
print(f"未命中(可能哨兵/越界): {len(missing)}")
if missing:
    print("  未命中样本:", sorted(set(missing))[:20])

# 展示命中的前若干事件及其名字
print("\n== 命中样本 (事件 -> 球员名) ==")
shown = 0
for x in f2:
    if x in id2name and shown < 25:
        print(f"  f2_hi={x}  ->  {id2name[x]!r}")
        shown += 1

# 导出完整的 事件表+名字 标注 CSV
out = os.path.join(BASE, "outputs", "event_table_named.csv")
with open(out, "w", encoding="utf-8") as f:
    f.write("save,kind,idx,date,f1,f2_lo,f2_hi(player_id),f3,f4,f5,f6,f7,f8,v1,v2,v3,v4,v5,v6,v7,v8,name\n")
    with open(csvp, encoding="utf-8") as fin:
        r = csv.DictReader(fin)
        for row in r:
            try:
                pid = int(row["f2_hi(player_id)"])
            except (KeyError, ValueError):
                pid = 0
            nm = id2name.get(pid, "")
            f.write(",".join([
                row.get("save",""), row.get("kind",""), row.get("idx",""), row.get("date",""),
                row.get("f1",""), row.get("f2_lo",""), row.get("f2_hi(player_id)",""),
                row.get("f3",""), row.get("f4",""), row.get("f5",""), row.get("f6",""),
                row.get("f7",""), row.get("f8",""), row.get("v1",""), row.get("v2",""),
                row.get("v3",""), row.get("v4",""), row.get("v5",""), row.get("v6",""),
                row.get("v7",""), row.get("v8",""), nm
            ]) + "\n")
print(f"\n导出带名字的事件表 -> {out}")
