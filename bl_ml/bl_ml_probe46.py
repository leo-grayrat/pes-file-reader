#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe46 (final): 用干净 EDIT id 集 + 0xde034 全扫 reg->db, 标注事件表 f2_hi。
输出 outputs/event_table_named.csv。
"""
import struct, os, csv

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
ML = os.path.join(BASE, "decoded", "ML00000000.data")
eb = open(EDIT, "rb").read(); EN = len(eb)
b = open(ML, "rb").read(); N = len(b)

def rname(buf, off):
    raw = buf[off + 0x36: off + 0x36 + 61]
    z = raw.split(b"\x00", 1)[0]
    try:
        return z.decode("utf-8")
    except Exception:
        return z.decode("latin1", "replace")

# EDIT 干净 id->name (stride-312, 0x7C 起)
edit_id2name = {}
off = 0x7C
while off + 312 <= EN:
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off + 240)[0]
    if pid != 0 and pid == aid and 1 <= pid <= 200000 and pid not in edit_id2name:
        edit_id2name[pid] = rname(eb, off)
    off += 312
eids = set(edit_id2name)
print(f"[EDIT] 干净 id->name: {len(eids)}, 范围 {min(eids)}..{max(eids)}")

# ML reg->db: 从 0xde034 全扫 stride-8, c 在 eids
reg2db = {}
o = 0xde034
while o + 8 <= N:
    a = struct.unpack_from("<I", b, o)[0]
    c = struct.unpack_from("<I", b, o + 4)[0]
    if c in eids and 1 <= a <= 400000:
        reg2db[a] = c
    o += 8
print(f"[ML reg] reg->db 条目: {len(reg2db)}")

# 标注事件表
csvp = os.path.join(BASE, "outputs", "event_table_clean.csv")
rows = []
with open(csvp, encoding="utf-8") as f:
    r = csv.DictReader(f)
    cols = r.fieldnames
    for row in r:
        rows.append(row)

direct = via = unres = 0
unres_samples = []
for row in rows:
    try:
        pid = int(row["f2_hi(player_id)"])
    except (KeyError, ValueError):
        pid = 0
    nm = ""
    if pid in eids:
        nm = edit_id2name[pid]; direct += 1
    elif pid in reg2db:
        nm = edit_id2name.get(reg2db[pid], ""); via += 1
    else:
        unres += 1
        if len(unres_samples) < 25:
            unres_samples.append(pid)
    row["name"] = nm

print(f"\n[事件表] 总 {len(rows)}")
print(f"  直接 db_id 命中: {direct}")
print(f"  经注册表命中:   {via}")
print(f"  已解析合计:     {direct+via} ({100*(direct+via)/len(rows):.1f}%)")
print(f"  未解析:         {unres}")
if unres_samples:
    print(f"  未解析样本: {unres_samples}")

out = os.path.join(BASE, "outputs", "event_table_named.csv")
with open(out, "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(cols) + ["name"])
    w.writeheader()
    for row in rows:
        w.writerow(row)
print(f"\n导出 -> {out}")
