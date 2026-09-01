#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe43: 净化 EDIT 球员表 (最长连续 stride-312 主阵列), 构建注册索引->db_id->name 链,
标注 ML 事件表全部 f2_hi。
"""
import struct, os, csv

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
ML = os.path.join(BASE, "decoded", "ML00000000.data")
eb = open(EDIT, "rb").read(); EN = len(eb)
b = open(ML, "rb").read(); N = len(b)

DATA, APPEAR, STRIDE = 240, 72, 312
NAME_OFF, NAME_LEN = 0x36, 61
SENT = 0x80000000

def rname(buf, off):
    raw = buf[off + NAME_OFF: off + NAME_OFF + NAME_LEN]
    z = raw.split(b"\x00", 1)[0]
    try:
        return z.decode("utf-8")
    except Exception:
        return z.decode("latin1", "replace")

# --- A) 净化 EDIT: 找最长连续 stride-312 主阵列, 收集 (id,name) ---
def best_run(buf, n):
    best = 0; bs = -1; cur = 0; s = -1; off = 0x7C
    while off + STRIDE <= n:
        pid = struct.unpack_from("<I", buf, off)[0]
        aid = struct.unpack_from("<I", buf, off + DATA)[0]
        if pid != 0 and pid == aid and pid < SENT:
            if cur == 0: s = off
            cur += 1
        else:
            if cur > best: best = cur; bs = s
            cur = 0
        off += STRIDE
    if cur > best: best = cur; bs = s
    return best, bs

erun, ebase = best_run(eb, EN)
edit_id2name = {}
off = ebase
while off + STRIDE <= EN:
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off + DATA)[0]
    if pid != 0 and pid == aid and pid < SENT and pid not in edit_id2name:
        edit_id2name[pid] = rname(eb, off)
    off += STRIDE
eids = set(edit_id2name)
print(f"[EDIT] 主阵列 {erun} 条 @ {hex(ebase)}, 干净 id 数 {len(eids)}, 范围 {min(eids)}..{max(eids)}")

# --- B) ML 注册表: 在 0xde034 起找 stride-8 (reg, db), 要求 db 在 eids 中 ---
REG_BASE = 0xde034
# 收集 (reg=a, db=c) 候选: 仅当 c 在 eids
reg2db = {}
db2reg = {}
o = REG_BASE
while o + 8 <= N:
    a, c = struct.unpack_from("<II", b, o)
    if c in eids and a < SENT:
        reg2db[a] = c
        db2reg.setdefault(c, a)
    o += 8
print(f"[ML reg] 注册表条目 (db 命中 EDIT): {len(reg2db)}  (唯一 db: {len(db2reg)})")

# --- C) 事件表 f2_hi 标注 ---
csvp = os.path.join(BASE, "outputs", "event_table_clean.csv")
rows = []
with open(csvp, encoding="utf-8") as f:
    r = csv.DictReader(f)
    cols = r.fieldnames
    for row in r:
        rows.append(row)

named_direct = 0      # f2_hi 直接是 db_id
named_via_reg = 0     # f2_hi 是 reg_index -> db_id
unresolved = 0
unresolved_samples = []
for row in rows:
    try:
        pid = int(row["f2_hi(player_id)"])
    except (KeyError, ValueError):
        pid = 0
    nm = ""
    if pid in eids:
        nm = edit_id2name[pid]
        named_direct += 1
    elif pid in reg2db:
        db = reg2db[pid]
        nm = edit_id2name.get(db, "")
        named_via_reg += 1
    else:
        unresolved += 1
        if len(unresolved_samples) < 20:
            unresolved_samples.append(pid)
    row["name"] = nm

print(f"\n[事件表] 总 {len(rows)} 条")
print(f"  直接 db_id 命中: {named_direct}")
print(f"  经注册表命中:   {named_via_reg}")
print(f"  未解析:         {unresolved}")
if unresolved_samples:
    print(f"  未解析样本: {unresolved_samples}")

# 导出带名字的最终事件表
out = os.path.join(BASE, "outputs", "event_table_named.csv")
with open(out, "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(cols) + ["name"])
    w.writeheader()
    for row in rows:
        w.writerow(row)
print(f"\n导出 -> {out}")

# 命中样本
print("\n== 直接命中样本 ==")
d = 0
for row in rows:
    if row["name"] and d < 10:
        try:
            if int(row["f2_hi(player_id)"]) in eids:
                print(f"  f2_hi={row['f2_hi(player_id)']} -> {row['name']!r}"); d += 1
        except: pass
print("== 经注册表命中样本 ==")
v = 0
for row in rows:
    if row["name"] and v < 10:
        try:
            if int(row["f2_hi(player_id)"]) in reg2db and int(row["f2_hi(player_id)"]) not in eids:
                print(f"  f2_hi={row['f2_hi(player_id)']} -> {row['name']!r}"); v += 1
        except: pass
