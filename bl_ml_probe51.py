#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe51: 用 v5_hi/v6_hi（注册索引）+ v4_lo（直接 db?）扩事件表名字覆盖。
关键点：v5/v6 是模板固定的注册索引，但**各档注册表不同**，必须按 src 用对应档的
reg 表（0xde034 锚点）解析。
输出 outputs/event_table_named_full.csv（追加 v5_name/v6_name/v4_name/v8_name 列）
+ 覆盖率对比。
"""
import csv, os, struct
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))

# ---- EDIT 名表 ----
eb = open(os.path.join(BASE, "decoded", "EDIT00000000.data"), "rb").read()
def rn(buf, off):
    return buf[off+0x36: off+0x36+61].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
id2name = {}
off = 0x7C
while off + 312 <= len(eb):
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off+240)[0]
    if pid and pid == aid and 1 <= pid <= 200000 and pid not in id2name:
        id2name[pid] = rn(eb, off)
    off += 312

# ---- 各档 reg 表（0xde034 锚点全扫）----
def load_reg(src):
    fname = {"ML0": "ML00000000", "ML1": "ML00000001", "ML13": "ML00000013"}[src]
    b = open(os.path.join(BASE, "decoded", fname + ".data"), "rb").read()
    reg = {}
    o = 0xde034
    while o + 8 <= len(b):
        a = struct.unpack_from("<I", b, o)[0]
        c = struct.unpack_from("<I", b, o+4)[0]
        if 1 <= a <= 400000 and 1 <= c <= 200000:
            reg[a] = c
        o += 8
    return reg

def n(r, k):
    try: return int(r[k])
    except (KeyError, ValueError): return None

rows = list(csv.DictReader(open(os.path.join(BASE, "outputs", "event_table_named.csv"),
                                encoding="utf-8")))
regs = {s: load_reg(s) for s in ["ML0", "ML1", "ML13"]}
for s, rg in regs.items():
    print(f"{s}: reg 条目 {len(rg)}")

# ---- 解析 ----
f2c = v5c = v6c = v4c = v8c = 0
f2v5diff = 0
rows_out = []
for r in rows:
    src = r["src"]
    reg = regs[src]
    # f2_hi（修正：排除 65535 哨兵；直接命中 EDIT 或经本档 reg）
    pid = n(r, "f2_hi(player_id)") or 0
    f2n = ""
    if pid and pid != 65535:
        f2n = id2name.get(pid, "")
        if not f2n:
            db = reg.get(pid)
            if db:
                f2n = id2name.get(db, "")
    if f2n: f2c += 1
    # v5_hi -> reg -> db -> name
    h5 = n(r, "v5") >> 16
    db5 = reg.get(h5)
    v5n = id2name.get(db5, "") if db5 else ""
    if v5n: v5c += 1
    # v6_hi（哨兵 65535 跳过）
    h6 = n(r, "v6") >> 16
    db6 = reg.get(h6) if h6 != 65535 else None
    v6n = id2name.get(db6, "") if db6 else ""
    if v6n: v6c += 1
    # v4_lo（直接 db?）
    l4 = n(r, "v4") & 0xFFFF
    v4n = id2name.get(l4, "")
    if v4n: v4c += 1
    # v8_lo
    l8 = n(r, "v8") & 0xFFFF
    v8n = id2name.get(l8, "")
    if v8n: v8c += 1

    anyn = f2n or v5n or v6n or v4n or v8n
    if v5n and f2n and v5n != f2n:
        f2v5diff += 1
    r2 = dict(r)
    r2.update({"name": f2n, "v5_name": v5n, "v6_name": v6n, "v4_name": v4n, "v8_name": v8n,
               "any_name": anyn})
    rows_out.append(r2)

T = len(rows)
print(f"\n=== 名字来源命中率（297 行）===")
print(f"f2_hi:        {f2c} ({f2c/T:.1%})  <- route A 既有")
print(f"v5_hi->reg:   {v5c} ({v5c/T:.1%})  <- 新来源")
print(f"v6_hi->reg:   {v6c} ({v6c/T:.1%})  <- 新来源")
print(f"v4_lo:        {v4c} ({v4c/T:.1%})  <- 新候选")
print(f"v8_lo:        {v8c} ({v8c/T:.1%})  <- 新候选")
union = sum(1 for r2 in rows_out if r2["any_name"])
print(f"\n行级覆盖（≥1 个名字）：{union}/{T} = {union/T:.1%}  (route A 为 {f2c/T:.1%})")
print(f"v5 名字与 f2 名字不同（同行为两个不同球员）：{f2v5diff} 行")

out = os.path.join(BASE, "outputs", "event_table_named_full.csv")
with open(out, "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows_out[0].keys()))
    w.writeheader()
    for r2 in rows_out:
        w.writerow(r2)
print(f"\n导出 -> {out}（{len(rows_out)} 行）")
