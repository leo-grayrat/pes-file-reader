#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe47: 分类事件表未命名的 175 条 f2_hi。
目标：搞清楚这些 f2_hi 是 (a) EDIT 中漏提的 db_id、(b) ML 注册表没抓全的 reg_index、
还是 (c) 真正的默认库球员（需要默认 Player.bin）。
全程只用已解密存档，不碰加密包。
"""
import struct, os, csv

BASE = os.path.dirname(os.path.abspath(__file__))
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

# ---- EDIT 干净 id->name (stride-312, 0x7C 起) ----
edit_id2name = {}
off = 0x7C
while off + 312 <= EN:
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off + 240)[0]
    if pid != 0 and pid == aid and 1 <= pid <= 200000 and pid not in edit_id2name:
        edit_id2name[pid] = rname(eb, off)
    off += 312
eids = set(edit_id2name)
print(f"[EDIT] 干净 id 数: {len(eids)}, 范围 {min(eids)}..{max(eids)}")

# 把 EDIT 全部合法 id 也建一个“是否作为球员 id 出现”的快速存在性集合（同上 eids）

# ---- 完整 ML reg->db (stride-8, 不过滤 c in eids) ----
reg_all = {}          # a -> c  (不过滤)
reg_editonly = {}     # 仅 c in eids (复现 probe46 口径)
o = 0xde034
while o + 8 <= N:
    a = struct.unpack_from("<I", b, o)[0]
    c = struct.unpack_from("<I", b, o + 4)[0]
    if 1 <= a <= 400000 and 1 <= c <= 200000:
        reg_all[a] = c
        if c in eids:
            reg_editonly[a] = c
    o += 8
print(f"[ML reg] 完整 reg->db: {len(reg_all)} (a 范围 {min(reg_all)}..{max(reg_all)})")
print(f"[ML reg] 仅 c in eids: {len(reg_editonly)}")

# ---- 未命名事件 f2_hi ----
csvp = os.path.join(BASE, "outputs", "event_table_named.csv")
U = []
all_f2 = []
with open(csvp, encoding="utf-8") as f:
    for row in csv.DictReader(f):
        try:
            pid = int(row["f2_hi(player_id)"])
        except (KeyError, ValueError):
            pid = 0
        all_f2.append(pid)
        if not row["name"].strip():
            U.append(pid)
print(f"\n[事件表] 总 f2_hi: {len(all_f2)}, 未命名: {len(U)}")
print(f"[未命名] 值范围: {min(U)}..{max(U)}")

# ---- 分类 ----
cat_direct_edit = []   # u 直接在 EDIT id 集（漏提？）
cat_reg_in_edit = []   # u 是 reg_index, 其 db_id 在 EDIT（注册表没抓全？）
cat_reg_needs_pbin = [] # u 是 reg_index, 其 db_id 不在 EDIT（需默认 Player.bin）
cat_default_db = []     # u 既不在 EDIT 也不在完整 reg 键集 → 默认 db_id 直引
cat_other = []

for u in U:
    if u in eids:
        cat_direct_edit.append(u)
    elif u in reg_all:
        db = reg_all[u]
        if db in eids:
            cat_reg_in_edit.append((u, db))
        else:
            cat_reg_needs_pbin.append((u, db))
    else:
        cat_default_db.append(u)

print("\n===== 分类结果 =====")
print(f"A. 直接在 EDIT id 集（疑似漏提）: {len(cat_direct_edit)}")
print(f"B. 是 reg_index 且 db_id 在 EDIT（注册表没抓全）: {len(cat_reg_in_edit)}")
print(f"C. 是 reg_index 但 db_id 不在 EDIT（需默认 Player.bin）: {len(cat_reg_needs_pbin)}")
print(f"D. 既非 EDIT 也非 reg 键（默认 db_id 直引，需默认 Player.bin）: {len(cat_default_db)}")
total = len(cat_direct_edit)+len(cat_reg_in_edit)+len(cat_reg_needs_pbin)+len(cat_default_db)
print(f"合计: {total} (应=175)")

# 若 B 或 A 非空，说明现有提取可改进，无需 Player.bin 即可提升覆盖率
fixable = len(cat_direct_edit) + len(cat_reg_in_edit)
needs_pbin = len(cat_reg_needs_pbin) + len(cat_default_db)
print(f"\n可仅靠现有数据修复（A+B）: {fixable}")
print(f"必须默认 Player.bin（C+D）: {needs_pbin}")

if cat_reg_in_edit:
    print("\nB 样例 (f2_hi -> db_id):", cat_reg_in_edit[:10])
if cat_reg_needs_pbin:
    print("\nC 样例 (f2_hi -> db_id):", cat_reg_needs_pbin[:10])
if cat_default_db:
    print("\nD 样例:", cat_default_db[:15])
if cat_direct_edit:
    print("\nA 样例:", cat_direct_edit[:15])
