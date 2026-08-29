#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe44: 确认 EDIT 文件球员 ID 上限, 并正确抽取 ML 注册表默认球员连续块。
判断: 注册表 db_id 超出 EDIT 覆盖 (65000-143544) 是否为覆盖缺口的根因。
"""
import struct, os

BASE = os.path.dirname(os.path.abspath(__file__))
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
ML = os.path.join(BASE, "decoded", "ML00000000.data")
eb = open(EDIT, "rb").read(); EN = len(eb)
b = open(ML, "rb").read(); N = len(b)
DATA, APPEAR, STRIDE = 240, 72, 312
SENT = 0x80000000

# EDIT: 全文件扫描 stride-312, 收集合法 dataID (dataID==appearRef, 且 1<=id<=200000 排除垃圾)
edit_ids = set()
off = 0x7C
while off + STRIDE <= EN:
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off + DATA)[0]
    if pid != 0 and pid == aid and 1 <= pid <= 200000:
        edit_ids.add(pid)
    off += STRIDE
print(f"[EDIT] 合法 player id 数: {len(edit_ids)}  范围 {min(edit_ids)}..{max(edit_ids)}")
print(f"       其中 >65000 的: {sum(1 for x in edit_ids if x>65000)}")
print(f"       其中 >100000 的: {sum(1 for x in edit_ids if x>100000)}")

# ML 注册表: 从 0xde034 取 (a,c). 找默认球员连续块:
# 规则: a 在 [1, 70000] 且连续递增(允许小跳空), c 在 [1, 200000]
REG_BASE = 0xde034
reg = []
o = REG_BASE
while o + 8 <= N:
    a, c = struct.unpack_from("<II", b, o)
    reg.append((a, c))
    o += 8
    if len(reg) >= 80000:
        break

# 找最长 "a 递增且 c 合法" 的段
best = 0; bs = -1; cur = 0; s = -1; prev_a = None
for i, (a, c) in enumerate(reg):
    if 1 <= a <= 200000 and 1 <= c <= 200000:
        if prev_a is None or a == prev_a + 1 or a == prev_a:  # 允许相等(重复)或+1
            if cur == 0: s = i
            cur += 1
            prev_a = a
        else:
            if cur > best: best = cur; bs = s
            cur = 1; s = i; prev_a = a
    else:
        if cur > best: best = cur; bs = s
        cur = 0; prev_a = None
if cur > best: best = cur; bs = s
print(f"\n[ML reg] 默认球员连续块最长: {best} 条 @ index {bs}")
if bs >= 0:
    a0 = reg[bs][0]
    db_vals = [reg[bs + k][1] for k in range(best)]
    print(f"   a(注册索引) 范围: {a0}..{reg[bs+best-1][0]}")
    print(f"   c(db_id) 范围: {min(db_vals)}..{max(db_vals)}")
    in_edit = sum(1 for x in db_vals if x in edit_ids)
    print(f"   c(db_id) 命中 EDIT: {in_edit}/{best} = {100*in_edit/best:.1f}%")
    print(f"   c > 65000 且不在 EDIT: {sum(1 for x in db_vals if x>65000 and x not in edit_ids)}")

# 整张注册表: 所有 (a,c) 中 c 在 edit_ids 的, 建立 reg->db
reg2db = {a: c for a, c in reg if c in edit_ids and 1 <= a <= 200000}
print(f"\n[ML reg] reg->db (c 在 EDIT) 共 {len(reg2db)} 条")
