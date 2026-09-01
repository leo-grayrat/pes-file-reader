#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe42: 提取 ML 存档 (decoded/ML00000000.data) 中 0xde034 附近的 stride-8
(reg_id, val) 注册表, 并测试两列是否能映射到 EDIT 数据库 id (从而拿到名字)。
"""
import struct, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ML = os.path.join(BASE, "decoded", "ML00000000.data")
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
b = open(ML, "rb").read()
N = len(b)
eb = open(EDIT, "rb").read()
EN = len(eb)

# EDIT id 集合 (stride-312 提取)
SENT = 0x80000000
edit_ids = set()
off = 0x7C
while off + 312 <= EN:
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off + 240)[0]
    if pid != 0 and pid == aid and pid < SENT:
        edit_ids.add(pid)
    off += 312
print(f"EDIT 有效 id 数: {len(edit_ids)}")

# 提取 0xde034 注册表 (stride 8, 两 u32)
base = 0xde034
reg = []
o = base
# 取一段 (到文件尾或断掉)
while o + 8 <= N:
    a, c = struct.unpack_from("<II", b, o)
    reg.append((a, c))
    o += 8
    if len(reg) >= 60000:
        break
print(f"从 0xde034 起提取 stride-8 对: {len(reg)}")

# 看 reg 中 (a,c) 连续递增情况
# 找 a 连续递增的最长段
best = 0; bs = -1; cur = 0; s = -1
for i, (a, c) in enumerate(reg):
    if i == 0 or reg[i][0] == reg[i-1][0] + 1:
        if cur == 0: s = i
        cur += 1
    else:
        if cur > best: best = cur; bs = s
        cur = 0
if cur > best: best = cur; bs = s
print(f"a 列连续递增最长段: {best} @ index {bs}")
if bs >= 0:
    a0 = reg[bs][0]; a1 = reg[bs + best - 1][0]
    print(f"  a 范围: {a0}..{a1}")
    print(f"  c 样本 (前10): {[reg[bs+k][1] for k in range(10)]}")
    print(f"  c 范围: {min(reg[bs+k][1] for k in range(best))}..{max(reg[bs+k][1] for k in range(best))}")

# 测试: 取连续段, 看 a 或 c 是否落在 edit_ids
if bs >= 0:
    seg_a = [reg[bs + k][0] for k in range(best)]
    seg_c = [reg[bs + k][1] for k in range(best)]
    a_in = sum(1 for x in seg_a if x in edit_ids)
    c_in = sum(1 for x in seg_c if x in edit_ids)
    print(f"\n连续段 a 列命中 EDIT: {a_in}/{best} = {100*a_in/max(1,best):.1f}%")
    print(f"连续段 c 列命中 EDIT: {c_in}/{best} = {100*c_in/max(1,best):.1f}%")

# 也测: 整个 reg 表的 a 列 / c 列 命中 edit
all_a = set(a for a, c in reg)
all_c = set(c for a, c in reg)
print(f"\n整表 a 列命中 EDIT: {len(all_a & edit_ids)}/{len(all_a)}")
print(f"整表 c 列命中 EDIT: {len(all_c & edit_ids)}/{len(all_c)}")
print(f"a 列范围: {min(all_a)}..{max(all_a)}")
print(f"c 列范围: {min(all_c)}..{max(all_c)}")
