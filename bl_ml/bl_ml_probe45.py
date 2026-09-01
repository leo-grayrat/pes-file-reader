#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe45 (fast): 用布尔数组 + 滑动窗口求和, 在 ML 存档中定位 stride-8
注册表 (c 列命中 EDIT id 最密集的连续区域)。
"""
import struct, os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EDIT = os.path.join(BASE, "decoded", "EDIT00000000.data")
ML = os.path.join(BASE, "decoded", "ML00000000.data")
eb = open(EDIT, "rb").read(); EN = len(eb)
b = open(ML, "rb").read(); N = len(b)
SENT = 0x80000000

# EDIT 合法 id
edit_ids = set()
off = 0x7C
while off + 312 <= EN:
    pid = struct.unpack_from("<I", eb, off)[0]
    aid = struct.unpack_from("<I", eb, off + 240)[0]
    if pid != 0 and pid == aid and 1 <= pid <= 200000:
        edit_ids.add(pid)
    off += 312
print(f"EDIT 合法 id 数: {len(edit_ids)}")

# 建 hit 数组: hit[i] = 1 若 stride-8 第 i 个位置的 c(第二 u32) 在 edit_ids
n8 = N // 8
hit = bytearray(n8)
for i in range(n8):
    o = i * 8 + 4
    c = struct.unpack_from("<I", b, o)[0]
    if c in edit_ids:
        hit[i] = 1

# 滑动窗口 (长度 WIN 个 stride-8 位置) 最大和
WIN = 2000
best = 0; best_i = -1
cur = sum(hit[0:WIN])
if cur > best: best = cur; best_i = 0
for i in range(1, n8 - WIN + 1):
    cur += hit[i + WIN - 1] - hit[i - 1]
    if cur > best:
        best = cur; best_i = i

print(f"最密集区域: stride-8 索引 {best_i} (文件偏移 0x{best_i*8:x}), 命中 {best}/{WIN} = {100*best/WIN:.1f}%")
print(f"  对应文件偏移范围: 0x{best_i*8:x} .. 0x{(best_i+WIN)*8:x}")

# 从 best_i 起抽取 reg->db (c 在 edit_ids 且 a 合理), 直到密度跌破
reg2db = {}
i = best_i
taken = 0
while i < n8 and taken < 60000:
    o = i * 8
    a = struct.unpack_from("<I", b, o)[0]
    c = struct.unpack_from("<I", b, o + 4)[0]
    if c in edit_ids and 1 <= a <= 400000:
        reg2db[a] = c
        taken += 1
    else:
        if taken > 2000:
            break
    i += 1
print(f"抽取 reg->db: {len(reg2db)} 条; a 范围 {min(reg2db)}..{max(reg2db)}")

out = os.path.join(BASE, "outputs", "ml_reg2db.csv")
with open(out, "w", encoding="utf-8") as f:
    f.write("reg_index,db_id\n")
    for a in sorted(reg2db):
        f.write(f"{a},{reg2db[a]}\n")
print(f"导出 -> {out}")
