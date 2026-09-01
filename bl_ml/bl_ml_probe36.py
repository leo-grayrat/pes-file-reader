#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe36 - 提取 ML 存档内的「球员注册表」(registration table) 第一跳，
并验证 val -> 数据库球员 ID (0x100000 + val) 的猜想是否自洽。

背景 (route A 调查结论):
- 事件表 f2_hi (10000-60000) 是存档内部的 *注册 ID* (registration id)，
  不是全局数据库球员 ID (后者 >= 1048576 = 0x100000)。
- 名字真正在 EDIT 数据库 Player.bin (240B/条) 里，与存档分离。
- 存档内注册表位于 0xde034 一带: stride 8, [u32 reg_id][u32 val]。
- 若 db_id = 0x100000 + val，则 reg_id -> db_id -> (Player.bin) -> name 可闭合。
  本脚本只验证前两步 (reg_id -> val -> db_id 是否在存档中被引用)。
"""
import struct, csv, sys

SAVE = "decoded/ML00000000.data"
OUT = "outputs/reg_table_ML0.csv"

def main():
    b = open(SAVE, "rb").read()
    N = len(b)

    # --- 1) 定位注册表: 扫描 stride-8 且 id 严格递增的密集长阵列 ---
    REG_LO, REG_HI = 10000, 60000
    best = (0, 0, 0)  # (start_off, end_off, count)
    off = 0
    prev_id = -1
    run_start = None
    run_count = 0
    while off + 8 <= N:
        i0, i1 = struct.unpack_from("<II", b, off)
        if REG_LO <= i0 <= REG_HI and i0 > prev_id:
            if run_start is None:
                run_start = off
                run_count = 1
            else:
                run_count += 1
            prev_id = i0
            off += 8
            continue
        else:
            if run_count > best[2]:
                best = (run_start, off, run_count)
            run_start = None
            run_count = 0
            prev_id = -1
            off += 4  # 错位继续，避免漏掉非对齐起点
    if run_count > best[2]:
        best = (run_start, off, run_count)

    base, end, cnt = best
    print(f"最长严格递增 stride-8 注册表段: @ {hex(base)}  {cnt} 条")

    if cnt < 50:
        print("未找到足够长的注册表 (可能本存档注册球员少，或结构不同)")
        # 仍输出找到的段
    pairs = []
    o = base
    while o + 8 <= end:
        i0, i1 = struct.unpack_from("<II", b, o)
        pairs.append((i0, i1))
        o += 8
    print(f"提取 {len(pairs)} 条, id {pairs[0][0]}..{pairs[-1][0]}")

    # --- 2) 验证 val -> db_id = 0x100000 + val 是否在存档中被引用 ---
    db_hits = 0
    db_present = []
    for reg_id, val in pairs:
        db_id = 0x100000 + val
        # 在整文件搜该 db_id 是否作为 u32 出现 (说明存档引用了该数据库球员)
        if b.find(struct.pack("<I", db_id)) != -1:
            db_hits += 1
            if len(db_present) < 10:
                db_present.append((reg_id, val, db_id))
    print(f"val->db_id 在存档中被引用的比例: {db_hits}/{len(pairs)}")
    for r, v, d in db_present:
        print(f"  reg={r} val={v} -> db_id={d} (0x{d:x}) PRESENT")

    # --- 3) 输出注册表 CSV (reg_id, val, hypothesized_db_id) ---
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["reg_id", "val", "hyp_db_id"])
        for reg_id, val in pairs:
            w.writerow([reg_id, val, 0x100000 + val])
    print(f"写出 {OUT} ({len(pairs)} 条)")

if __name__ == "__main__":
    main()
