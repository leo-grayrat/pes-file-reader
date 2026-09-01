#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe23.py — 验证 0x12a72fd 表（步长 0x24，99 条）是否为交易/财务流水：
比较 in-season(ML0) 与 preseason(ML2) 同区域，preseason 应近乎空。
并完整 dump 记录内 9 个 u32 供判读字段含义。
"""
import struct

def load(p):
    with open(p, "rb") as f:
        return f.read()

def find_dates(b, lo, hi):
    out = []
    i = lo
    while i + 3 < hi:
        y = struct.unpack_from("<H", b, i)[0]
        if 0x07D8 <= y <= 0x07F4:
            m = b[i + 2]; d = b[i + 3]
            if 1 <= m <= 12 and 1 <= d <= 31:
                out.append(i)
        i += 1
    return out

def scan_table(b, lo, hi):
    ds = find_dates(b, lo, hi)
    if len(ds) < 10:
        return None
    gaps = [ds[i+1]-ds[i] for i in range(len(ds)-1) if 0 < ds[i+ 1]-ds[i] <= 0x2000]
    from collections import Counter
    if not gaps:
        return None
    step = Counter(gaps).most_common(1)[0][0]
    if step >= 0x400:
        return None
    recs = []
    pos = ds[0]
    while pos + 36 < hi:
        y = struct.unpack_from("<H", b, pos)[0]
        if not (0x07D8 <= y <= 0x07F4):
            break
        # 9 个 u32（date 占前 4 字节，后续 8 个字段）
        vals = [struct.unpack_from("<I", b, pos + k*4)[0] for k in range(9)]
        recs.append(vals)
        pos += step
    return recs, step

def main():
    b0 = load("decoded/ML00000000.data")
    b2 = load("decoded/ML00000002.data")
    r0 = scan_table(b0, 0x12a72fd, 0x12a80e9)
    r2 = scan_table(b2, 0x12a72fd, 0x12a80e9)
    if r0:
        recs0, step0 = r0
        print("ML0(in-season) 0x12a72fd: 记录数=%d 步长=0x%X" % (len(recs0), step0))
        print("  前 14 条 (date_u32, f1,f2,f3,f4,f5,f6,f7,f8)：")
        for v in recs0[:14]:
            print("   ", v)
    else:
        print("ML0 未在该区形成表")
    if r2:
        recs2, step2 = r2
        print("\nML2(preseason) 0x12a72fd: 记录数=%d 步长=0x%X" % (len(recs2), step2))
        for v in recs2[:6]:
            print("   ", v)
    else:
        print("\nML2(preseason): 该区无日期表（符合'赛季前无交易'预期）")

    # 字段统计：f2(idx4)/f3(idx5) 是否像金额×100
    if r0:
        f2 = [v[2] for v in recs0]; f3 = [v[3] for v in recs0]
        print("\n  f2(偏移+0x08) 范围: min=%d max=%d" % (min(f2), max(f2)))
        print("  f3(偏移+0x0C) 范围: min=%d max=%d" % (min(f3), max(f3)))
        print("  f2 中 可被100整除的比例: %d/%d" % (sum(1 for x in f2 if x % 100 == 0), len(f2)))

main()
