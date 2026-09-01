#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe25.py — 深化 0x12a72fd 事件表：字段语义、金额闭合、环形缓冲验证。"""
import struct
from collections import Counter

FILES = {
    "ML0(in-season)": "decoded/ML00000000.data",
    "ML1(in-season)": "decoded/ML00000001.data",
    "ML13(in-season)": "decoded/ML00000013.data",
    "ML2(preseason)": "decoded/ML00000002.data",
}

def load(p):
    with open(p, "rb") as f:
        return f.read()

def find_dates(b, lo, hi):
    out = []
    i = lo
    while i + 3 < hi:
        y = struct.unpack_from("<H", b, i)[0]
        if 0x07D8 <= y <= 0x07F4:
            m = b[i+2]; d = b[i+3]
            if 1 <= m <= 12 and 1 <= d <= 31:
                out.append(i)
        i += 1
    return out

def table(b, lo, hi):
    ds = find_dates(b, lo, hi)
    if len(ds) < 10:
        return [], 0
    gaps = [ds[i+ 1]-ds[i] for i in range(len(ds)-1) if 0 < ds[i+1]-ds[i] <= 0x2000]
    if not gaps:
        return [], 0
    step = Counter(gaps).most_common(1)[0][0]
    if step >= 0x400:
        return [], 0
    recs = []
    pos = ds[0]
    while pos + 36 < hi:
        y = struct.unpack_from("<H", b, pos)[0]
        if not (0x07D8 <= y <= 0x07F4):
            break
        vals = [struct.unpack_from("<I", b, pos + k*4)[0] for k in range(9)]
        recs.append(vals)
        pos += step
    return recs, step

def signed(v):
    return v - 0x100000000 if v >= 0x80000000 else v

def main():
    for name, p in FILES.items():
        b = load(p)
        recs, step = table(b, 0x12a72fd, 0x12a80e9)
        if not recs:
            print("%-14s : 无表" % name); continue
        def d(r): 
            return (r[0]&0xFFFF,(r[0]>>16)&0xFF,(r[0]>>24)&0xFF)
        # 日期严格递增？
        dates = [d(r) for r in recs]
        inc = all(((dates[i][0],dates[i][1],dates[i][2]) < (dates[i+1][0],dates[i+1][1],dates[i+1][2])) for i in range(len(dates)-1))
        # f4 金额统计（无符号 + 有符号）
        f4 = [r[4] for r in recs]
        f4_signed = [signed(v) for v in f4]
        f4_full = sum(1 for v in f4 if v == 0xFFFFFFFF)
        f4_plausible = sum(1 for v in f4 if 1000 <= v <= 5_000_000)
        f4_neg = sum(1 for v in f4_signed if v < 0 and v != -1)
        # f3 金额统计
        f3 = [r[3] for r in recs]
        f3_plausible = sum(1 for v in f3 if 1000 <= v <= 5_000_000)
        # f6 / f5 空值（0xFFFFFFFF）
        f6_null = sum(1 for r in recs if r[6] == 0xFFFFFFFF)
        f5_null = sum(1 for r in recs if r[5] == 0xFFFFFFFF)
        # f2 唯一性
        f2 = [r[2] for r in recs]
        f2_unique = len(set(f2))
        # f1 / f7 取值
        f1c = Counter(r[1] for r in recs)
        f7c = Counter(r[7] for r in recs)
        print("%-14s 记录=%d 递增=%s" % (name, len(recs), inc))
        print("   f4(+10) 空(0xFFFFFFFF)=%d  落在金额区间=%d/%d  有符号负且非-1=%d  总和(×100)=%d亿" % (
            f4_full, f4_plausible, len(f4), f4_neg, sum(f4)//100//1_0000_0000))
        print("   f3(+0C) 落在金额区间=%d/%d" % (f3_plausible, len(f3)))
        print("   f5空=%d f6空=%d  f2唯一=%d/%d" % (f5_null, f6_null, f2_unique, len(f2)))
        print("   f1分布=%s  f7分布=%s" % (dict(f1c), dict(f7c)))
        # f7=1 时 f6 是否恒为空
        f7one_f6null = sum(1 for r in recs if r[7]==1 and r[6]==0xFFFFFFFF)
        f7one_total = sum(1 for r in recs if r[7]==1)
        print("   f7==1 且 f6空: %d/%d" % (f7one_f6null, f7one_total))

main()
