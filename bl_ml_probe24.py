#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe24.py — 跨样本解析 0x12a72fd 事件表，判断累积性与金额字段。"""
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
    gaps = [ds[i+1]-ds[i] for i in range(len(ds)-1) if 0 < ds[i+1]-ds[i] <= 0x2000]
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

def main():
    for name, p in FILES.items():
        b = load(p)
        recs, step = table(b, 0x12a72fd, 0x12a80e9)
        if not recs:
            print("%-14s : 无表（0 条）" % name)
            continue
        # 首末日期
        def date_of(r):
            raw = r[0]
            yy = raw & 0xFFFF
            mm = (raw >> 16) & 0xFF
            dd = (raw >> 24) & 0xFF
            return (yy, mm, dd)
        first = date_of(recs[0]); last = date_of(recs[-1])
        print("%-14s : 记录=%d 步长=0x%X  首%s 末%s" % (
            name, len(recs), step, first, last))
        # 金额候选：统计 f2(偏移对应 idx1)、f3(idx2)、f4(idx3) 中 ×100 后落 1e6~5e8 EUR 的数量
        for idx, label in [(1,"f1(+04)"),(2,"f2(+08)"),(3,"f3(+0C)"),(4,"f4(+10)")]:
            vals = [r[idx] for r in recs]
            money = sum(1 for v in vals if 1000 <= v <= 5_000_000)  # ×100 即 10万~5亿
            print("    %-8s 范围[%d, %d]  ×100∈[1e6,5e8]占比 %d/%d" % (
                label, min(vals), max(vals), money, len(vals)))
    # 打印 ML0 全部记录明细（前 40）
    b0 = load("decoded/ML00000000.data")
    recs0, _ = table(b0, 0x12a72fd, 0x12a80e9)
    print("\n=== ML0 事件表全 %d 条明细（date, f1,f2,f3,f4,f5,f6,f7,f8）===" % len(recs0))
    for i, r in enumerate(recs0):
        yy = r[0] & 0xFFFF; mm = (r[0]>>16)&0xFF; dd=(r[0]>>24)&0xFF
        print("  #%02d %d-%02d-%02d  %s" % (i, yy, mm, dd, r[1:]))

main()
