#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe22.py — 分析候选日期块的记录步长，并提取 date 邻近字段，判断是否流水明细。"""
import struct

def load():
    with open("decoded/ML00000000.data", "rb") as f:
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

def analyze(b, lo, hi, label):
    ds = find_dates(b, lo, hi)
    if len(ds) < 10:
        print("[%s] 命中过少 %d，跳过" % (label, len(ds)))
        return
    gaps = [ds[i+1]-ds[i] for i in range(len(ds)-1)]
    # 过滤异常大间距，取众数
    good = [g for g in gaps if 0 < g <= 0x2000]
    from collections import Counter
    cnt = Counter(good)
    mode_gap, mode_n = cnt.most_common(1)[0] if good else (0, 0)
    print("\n=== %s @ 0x%X~0x%X  命中%d  众数间距 0x%X(%d次) ===" % (
        label, lo, hi, len(ds), mode_gap, mode_n))
    # 用众数间距重组记录：从第一个 date 起按 mode_gap 取样
    if mode_gap and mode_gap < 0x400:
        base = ds[0]
        recs = []
        pos = base
        while pos + 4 < hi:
            y = struct.unpack_from("<H", b, pos)[0]
            if not (0x07D8 <= y <= 0x07F4):
                break
            # 提取 date 周围 6 个 u32（前后各 2）
            before = [struct.unpack_from("<I", b, pos-8)[0] if pos-8>=0 else 0,
                      struct.unpack_from("<I", b, pos-4)[0] if pos-4>=0 else 0]
            after  = [struct.unpack_from("<I", b, pos+4)[0],
                      struct.unpack_from("<I", b, pos+8)[0],
                      struct.unpack_from("<I", b, pos+12)[0],
                      struct.unpack_from("<I", b, pos+16)[0]]
            recs.append((y, b[pos+2], b[pos+3], before, after))
            pos += mode_gap
        print("  重组记录数: %d" % len(recs))
        for r in recs[:12]:
            y,m,d,before,after = r
            print("    date %d-%02d-%02d  before=%s  after=%s" % (
                y, m, d, before, [("%d" % v) for v in after]))

def main():
    b = load()
    # 候选块（排除赛程表 0x3299B0~0xA8D350）
    blocks = [
        ("blk_a8d6d8", 0xa8d6d8, 0xa92c9c),
        ("blk_aac8a8", 0xaac8a8, 0xab76ec),
        ("blk_acb7b4", 0xacb7b4, 0xacc61c),
        ("blk_be3140", 0xbe3140, 0xbe47b4),
        ("blk_be5fd8", 0xbe5fd8, 0xbe638c),
        ("blk_be8b88", 0xbe8b88, 0xbecfe8),
        ("blk_125f95d", 0x125f95d, 0x125febd),
        ("blk_12a72fd", 0x12a72fd, 0x12a80e9),
    ]
    for name, lo, hi in blocks:
        analyze(b, lo, hi, name)

main()
