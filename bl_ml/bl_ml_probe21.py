#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe21.py — 在 ML 解码存档中扫描"日期三元组"密集区（排除已知赛程表 0x3299B0）。

日期三元组（文档 1.6）：u16 年(0x07D8~0x07F4=2008~2036) + u8 月(1..12) + u8 日(1..31)。
若转会/工资流水带日期，会表现为与赛程表不同的密集块。
"""
import struct

PATH = "decoded/ML00000000.data"
# 已知赛程表范围（13000 * 0x254 槽，含少量哨兵）
SCHED_BASE = 0x3299B0
SCHED_END = 0x3299B0 + 13000 * 0x254

def main():
    with open("decoded/ML00000000.data", "rb") as f:
        b = f.read()
    n = len(b)

    # 收集所有日期三元组位置
    hits = []
    i = 0
    while i + 3 < n:
        y = struct.unpack_from("<H", b, i)[0]
        if 0x07D8 <= y <= 0x07F4:
            m = b[i + 2]
            d = b[i + 3]
            if 1 <= m <= 12 and 1 <= d <= 31:
                # 额外约束：年份后通常不是 0（避免误判普通整数）
                hits.append(i)
                i += 1
            else:
                i += 1
        else:
            i += 1

    print("总日期三元组命中: %d" % len(hits))

    # 聚类：相邻命中间距 < 0x400 视为同一块
    clusters = []
    cur = []
    for h in sorted(hits):
        if cur and h - cur[-1] > 0x400:
            clusters.append(cur)
            cur = []
        cur.append(h)
    if cur:
        clusters.append(cur)

    # 排除赛程表块，报告其余密集块
    print("\n=== 候选日期块（排除赛程表 0x%X~0x%X）===" % (SCHED_BASE, SCHED_END))
    shown = 0
    for c in clusters:
        lo, hi = c[0], c[-1]
        if SCHED_BASE <= lo and hi <= SCHED_END:
            continue  # 赛程表跳过
        if len(c) >= 20:  # 较密集才报告
            print("  块 [%s ~ %s] 命中%d 个, span=0x%X, 步进众数=" % (
                hex(lo), hex(hi), len(c), hi - lo))

    # 估算候选块的步长：相邻命中间距直方图（排除赛程表）
    from collections import Counter
    gaps = Counter()
    for c in clusters:
        if SCHED_BASE <= c[ 0] and c[-1] <= SCHED_END:
            continue
        for a, bb in zip(c, c[1:]):
            g = bb - a
            if g > 0 and g <= 0x2000:
                gaps[g] += 1
    print("\n=== 非赛程表日期命中 步长直方图（前 12）===")
    for g, cnt in gaps.most_common(12):
        print("  间距 0x%X (%d) : %d 次" % (g, g, cnt))

if __name__ == "__main__":
    main()
