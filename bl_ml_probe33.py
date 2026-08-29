#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe33.py — 在球队块中寻找「玩家队(my-team)」标志位。

球队块：0x100 起，步长 0x690，共 700 队。
思路：在每一 stride 内逐偏移扫描，找出「所有球队中恰有一队取某非默认值的字段」，
作为 my-team 候选标志（玩家队在此字段被置位/编号）。
同时列出 +0x598 预算非 0 的球队（真实有预算的俱乐部子集）。
"""
import os, struct

BASE = "decoded"
FN = "ML00000000.data"
STRIDE = 0x690
N_TEAM = 700
BASE_OFF = 0x100

b = open(os.path.join(BASE, FN), "rb").read()

# 收集每个 stride 内偏移处的「值集合」
from collections import defaultdict, Counter
field_counters = defaultdict(Counter)   # off -> Counter(value)
teams = []
for t in range(N_TEAM):
    off = BASE_OFF + t * STRIDE
    if off + STRIDE > len(b): break
    rec = b[off:off+STRIDE]
    teams.append(rec)
    for i in range(0, STRIDE, 4):
        val = struct.unpack_from("<I", rec, i)[0]
        field_counters[i][val] += 1

# 候选 A：某 4 字节字段恰有一个 team 取「唯一非零」值（且样本齐全 700）
candidates = []
for i in range(0, STRIDE, 4):
    c = field_counters[i]
    if len(c) >= 1 and len(teams) == N_TEAM:
        # 找「仅出现一次」的值
        singletons = [(v, n) for v, n in c.items() if n == 1]
        if len(singletons) == 1 and singletons[0][0] != 0:
            candidates.append((i, singletons[0][0]))

print(f"球队样本数={len(teams)}")
print("候选 my-team 标志（整 stride 内唯一非零、仅一队）：")
for off, val in sorted(candidates)[:30]:
    # 反查该值在哪一队
    for t, rec in enumerate(teams):
        if struct.unpack_from("<I", rec, off)[0] == val:
            print(f"  off=+0x{off:03X} val=0x{val:X} -> team#{t}")

# 候选 B：+0x598 预算非 0 的球队
print("\n+0x598 预算非 0 的球队（真实俱乐部子集）：")
cnt = 0
for t, rec in enumerate(teams):
    bud = struct.unpack_from("<I", rec, 0x598)[0]
    if bud != 0:
        cnt += 1
        if cnt <= 20:
            print(f"  team#{t}: budget_raw=0x{bud:08X} (= {bud})")
print(f"  总计 {cnt} 队有非空预算")
