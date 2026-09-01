#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PES2021 回放文件深度分析：熵分析 + 全样本共识(恒定字节)分析（只读）。"""
import os
import glob
import math
import collections

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REP_DIR = os.path.join(BASE, "examples", "rep")


def entropy(data):
    counter = collections.Counter(data)
    n = len(data)
    h = 0.0
    for c in counter.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def main():
    files = sorted(glob.glob(os.path.join(REP_DIR, "REPLAY*")))
    print(f"== 共 {len(files)} 个回放样本 ==")

    # 1) 熵分析
    print("\n== 各样本香农熵 (bits/byte, 8.0=纯随机) ==")
    for f in files[:8]:
        d = open(f, "rb").read()
        print(f"{os.path.basename(f)}: {entropy(d):.6f}")

    # 分块熵：看头部/尾部熵是否一致
    print("\n== 分块熵 (0x00-0xFF 等 4 块) ==")
    d0 = open(files[0], "rb").read()
    step = len(d0) // 4
    for k in range(4):
        seg = d0[k * step: (k + 1) * step]
        print(f"block{k} [{k*step:08X}-{(k+1)*step:08X}): {entropy(seg):.6f}")

    # 2) 共识分析：所有样本恒定字节位置
    print("\n== 全样本恒定字节共识分析 ==")
    base = open(files[0], "rb").read()
    same = bytearray([1]) * len(base)  # 占位
    same = [1] * len(base)
    for f in files[1:]:
        d = open(f, "rb").read()
        if len(d) != len(base):
            print(f"  警告: {os.path.basename(f)} 大小不符 {len(d)}")
            continue
        for i in range(len(base)):
            if same[i] and d[i] != base[i]:
                same[i] = 0

    total_same = sum(same)
    print(f"总计恒定字节: {total_same} / {len(base)} ({100.0*total_same/len(base):.4f}%)")

    # 恒定 run 输出
    runs = []
    i = 0
    while i < len(base):
        if same[i]:
            j = i
            while j < len(base) and same[j]:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    print(f"恒定 run 数量: {len(runs)}")
    for s, e in runs[:200]:
        chunk = base[s:min(e, s + 16)]
        hexv = " ".join(f"{x:02X}" for x in chunk)
        print(f"  [{s:08X}, {e:08X}) len={e-s:6d}  {hexv}")


if __name__ == "__main__":
    main()