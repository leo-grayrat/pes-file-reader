#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""快速验证 BL/ML 存档是否同样高熵/加密（只读）。"""
import os
import math
import glob
import collections

BASE = os.path.dirname(os.path.abspath(__file__))
EX_DIR = os.path.join(BASE, "examples")


def entropy(data):
    c = collections.Counter(data)
    n = len(data)
    h = 0.0
    for v in c.values():
        p = v / n
        h -= p * math.log2(p)
    return h


def ascii_strings(b, minlen=5, maxn=30):
    res, cur, start = [], [], -1
    for i, x in enumerate(b):
        if 32 <= x < 127:
            if not cur:
                start = i
            cur.append(chr(x))
        else:
            if len(cur) >= minlen:
                res.append((start, "".join(cur)))
            cur = []
    if len(cur) >= minlen:
        res.append((start, "".join(cur)))
    return res[:maxn]


def check(name):
    path = os.path.join(EX_DIR, name)
    b = open(path, "rb").read()
    hdr = b[:32].hex()
    ss = ascii_strings(b)
    # 找前 1MB 与后 1MB 的明文迹象
    print(f"{name}: size={len(b)}  entropy={entropy(b):.6f}")
    print(f"  head32: {hdr}")
    print(f"  ascii_strings(>=5, first30): {ss}")


def main():
    bl = sorted(glob.glob(os.path.join(EX_DIR, "BL*")))
    ml = sorted(glob.glob(os.path.join(EX_DIR, "ML*")))
    print(f"BL files: {len(bl)}  ML files: {len(ml)}\n")
    for f in bl[:1]:
        check(os.path.basename(f))
    for f in ml[:1]:
        check(os.path.basename(f))

    # BL 样本间 diff / 共识
    if len(bl) >= 2:
        a = open(bl[0], "rb").read()
        b = open(bl[1], "rb").read()
        n = min(len(a), len(b))
        diff = sum(1 for i in range(n) if a[i] != b[i])
        same = sum(1 for i in range(n) if a[i] == b[i])
        print(f"\nBL[0] vs BL[1]: same={same} diff={diff} (diff%={100.0*diff/n:.2f})")
    if len(ml) >= 2:
        a = open(ml[0], "rb").read()
        b = open(ml[1], "rb").read()
        n = min(len(a), len(b))
        diff = sum(1 for i in range(n) if a[i] != b[i])
        print(f"ML[0] vs ML[1]: diff={diff} (diff%={100.0*diff/n:.2f})")


if __name__ == "__main__":
    main()