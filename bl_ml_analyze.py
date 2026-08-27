#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML(一球成名/大师联赛) 解密 data 块的结构逆向分析脚本。"""
import os
import sys
import struct
from collections import Counter

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")


def load(name):
    return open(os.path.join(DEC, name), "rb").read()


def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]


def u16(b, off):
    return struct.unpack_from("<H", b, off)[0]


def ascii_strings(b, minlen=4, min_print=3):
    """提取可打印 ASCII 串(过滤掉纯数字/连续递增这类伪文本)。"""
    res = []
    cur, start = [], -1
    for i, x in enumerate(b):
        if 32 <= x < 127:
            if not cur:
                start = i
            cur.append(chr(x))
        else:
            if len(cur) >= minlen:
                s = "".join(cur)
                if sum(c.isalpha() for c in s) >= min_print:
                    res.append((start, s))
            cur = []
    return res


def utf16le_strings(b, minlen=3):
    """提取 UTF-16LE 字符串(英文字母间会有 0x00 分隔)。"""
    res = []
    cur, start = [], -1
    i = 0
    while i + 1 < len(b):
        ch = u16(b, i)
        if 0x20 <= ch < 0x2000:
            if not cur:
                start = i
            cur.append(chr(ch) if ch < 0x80 else "?")
            i += 2
        else:
            if len(cur) >= minlen:
                res.append((start, "".join(cur)))
            cur = []
            i += 1
    return res


def diff_change_runs(a, b, limit=None):
    """返回两文件差异位置的连续 run（用于定位动态 vs 固定区）。"""
    n = min(len(a), len(b))
    runs = []
    i = 0
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    if limit:
        total = sum(e - s for s, e in runs)
        return runs[:limit], total, n
    return runs


def main():
    print("=" * 70)
    print("一、data 头部结构 (前 80 字节, 每 4 字节一个 uint32)")
    print("=" * 70)
    for name, label in [("BL00000000.data", "BL"), ("ML00000000.data", "ML")]:
        b = load(name)
        print(f"\n[{label}] 大小={len(b)}")
        for i in range(20):
            v = u32(b, i * 4)
            print(f"  +{i*4:03X}  {i:2d}: {v:10d}  0x{v:08X}")

    print("\n" + "=" * 70)
    print("二、ASCII 字符串落点 (BL 前 40 个, 带偏移)")
    print("=" * 70)
    b0 = load("BL00000000.data")
    for off, s in ascii_strings(b0)[:40]:
        print(f"  0x{off:08X}  {s!r}")

    print("\n" + "=" * 70)
    print("三、BL00000000 vs BL00000001 差异 run (前 30 个) + 变化率")
    print("=" * 70)
    b1 = load("BL00000001.data")
    runs, total, n = diff_change_runs(b0, b1, 30)
    print(f"总变化字节 {total}/{n} = {100.0*total/n:.2f}%")
    for s, e in runs:
        print(f"  [{s:08X}, {e:08X})  len={e-s:8d}")

    print("\n" + "=" * 70)
    print("四、ML00000000 vs ML00000013 差异 run (前 30 个) + 变化率")
    print("=" * 70)
    m0 = load("ML00000000.data")
    m13 = load("ML00000013.data")
    mruns, mtotal, mn = diff_change_runs(m0, m13, 30)
    print(f"总变化字节 {mtotal}/{mn} = {100.0*mtotal/mn:.2f}%")
    for s, e in mruns:
        print(f"  [{s:08X}, {e:08X})  len={e-s:8d}")


if __name__ == "__main__":
    main()