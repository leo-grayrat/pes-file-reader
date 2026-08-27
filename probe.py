#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PES2021 存档回放文件初探脚本（只读，不修改任何样例文件）。"""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
REP_DIR = os.path.join(BASE, "examples", "rep")


def hexdump(b, offset=0, length=512, width=16):
    out = []
    for i in range(0, length, width):
        chunk = b[offset + i: offset + i + width]
        if not chunk:
            break
        hexpart = " ".join(f"{x:02X}" for x in chunk)
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append(f"{offset + i:08X}  {hexpart:<{width*3}}  {asc}")
    return "\n".join(out)


def strings(b, minlen=4, maxn=300):
    res = []
    cur = []
    start = -1
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


def diff_files(path_a, path_b, limit=80):
    a = open(path_a, "rb").read()
    b = open(path_b, "rb").read()
    n = min(len(a), len(b))
    diffs = []
    for i in range(n):
        if a[i] != b[i]:
            diffs.append((i, a[i], b[i]))
    return diffs[:limit], len(diffs)


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "REPLAY00000000"
    path = os.path.join(REP_DIR, name)
    b = open(path, "rb").read()
    print(f"== file: {name}  size={len(b)} bytes (0x{len(b):X}) ==\n")
    print("== first 512 bytes ==")
    print(hexdump(b, 0, 512))
    print("\n== last 256 bytes ==")
    print(hexdump(b, len(b) - 256, 256))
    print("\n== ASCII strings (first 300, len>=4) ==")
    for off, s in strings(b):
        print(f"{off:08X}  {s!r}")

    # 与相邻样本 diff
    if len(sys.argv) > 2:
        path_b = os.path.join(REP_DIR, sys.argv[2])
    else:
        path_b = os.path.join(REP_DIR, "REPLAY00000001")
    if os.path.exists(path_b):
        diffs, total = diff_files(path, path_b)
        print(f"\n== diff vs {os.path.basename(path_b)}: total {total} differing bytes ==")
        for off, va, vb in diffs:
            print(f"{off:08X}  {va:02X} -> {vb:02X}")


if __name__ == "__main__":
    main()