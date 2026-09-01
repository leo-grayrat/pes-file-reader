#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_condition.py -- 全文件扫描 per-player 动态表的扁平签名:
- u8 长程 [0,7]   (状态 condition 0-7)
- u8 长程 [0,100] (状态/表单 百分比)
- u16 长程 [0,7]  (状态 存为 u16)
- u16 长程 [0,100]
报告 >=100 元素的连续段位置(可能就是全局 per-player 表)。
"""
import os, struct
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")
TB_OFF = 0x100
TB_SIZE = 0x690
N_TEAMS = 700


def in_teamblock(off):
    if TB_OFF <= off < TB_OFF + N_TEAMS * TB_SIZE:
        return (off - TB_OFF) // TB_SIZE
    return None


def runs_u8(d, lo, hi, minlen):
    res = []
    run = 0; rs = 0
    for i, v in enumerate(d):
        if lo <= v <= hi:
            if run == 0:
                rs = i
            run += 1
        else:
            if run >= minlen:
                res.append((rs, i, run))
            run = 0
    if run >= minlen:
        res.append((rs, len(d), run))
    return res


def runs_u16(d, lo, hi, minlen):
    res = []
    n = len(d) // 2
    run = 0; rs = 0
    for i in range(n):
        v = struct.unpack_from("<H", d, i*2)[0]
        if lo <= v <= hi:
            if run == 0:
                rs = i*2
            run += 1
        else:
            if run >= minlen:
                res.append((rs, i*2, run))
            run = 0
    return res


def main():
    d = open(os.path.join(DEC, "ML00000000.data"), "rb").read()
    print(f"ML00000000 size={len(d)}")
    for tag, (lo, hi, minlen, fn) in {
        "u8[0,7]": (0, 7, 200, runs_u8),
        "u8[0,100]": (0, 100, 200, runs_u8),
        "u16[0,7]": (0, 7, 200, runs_u16),
        "u16[0,100]": (0, 100, 200, runs_u16),
    }.items():
        runs = fn(d, lo, hi, minlen)
        print(f"\n[{tag}] 长程(>={minlen})段数={len(runs)}")
        for st, en, ln in sorted(runs, key=lambda r: -r[2])[:12]:
            tb = in_teamblock(st)
            loc = f"队块#{tb}" if tb is not None else "队块外"
            print(f"  0x{st:X}..0x{en:X} len={ln} ({loc})")


if __name__ == "__main__":
    main()
