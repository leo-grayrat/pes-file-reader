#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe26.py — 提取 700 队口号槽与队名，验证 off-by-one 错位假说。"""
import struct

PATH = "decoded/ML00000000.data"
SLOTS = [(0x55, "c0"), (0x65, "c1"), (0x75, "c2"), (0x85, "c3")]

def load(p):
    with open(p, "rb") as f:
        return f.read()

def strz(b, off, n=64):
    s = b[off:off+n]
    end = s.find(b"\x00")
    if end < 0:
        end = n
    try:
        return s[:end].decode("ascii", "replace")
    except Exception:
        return ""

def main():
    b = load(PATH)
    out = []
    recs = []
    for i in range(700):
        base = 0x100 + i * 0x690
        name = strz(b, base + 0x5E4, 32)
        abbr = strz(b, base + 0x62A, 8)
        chants = [(lab, strz(b, base + o, 16)) for o, lab in SLOTS]
        recs.append((i, name, abbr, chants))
    # 打印全部
    for i, name, abbr, chants in recs:
        cs = " | ".join("%s=%s" % (lab, t) for lab, t in chants)
        out.append("%3d  %-14s [%-4s]  %s" % (i, name[:14], abbr, cs))
    txt = "\n".join(out)
    with open("outputs/chant_check.txt", "w", encoding="utf-8") as f:
        f.write(txt)
    print("wrote outputs/chant_check.txt with %d teams" % len(recs))
    # 单独打印含"阿斯顿"的队及其邻居
    for i, name, abbr, chants in recs:
        if "阿斯顿" in name or "阿森" in name:
            lo = max(0, i-2); hi = min(700, i+3)
            print("\n--- 命中 index %d (%s) 邻域 ---" % (i, name))
            for j in range(lo, hi):
                nm, ab, ch = recs[j][1], recs[j][2], recs[j][3]
                cs = " | ".join("%s=%s" % (l, t) for l, t in ch)
                print("%3d  %-14s [%-4s]  %s" % (j, nm[:14], ab, cs))

main()
