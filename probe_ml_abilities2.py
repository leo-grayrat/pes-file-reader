#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_abilities2.py -- 在 ML/BL 中定位能力值表，覆盖多种存储假设:
  7-bit LSB 打包(bit-start 0..7, EDIT 字段序) 与 8-bit(每能力 1 字节, 25 连续字节∈[40,99])。
  找到后按候选 stride 聚链定位 base/记录数。
"""
import os, sys, collections
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")


def abil7_ok(b, bitpos):
    for i in range(25):
        s = bitpos + i * 7
        v = 0
        for j in range(7):
            bb = s + j
            if (b[bb >> 3] >> (bb & 7)) & 1:
                v |= (1 << j)
        if not (40 <= v <= 99):
            return False
    return True


def scan7(b, lo, hi, bs):
    return [o for o in range(lo, hi - 30) if abil7_ok(b, o * 8 + bs)]


def scan8(b, lo, hi):
    offs = []
    for o in range(lo, hi - 25):
        ok = True
        for j in range(25):
            v = b[o + j]
            if not (40 <= v <= 99):
                ok = False
                break
        if ok:
            offs.append(o)
    return offs


def largest_chain(hit_offsets, stride):
    posset = set(hit_offsets)
    best = (0, 0, 0)
    for st in hit_offsets:
        if (st - stride) in posset:
            continue
        cnt = 1
        cur = st
        while (cur + stride) in posset:
            cur += stride
            cnt += 1
        if cnt > best[2]:
            best = (st, cur, cnt)
    return best


def report(stem, offs, label):
    if not offs:
        print(f"  [{label}] 0 候选")
        return
    diffs = collections.Counter(offs[i + 1] - offs[i] for i in range(len(offs) - 1))
    print(f"  [{label}] 候选 {len(offs)}  间隔 TOP6: {diffs.most_common(6)}")
    for S, _ in diffs.most_common(12):
        if 80 <= S <= 4096:
            base, end, cnt = largest_chain(offs, S)
            if cnt >= 30:
                print(f"    -> stride={S}B base=0x{base:X} end=0x{end:X} "
                      f"recs≈{cnt} size≈{cnt * S}B")


def main():
    stem = sys.argv[1] if len(sys.argv) > 1 else "ML00000000"
    path = os.path.join(DEC, stem + ".data")
    b = open(path, "rb").read()
    print(f"{stem}: size={len(b)}")
    print("  7-bit EDIT序 bit-start 0..7:")
    for bs in range(8):
        report(stem, scan7(b, 0, len(b), bs), f"7bit bs={bs}")
    print("  8-bit (25连续字节∈[40,99]):")
    report(stem, scan8(b, 0, len(b)), "8bit")


if __name__ == "__main__":
    main()
