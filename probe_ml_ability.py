#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_ability.py -- 用 EDIT 式 7-bit 能力值位打包特征(25 个连续 7-bit 值全∈[40,99])
在 ML/BL 未知区定位球员实例表 base/stride。不受 player_id 布局影响。

用法:
  python probe_ml_ability.py ML00000000            # 默认全文件, bit-start 0
  python probe_ml_ability.py ML00000000 0 1 2 3    # 试多个 bit-start
"""
import os, sys, array, collections
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")


def abil_ok(b, bitpos):
    """从 bitpos 起读 25 个 7-bit LSB-first 值，全部∈[40,99] 才为真（早退）。"""
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


def scan_bitstart(b, lo, hi, bs):
    offs = []
    for o in range(lo, hi - 30):
        if abil_ok(b, o * 8 + bs):
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


def main():
    stem = sys.argv[1] if len(sys.argv) > 1 else "ML00000000"
    bitstarts = [int(x) for x in sys.argv[2:]] or [0]
    path = os.path.join(DEC, stem + ".data")
    data = open(path, "rb").read()
    print(f"{stem}: size={len(data)} bitstarts={bitstarts}")
    for bs in bitstarts:
        offs = scan_bitstart(data, 0, len(data), bs)
        print(f"  bit-start={bs}: {len(offs)} 候选能力值块")
        if not offs:
            continue
        # 全局间隔众数 -> 候选 stride
        diffs = collections.Counter(offs[i + 1] - offs[i] for i in range(len(offs) - 1))
        top = diffs.most_common(8)
        print(f"    间隔 TOP8: {top}")
        for S, _ in top:
            if 100 <= S <= 1024:
                base, end, cnt = largest_chain(offs, S)
                if cnt >= 30:
                    print(f"    -> stride={S}B base=0x{base:X} end=0x{end:X} "
                          f"recs≈{cnt} size≈{cnt * S}B")
                    # dump 首条记录能力值 & 前若干字节
                    rec = data[base:base + S]
                    print(f"       rec0 hex={rec[:28].hex()}")


if __name__ == "__main__":
    main()
