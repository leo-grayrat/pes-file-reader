#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_candidate.py -- 综合探针:
(A) 确认 0x2D7900 表记录间距(真实数据簇起点间隔)
(B) dump 队块#0 阵容后动态区(+0x2A0..+0x598) 找 condition/合约/球衣 数组
"""
import os, struct
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")


def main():
    b = open(os.path.join(DEC, "ML00000000.data"), "rb").read()
    # (A) 0x2D7900 表: 找真实数据簇起点(值不在{07F7FFFF,FFFFFFFF}且前驱是填充)
    LO, HI = 0x2D7900, 0x320000
    a = struct.unpack_from("<%dI" % ((HI - LO) // 4), b, LO)
    fill = {0x07F7FFFF, 0xFFFFFFFF}
    starts = []
    for i in range(1, len(a)):
        if a[i] not in fill and a[i - 1] in fill:
            starts.append(LO + i * 4)
    print(f"(A) 0x2D7900 表真实数据簇起点: 前12个")
    gaps = [starts[i] - starts[i - 1] for i in range(1, len(starts))]
    print("    起点:", [hex(x) for x in starts[:12]])
    print("    间隔:", [hex(g) for g in gaps[:11]])
    from collections import Counter
    print("    间隔众数:", Counter(gaps).most_common(5))

    # (B) 队块#0 动态区
    tb = 0x100
    print(f"\n(B) Team#0 动态区 @0x{tb+0x2A0:X}..0x{tb+0x598:X}")
    for off in range(tb + 0x2A0, tb + 0x598, 16):
        chunk = b[off:off + 16]
        u = [struct.unpack_from("<I", chunk, j)[0] for j in range(0, 16, 4)]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        print(f"  0x{off:X}: {u}  {asc}")
    # 扫描动态区 u8 in [0,7] (condition 候选) 连续>=4
    print("\n  condition候选(连续u8∈[0,7]>=4):")
    reg = b[tb + 0x2A0:tb + 0x598]
    run = 0; rs = 0
    for k, v in enumerate(reg):
        if 0 <= v <= 7:
            run += 1
            if run == 4:
                rs = k - 3
            if run >= 4 and (k == len(reg) - 1 or reg[k + 1] > 7):
                print(f"    0x{tb+0x2A0+rs:X}..0x{tb+0x2A0+k:X} vals={list(reg[rs:k+1])}")
                run = 0
        else:
            run = 0


if __name__ == "__main__":
    main()
