#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_playertable.py -- 把 0x2D7900 区域按 3x0x07F7FFFF 分隔头切开, dump 各记录体原始字节+ASCII,
判读 ML 球员实例/注册表结构(是否含名字/id/动态字段)。
"""
import os, struct
BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")
SEP = b"\xff\xf7\xf7\x07\xff\xf7\xf7\x07\xff\xf7\xf7\x07"  # 3 x 0x07F7FFFF (LE)


def main():
    b = open(os.path.join(DEC, "ML00000000.data"), "rb").read()
    # 在 [0x2D7900, 0x320000] 找分隔头
    LO, HI = 0x2D7900, 0x320000
    seg = b[LO:HI]
    idxs = []
    i = seg.find(SEP)
    while i != -1 and i < len(seg) - 4:
        idxs.append(LO + i)
        i = seg.find(SEP, i + 1)
    print(f"在 0x{LO:X}..0x{HI:X} 找到分隔头 {len(idxs)} 个")
    for k, off in enumerate(idxs[:8]):
        body_start = off + len(SEP)
        body = b[body_start:body_start + 32]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in body)
        u32s = [struct.unpack_from("<I", body, j)[0] for j in range(0, min(28, len(body)), 4)]
        print(f"\n记录#{k} @0x{off:X} 体@0x{body_start:X}")
        print(f"  hex: {body.hex()}")
        print(f"  asc: {asc}")
        print(f"  u32: {u32s}")


if __name__ == "__main__":
    main()
