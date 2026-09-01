#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""probe_ml_firstrec.py -- 验证 ML/BL 是否在 0x7C 镜像 EDIT 球员能力值表(stride 312)。

复用 EDIT 的 7-bit 能力值位解包，对比 EDIT/ML/BL 首条记录(id/名字/能力值范围)，
判断 ML/BL 是否含独立的能力值表，以及动态字段可能叠加在何处。
"""
import os, struct, csv
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")

ABIL = [(0x0E, 0, 7), (0x0E, 7, 7), (0x10, 0, 7), (0x10, 7, 7), (0x11, 6, 7),
        (0x12, 5, 7), (0x14, 0, 7), (0x14, 7, 7), (0x15, 6, 7), (0x16, 5, 7),
        (0x18, 0, 7), (0x18, 7, 7), (0x19, 6, 7), (0x1A, 5, 7), (0x1C, 0, 7),
        (0x1C, 7, 7), (0x1D, 6, 7), (0x1E, 5, 7), (0x20, 0, 7), (0x24, 0, 7),
        (0x24, 7, 7), (0x25, 6, 7), (0x28, 0, 7), (0x2C, 6, 7), (0x2D, 5, 7)]


def rf(rec, byte, bit, length):
    start = byte * 8 + bit
    v = 0
    for i in range(length):
        s = start + i
        if (rec[s >> 3] >> (s & 7)) & 1:
            v |= (1 << i)
    return v


def decode_abilities(rec):
    return [rf(rec, byte, bit, length) for (byte, bit, length) in ABIL]


def show(path, base=0x7C, stride=312, n=3):
    b = open(path, "rb").read()
    print(f"=== {os.path.basename(path)} (len={len(b)}) base=0x{base:X} stride={stride} ===")
    for k in range(n):
        off = base + k * stride
        if off + 0x40 > len(b):
            break
        pid = struct.unpack_from("<I", b, off)[0]
        name = b[off + 0x36:off + 0x36 + 61].split(b"\x00")[0].decode("utf-8", "replace")
        ab = decode_abilities(b[off:off + 0x30])
        mn, mx = (min(ab), max(ab)) if ab else (0, 0)
        ok = all(40 <= x <= 99 for x in ab)
        print(f"  rec#{k} @0x{off:X} pid={pid} name={name!r} "
              f"abil[{len(ab)}] range=[{mn},{mx}] all40-99={ok}")


def main():
    for stem in ["EDIT00000000", "ML00000000", "BL00000000"]:
        p = os.path.join(DEC, stem + ".data")
        if os.path.exists(p):
            show(p)


if __name__ == "__main__":
    main()
