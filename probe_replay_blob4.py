#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REPLAY 248B blob 四探（验证）：blob[144:192] uint16 逐帧轨迹 + 尾部常量/零确认。"""
import struct
from collections import Counter

SEG_OFF = 0x3AA0
EVT_FRAME = 8112
EVT_TBL = 4112
BLOB_OFF_IN_SLOT = 52
BLOB_LEN = 248


def load(name):
    with open(f"decoded/{name}.data", "rb") as f:
        return f.read()


def slot_starts(area):
    out = []
    for j in range(2, len(area) - 1):
        if area[j] == 1 and area[j - 1] == 0 and area[j - 2] == 0 and 2 <= area[j + 1] <= 40:
            out.append(j)
    return out


def main():
    b = load("REPLAY00000000")
    ev = b[SEG_OFF:]
    blobs = []
    for k in range(660):
        area = ev[k * EVT_FRAME + EVT_TBL: k * EVT_FRAME + EVT_FRAME]
        m12 = next((m for m in slot_starts(area) if area[m + 1] == 12), None)
        if m12 is None:
            continue
        blob = area[m12 + BLOB_OFF_IN_SLOT: m12 + BLOB_OFF_IN_SLOT + BLOB_LEN]
        if len(blob) == BLOB_LEN:
            blobs.append(blob)

    # blob[144:192] = 24 uint16, 逐帧打印 帧0,1,2,3,100,659
    print("=== blob[144:192] 24×uint16 逐帧（帧0,1,2,3,100,659）===")
    for k in (0, 1, 2, 3, 100, 659):
        us = [struct.unpack("<H", blobs[k][144 + i:144 + i + 2])[0] for i in range(0, 48, 2)]
        print(f"  帧{k:3d}: " + " ".join(f"{v:5d}" for v in us))

    # 逐偏移（24 个 uint16）跨帧值域，标出常量 vs 变化
    print("\n=== 24 个 uint16 逐偏移跨帧 min/max/是否常量 ===")
    const_offs = []
    for i in range(0, 48, 2):
        col = [struct.unpack("<H", blobs[k][144 + i:144 + i + 2])[0] for k in range(len(blobs))]
        mn, mx = min(col), max(col)
        isc = (mn == mx)
        if isc:
            const_offs.append(144 + i)
        print(f"  +{144+i:3d}: min={mn:5d} max={mx:5d} {'常量' if isc else '变化'}")

    # 尾部常量/零确认
    print("\n=== 尾部 blob[192:248] ===")
    magic = Counter(blobs[k][192:196].hex() for k in range(len(blobs)))
    print(f"  blob[192:196] 跨帧取值分布: {dict(magic)}")
    zero_offs = [o for o in range(196, 248) if all(bl[o] == 0 for bl in blobs)]
    print(f"  blob[196:248] 全零偏移: {zero_offs[0]}..{zero_offs[-1]} (共 {len(zero_offs)}B, 总52B)")


if __name__ == "__main__":
    main()
