#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""补充探测：头部偏移指针、球队区之后区块布局。"""
import struct

b = open("decoded/BL00000000.data", "rb").read()
n = len(b)


def u32(o):
    return struct.unpack_from("<I", b, o)[0]


print("=== 头部原始字节 0x90~0xA4 ===")
print(' '.join(f"{x:02X}" for x in b[0x90:0xA4]))
try:
    print("ASCII:", b[0x90:0xA4].decode("latin1"))
except Exception as e:
    print(e)

print("\n=== 0x194000 偏移处内容 ===")
for off in (0x194000, 0x194010, 0x194020):
    print(f"  +{off:08X}:", ' '.join(f"{x:02X}" for x in b[off:off+32]))

print("\n=== 球队区结束 0x11F2C0 之后 ===")
for off in (0x11F2C0, 0x11F300, 0x120000, 0x130000):
    print(f"  +{off:08X}:", ' '.join(f"{x:02X}" for x in b[off:off+32]))

print("\n=== 头部中大数值(疑似偏移指针) ===")
for o in range(0x4C, 0x64, 4):
    v = u32(o)
    if 0 < v < n:
        head = ' '.join(f"{x:02X}" for x in b[v:v+16])
        print(f"  +{o:03X} = 0x{v:08X} ({v}) -> {head}")

print("\n=== data 尾部 64 字节 ===")
print(' '.join(f"{x:02X}" for x in b[n-64:]))