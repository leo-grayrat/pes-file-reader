#!/usr/bin/env python3
# 验证 flat 口径 vs VA 段映射：比较 Raw 0x00a89c10（之前反汇编的位置）与 Raw 0xa89210
# （VA 0x00a89c10 经段表映射的真实位置），并 dump 真正的 vtable（VA 0x01C79698 -> Raw 0x1c78c98）。
import struct

EXE = 'resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe'
data = open(EXE, 'rb').read()

def qw(off):
    return struct.unpack('<Q', data[off:off+8])[0]

print('=== 比较 Raw 0x00a89c10 vs Raw 0xa89210（各前 32 字节）===')
a = data[0x00a89c10:0x00a89c10+32]
b = data[0xa89210:0xa89210+32]
print('Raw 0x00a89c10:', a.hex())
print('Raw 0xa89210 :', b.hex())
print('相同?', a == b)

print('\n=== 真正 vtable @ VA 0x01C79698 -> Raw 0x1c78c98 ===')
VT = 0x1c78c98
for i in range(48):
    p = qw(VT + i*8)
    kind = ''
    if p == 0:
        kind = '(null)'
    elif p >= len(data):
        kind = '(OOB)'
    else:
        code = data[p:p+2]
        if code in (b'\x55\x48', b'\x48\x89', b'\x40\x53', b'\x48\x83', b'\x53\x48', b'\x41\x54', b'\x48\x8b', b'\x4c\x8b', b'\x48\x89', b'\x41\x57'):
            kind = 'code?'
        else:
            kind = '?'
    mark = '  <== call [rdx+0x40] 目标 (entry 8)' if i*8 == 0x40 else ''
    print(f'  [{i:2d}] +{i*8:#04x}: {p:#010x}  {kind}{mark}')
