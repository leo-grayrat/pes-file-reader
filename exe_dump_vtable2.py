#!/usr/bin/env python3
# 修正 vtable 路线：ReplayFrame 构造器 0x00A89C35 的 `lea rax,[rip+0x1bcea5c]`
# 真实 vtable 地址 = 0x00A89C3C + 0x01bcea5c = 0x01C79698（此前误当绝对地址 0x1bcea5c 导致失败）。
# 纯只读 dump 该 vtable 的方法指针（每个 8 字节），识别 +0x40 条目（call [rdx+0x40] 的目标）。
import struct

EXE = 'resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe'
VT = 0x01C79698
data = open(EXE, 'rb').read()
print(f'exe size = {len(data):#x}')

def rva_to_off(rva):
    # flat image: 文件偏移即地址（与 exe_dis_func.py 口径一致）
    return rva

def qword_at(rva):
    off = rva_to_off(rva)
    return struct.unpack('<Q', data[off:off+8])[0]

print(f'\n=== vtable @ {VT:#010x} ===')
N = 48
for i in range(N):
    ent = VT + i*8
    p = qword_at(ent)
    # 判定是否像代码指针：非 0、在 exe 范围、且指向的 8 字节看起来像函数序言(55 48 / 48 89 / 40 53 / 48 83 ...)
    kind = ''
    if p == 0:
        kind = '(null)'
    elif p >= len(data):
        kind = '(OOB)'
    else:
        b = data[p:p+2]
        if b in (b'\x55\x48', b'\x48\x89', b'\x40\x53', b'\x48\x83', b'\x53\x48', b'\x41\x54', b'\x48\x8b', b'\x4c\x8b'):
            kind = 'code?'
        else:
            kind = '?'
    mark = '  <-- call [rdx+0x40] 目标 (entry 8)' if i*8 == 0x40 else ''
    print(f'  [{i:2d}] +{i*8:#04x}: {p:#010x}  {kind}{mark}')
