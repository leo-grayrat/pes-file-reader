#!/usr/bin/env python3
# PE 段表解析：把 VA 正确映射到文件偏移。此前 flat 口径(文件偏移=VA)对 .rdata 失效，
# 导致 vtable 在 0x01C79698 读出代码字节。本脚本给出各 section 的 VA<->Raw 映射，
# 并测试 0x00A89C10(代码, 之前反汇编成功) 与 0x01C79698(vtable 候选) 的真实文件偏移。
import struct

EXE = 'resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe'
data = open(EXE, 'rb').read()
print(f'exe size={len(data):#x}')

e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
print(f'e_lfanew={e_lfanew:#x}')
assert data[e_lfanew:e_lfanew+4] == b'PE\x00\x00', 'not PE'
coff = e_lfanew + 4
num_sec = struct.unpack('<H', data[coff+2:coff+4])[0]
opt_size = struct.unpack('<H', data[coff+16:coff+18])[0]
opt = e_lfanew + 24          # 可选头起点（修正：此前在 coff+24 多移了 4 字节）
magic = struct.unpack('<H', data[opt:opt+2])[0]
image_base = struct.unpack('<Q', data[opt+0x18:opt+0x20])[0] if magic == 0x20b else struct.unpack('<I', data[opt+0x1c:opt+0x20])[0]
print(f'num_sec={num_sec} opt_size={opt_size:#x} magic={magic:#x} image_base={image_base:#x}')

sec = opt + opt_size
sections = []
for i in range(num_sec):
    off = sec + i*40
    name = data[off:off+8].split(b'\x00')[0].decode('latin1', 'replace')
    vsize = struct.unpack('<I', data[off+8:off+12])[0]
    vaddr = struct.unpack('<I', data[off+12:off+16])[0]
    rsize = struct.unpack('<I', data[off+16:off+20])[0]
    raw = struct.unpack('<I', data[off+20:off+24])[0]
    sections.append((name, vaddr, vsize, raw, rsize))
    print(f'  {name:8s} VA={vaddr:#010x} VSize={vsize:#010x} Raw={raw:#010x} RawSize={rsize:#010x}')

def va_to_raw(va):
    for name, vaddr, vsize, raw, rsize in sections:
        if vaddr <= va < vaddr + max(vsize, rsize):
            return raw + (va - vaddr)
    return None

for va in [0x00A89C10, 0x01C79698, 0x1FE0E20, 0x00A8D8A0]:
    r = va_to_raw(va)
    print(f'VA {va:#010x} -> Raw {r if r is None else hex(r)}')
