#!/usr/bin/env python3
# 实证校验「exe 静态推导的 300B 槽布局」vs「数据侧 §1.6 读到的 12B 头 + 20×i16 + 248B blob」
# 纯只读：只读取已解密 data 块，不碰运行时内存。
import struct, sys, glob

FILES = sorted(glob.glob('decoded/rep_REPLAY*.data'))
if not FILES:
    print('no decoded replay data'); sys.exit(1)
fn = FILES[0]
data = open(fn, 'rb').read()
print(f'file={fn} len={len(data):#x} (expect 0x51EC60)')

ROSTER = 0x3AA0
FRAME = 8112
f0 = data[ROSTER:ROSTER+FRAME]
print(f'frame0 head16={f0[:16].hex()}')
print(f'frame0 state[0x10:0x20]={f0[0x10:0x20].hex()}')
ev0 = f0[0x1010:0x1010+4000]
print(f'event region head16={ev0[:16].hex()}')

# 数据侧 §1.6：事件区 = 16B 子头 + 10 槽 × 300；个别帧 11 槽
sub = ev0[:16]
print(f'subhead u16s={struct.unpack("<8H", sub)}')

# 试两种「槽起点」假设：
#  A) 数据侧：10 个连续 300B 槽，紧接 16B 子头
#  B) 扫描 event region 找 byte0 的 3+3+2 位域合理的槽（静态布局：槽起点 byte0 是位域）
def iter_slots(base, stride=300, n=10):
    for i in range(n):
        s = ev0[base + i*stride : base + i*stride + stride]
        yield i, s

print('\n=== 假设 A：10 槽紧接 16B 子头 (base=16) ===')
for i, s in iter_slots(16, n=10):
    b0 = s[0]
    lo3 = b0 & 7; mid3 = (b0>>3)&7; hi2 = (b0>>6)&3
    b1 = s[1]; b2 = s[2]
    u16_e = struct.unpack('<H', s[0x0E:0x10])[0]   # getter2 返回字 @+0xE
    u16_8 = struct.unpack('<H', s[0x08:0x0A])[0]   # getter8 返回字 @+8
    sent_a8 = struct.unpack('<H', s[0xa8:0xaa])[0] # 构造器哨兵 word @+0xa8
    head12 = s[:12].hex()
    sent124 = struct.unpack('<H', s[0x124:0x126])[0]
    print(f'slot{i}: b0={b0:#04x}(lo3={lo3},mid3={mid3},hi2={hi2}) b1={b1:#04x} b2={b2:#04x} '
          f'u16@E={u16_e:#06x} u16@8={u16_8:#06x} sent@a8={sent_a8:#06x} sent@124={sent124:#06x} head12={head12}')

# 静态布局关键判定：构造器在 slot+0xa8 写 0x7fff 哨兵(word)，slot+0x124 写 0(dword)，
# slot+0x110 写 0(byte)。若真实数据在这些偏移保留 0x7fff / 0，则静态 300B 映射坐实。
print('\n=== 扫描整段 event region 找 0xa8 处 = 0x7fff 的 300B 对齐槽（定位真实槽起点） ===')
hits = []
for off in range(0, len(ev0)-300, 1):
    sent = struct.unpack('<H', ev0[off+0xa8:off+0xa8+2])[0]
    if sent == 0x7fff:
        hits.append(off)
print(f'0x7fff@a8 命中数={len(hits)} 前20={hits[:20]}')
# 也试 0x7fff 在 slot+0xa8 但槽起点对齐 300 网格（base 未知，先扫任意偏移）
# 若 hits 恰好是 16 + 300*k 模式，则说明 base=16 假设成立
