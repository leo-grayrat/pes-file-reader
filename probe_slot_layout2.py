#!/usr/bin/env python3
# 扫描事件区找 §1.6 的槽标记 "00 00 01 XX"(XX 在 2..40)，定位真实槽起点与间距。
import struct, glob, sys

fn = sorted(glob.glob('decoded/rep_REPLAY*.data'))[0]
data = open(fn, 'rb').read()
ROSTER = 0x3AA0; FRAME = 8112
f0 = data[ROSTER:ROSTER+FRAME]
ev0 = f0[0x1010:0x1010+4000]

def scan_marker(buf, lo=0x02, hi=0x28):
    offs = []
    i = 0
    while i < len(buf)-3:
        if buf[i]==0x00 and buf[i+1]==0x00 and buf[i+2]==0x01 and lo <= buf[i+3] <= hi:
            offs.append(i)
            i += 1
        else:
            i += 1
    return offs

offs = scan_marker(ev0)
print(f'event region 内 "00 00 01 XX"(X∈[2,40]) 命中 {len(offs)} 个: {offs[:20]}')
if len(offs) >= 2:
    diffs = [offs[i+1]-offs[i] for i in range(len(offs)-1)]
    print(f'相邻间距: {diffs[:12]}')

# 取第一个命中点作为候选槽起点，抽取并核对静态布局
if offs:
    base = offs[0]
    print(f'\n候选槽起点 base={base} (在事件区内相对偏移)，帧绝对={ROSTER+0x1010+base}')
    # 抽 10 个 300B 槽
    for k in range(10):
        s = ev0[base + k*300 : base + k*300 + 300]
        if len(s) < 300: break
        b0 = s[0]; lo3=b0&7; mid3=(b0>>3)&7; hi2=(b0>>6)&3
        b1=s[1]; b2=s[2]; b3=s[3]
        # 静态关键字段
        u16_e = struct.unpack('<H', s[0x0E:0x10])[0]
        u16_8 = struct.unpack('<H', s[0x08:0x0A])[0]
        sent_a8 = struct.unpack('<H', s[0xa8:0xaa])[0]
        sent_124 = struct.unpack('<H', s[0x124:0x126])[0]
        # 20 项区域：静态在 s[4:164)（20 记录，每记录 8B = i32 + f32）
        recs = []
        for r in range(20):
            o = 4 + r*8
            i32 = struct.unpack('<i', s[o:o+4])[0]
            f32 = struct.unpack('<f', s[o+4:o+8])[0]
            recs.append((i32, round(f32,3)))
        print(f'slot{k}: b0={b0:#04x}(lo3={lo3},mid3={mid3},hi2={hi2}) b1={b1:#04x} b2={b2:#04x} b3(slotnum)={b3} '
              f'u16@E={u16_e:#06x} u16@8={u16_8:#06x} sent@a8={sent_a8:#06x} sent@124={sent_124:#06x}')
        if k==0:
            print(f'   slot0 前 24 字节={s[:24].hex()}')
            print(f'   slot0 20 记录(i32,f32)={recs}')
            print(f'   slot0 [0xa0:0xb0]={s[0xa0:0xb0].hex()}')
