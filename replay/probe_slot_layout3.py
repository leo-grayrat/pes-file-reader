#!/usr/bin/env python3
# 多帧核对序列化槽布局：标记稳定性、byte0 的 3+3+2 位域是否变化、20×i16 帧间变化、blob。
import struct, glob, sys

fn = sorted(glob.glob('decoded/rep_REPLAY*.data'))[0]
data = open(fn, 'rb').read()
ROSTER = 0x3AA0; FRAME = 8112

def frame_event(fi):
    f = data[ROSTER + fi*FRAME : ROSTER + fi*FRAME + FRAME]
    return f[0x1010:0x1010+4000]

def slots_of(ev):
    # 标记 "00 00 01 XX"(X in 2..40) 间距 300，起点 = 第一个命中
    base = None
    for i in range(len(ev)-3):
        if ev[i]==0 and ev[i+1]==0 and ev[i+2]==1 and 2 <= ev[i+3] <= 40:
            base = i; break
    if base is None: return None, []
    out = []
    for k in range(10):
        s = ev[base + k*300 : base + k*300 + 300]
        out.append(s)
    return base, out

# 跨帧统计 byte0 位域非零次数 & byte2/byte3 稳定性
import collections
b0_nonzero = 0; total = 0
b2_set = collections.Counter(); b3_set = collections.Counter()
for fi in range(660):
    ev = frame_event(fi)
    base, sls = slots_of(ev)
    if base is None: continue
    for s in sls:
        if len(s) < 300: continue
        total += 1
        if s[0] != 0: b0_nonzero += 1
        b2_set[s[2]] += 1
        b3_set[s[3]] += 1
print(f'跨 660 帧：槽总数={total}, byte0(位域)!=0 次数={b0_nonzero} ({100*b0_nonzero/total:.1f}%)')
print(f'byte2 取值分布={dict(b2_set)}')
print(f'byte3(槽号) 取值分布={dict(sorted(b3_set.items()))}')

# 取若干帧的 slot#12（byte3==12），dump 头 + 20×i16
print('\n=== 多帧 slot#12 详情 ===')
for fi in [0, 50, 100, 300, 659]:
    ev = frame_event(fi)
    base, sls = slots_of(ev)
    s = None
    for cand in sls:
        if len(cand)>=300 and cand[3]==12:
            s = cand; break
    if s is None:
        print(f'frame{fi}: 无 slot#12'); continue
    b0=s[0]; lo3=b0&7; mid3=(b0>>3)&7; hi2=(b0>>6)&3
    i16 = struct.unpack('<20h', s[12:12+40])
    print(f'frame{fi}: marker={s[:4].hex()} b0={b0:#04x}(lo3={lo3},mid3={mid3},hi2={hi2}) '
          f'head[4:12]={s[4:12].hex()} 20xi16={list(i16)}')
