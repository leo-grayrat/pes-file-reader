#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe34.py — 跨存档交叉验证「玩家队标志位」。

对三个存档分别找「整 stride 内仅一队非零」的字段，再取交集偏移：
若同一偏移在三档都是唯一非零，则是结构性(my-team)标志位（指向队伍可能随生涯变化）。
分别用 1 字节与 2 字节粒度。
"""
import os, struct
from collections import defaultdict

BASE = "decoded"
SAMPLES = [("ML0","ML00000000.data"),("ML1","ML00000001.data"),("ML13","ML00000013.data")]
STRIDE = 0x690
N_TEAM = 700
BASE_OFF = 0x100

def singleton_offsets(fn, width):
    b = open(os.path.join(BASE, fn), "rb").read()
    res = {}  # off -> (teamIdx, val)
    for off in range(0, STRIDE, width):
        cnt = defaultdict(int); team_for = {}
        for t in range(N_TEAM):
            o = BASE_OFF + t*STRIDE
            if o+off+width > len(b): break
            if width==1: val=int(b[o+off])
            elif width==2: val=struct.unpack_from("<H", b, o+off)[0]
            cnt[val]+=1; team_for[val]=t
        # 恰一个非零值且仅一队
        nz = [(v,n) for v,n in cnt.items() if v!=0 and n==1]
        if len(nz)==1:
            res[off]=(team_for[nz[0][0]], nz[0][0])
    return res

for w in (1,2):
    print(f"==== 粒度 {w} 字节 ====")
    per = {}
    for tag, fn in SAMPLES:
        per[tag] = singleton_offsets(fn, w)
    # 取三档都出现的偏移交集
    common = set.intersection(*[set(d) for d in per.values()])
    print(f"三档均唯一非零的偏移数: {len(common)}")
    for off in sorted(common)[:40]:
        print(f"  +0x{off:03X}: " + " | ".join(f"{t}:team#{per[t][off][0]}(0x{per[t][off][1]:X})" for t in per))
    print()
