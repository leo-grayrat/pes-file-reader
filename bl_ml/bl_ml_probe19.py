#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe19.py — 扫描球队记录财务尾部（+0x590~+0x690），跨样本比较 preseason vs in-season。

团队记录在 0x100 起，步长 0x690，共 700 队。该区域在所有样本中长度固定，
可逐记录对齐比较。重点看 +0x598 预算簇及其周边是否还有结构化财务字段。
"""
import struct

FILES = {
    "ML0(in-season)": "decoded/ML00000000.data",
    "ML2(preseason)": "decoded/ML00000002.data",
    "ML13(in-season)": "decoded/ML00000013.data",
}
REC_BASE = 0x100
REC_STRIDE = 0x690
N_TEAMS = 700

def read(path):
    with open(path, "rb") as f:
        return f.read()

def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]

data = {name: read(p) for name, p in FILES.items()}

# 1) 验证 block 长度一致
print("=== block 长度（0x100..0x11F2C0）一致性校验 ===")
for name, b in data.items():
    size_region = len(b) - 0x100 - N_TEAMS * REC_STRIDE
    print("  %-14s total=%d  区块剩余=%d" % (name, len(b), size_region))

# 2) 逐队 dump +0x590..+0x690（64 个 u32）
SHOW = [0, 1, 2, 3, 10, 50, 699]
print("\n=== 代表性球队 财务尾部 u32（offset_in_record -> value）===")
for name, b in data.items():
    print("\n-- %s --" % name)
    for tid in SHOW:
        base = REC_BASE + tid * REC_STRIDE
        vals = []
        for off in range(0x590, 0x690, 4):
            v = u32(b, base + off)
            vals.append("%04X:%d" % (off - 0x590, v))
        print("  team %3d: %s" % (tid, " ".join(vals)))

# 3) 比较 ML2(preseason) 与 ML0(in-season) 在 +0x590..+0x690 的差异分布
print("\n=== ML2 vs ML0 财务尾部逐偏移差异计数（700 队，+0x590..+0x690, 64 槽）===")
b2 = data["ML2(preseason)"]
b0 = data["ML0(in-season)"]
diffcount = [0] * 64
for tid in range(N_TEAMS):
    for i in range(64):
        off = 0x590 + i * 4
        if u32(b2, REC_BASE + tid * REC_STRIDE + off) != u32(b0, REC_BASE + tid * REC_STRIDE + off):
            diffcount[i] += 1
print("  偏移(相对0x590) : 两队以上不同的队数 / 700")
for i in range(64):
    if diffcount[i]:
        print("   +0x%03X : %d" % (0x590 + i * 4, diffcount[i]))

# 4) 两样本预算(+0x598)对比：preseason 是否全 0
print("\n=== +0x598 预算（×100 EUR）：preseason 全队统计 ===")
zero = sum(1 for tid in range(N_TEAMS) if u32(b2, REC_BASE + tid * REC_STRIDE + 0x598) == 0)
print("  ML2(preseason) 预算=0 的队数: %d / 700" % zero)
nz0 = sum(1 for tid in range(N_TE * REC_STRIDE) if False for _ in [0])
nz0 = sum(1 for tid in range(N_TEAMS) if u32(b0, REC_BASE + tid * REC_STRIDE + 0x598) != 0)
print("  ML0(in-season) 预算!=0 的队数: %d / 700" % nz0)
