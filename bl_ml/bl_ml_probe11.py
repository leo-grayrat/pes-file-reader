#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第十轮 (probe11): 资金攻坚 + 补丁核查。

背景:
  - probe9 万位整 u32 扫描 (0x11F2C0~0x1F0000) 零命中 → 资金可能
    以万为单位、float、double 或位于赛事表/头部区;
  - probe10 赛程表已固化 (0x254 步长), 但 BL2/BL3 零命中需解释。
本轮:
  A. BL2/BL3 赛程区核查: 表位置原始 hex + 全文件日期三元组计数;
  B. 资金宽扫 (4 ML 样本): 万单位整数 / float 量级 / double 量级,
     区 [0,0x11F2C0) 头部+球队区也纳入 (预算可能在球队记录内);
  C. 赛事记录 +0x2C8 日期簇跨 8 样本 (赛季年字段验证)。

用法: python bl_ml_probe11.py [节号...]   纯标准库, 输入只读。
"""
import os
import re
import sys
import struct
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEC = os.path.join(BASE, "decoded")

FILES = {
    "BL0": "BL00000000.data", "BL1": "BL00000001.data",
    "BL2": "BL00000002.data", "BL3": "BL00000003.data",
    "ML0": "ML00000000.data", "ML1": "ML00000001.data",
    "ML2": "ML00000002.data", "ML13": "ML00000013.data",
}

_cache = {}
DATE_RE = re.compile(rb"[\xe5-\xe7]\x07[\x01-\x0c][\x01-\x1f]")


def load(key):
    if key not in _cache:
        with open(os.path.join(DEC, FILES[key]), "rb") as f:
            _cache[key] = f.read()
    return _cache[key]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def f32(b, o):
    return struct.unpack_from("<f", b, o)[0]


def f64(b, o):
    return struct.unpack_from("<d", b, o)[0]


def hx(b, o, n=32):
    return " ".join(f"{x:02X}" for x in b[o:o + n])


def banner(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


# -------------------------------------------------- A: BL2/BL3 核查
def secA_bl23():
    banner("A、BL2/BL3 赛程区核查")
    for k in ("BL0", "BL2", "BL3"):
        b = load(k)
        print(f"\n[{k}] len=0x{len(b):X}")
        print(f"  0x345408 处 0x40 字节: {hx(b, 0x345408, 0x40)}")
        print(f"  0x345560 处 0x20 字节: {hx(b, 0x345560, 0x20)}")
        hits = list(DATE_RE.finditer(b))
        in_band = sum(1 for m in hits if 0x11F2C0 <= m.start() < 0x400000)
        print(f"  全文件日期三元组 {len(hits)} 处, 其中主带内 {in_band}")
        if hits:
            o = hits[0].start()
            print(f"  首个三元组 @0x{o:08X}: "
                  f"{u16(b, o)}-{b[o+2]:02d}-{b[o+3]:02d}")


# -------------------------------------------------- B: 资金宽扫
def secB_money():
    banner("B、资金宽扫 (4 ML 样本: 万单位 / float / double)")
    keys = ("ML0", "ML1", "ML2", "ML13")
    bufs = [load(k) for k in keys]
    n = min(len(x) for x in bufs)
    regions = ((0x100, 0x11F2C0, "球队区"),
               (0x11F2C0, 0x194000, "动态区"),
               (0x194000, min(0x1F0000, n), "配置区"))
    # B1: u32 万单位 (v%10000==0, 10万~20亿)
    for lo, hi, tag in regions:
        cands = []
        for o in range(lo, min(hi, n) - 4, 4):
            vs = [u32(x, o) for x in bufs]
            if all(100000 <= v <= 2000000000 and v % 10000 == 0
                   for v in vs) and len(set(vs)) > 1 \
               and max(vs) < 100 * min(vs):
                cands.append((o, vs))
        print(f"\n[B1 万单位 u32] {tag} [0x{lo:06X},0x{hi:06X}): "
              f"{len(cands)} 处")
        for o, vs in cands[:20]:
            print(f"  0x{o:08X}: " +
                  " ".join(f"{k}={v:>12,}" for k, v in zip(keys, vs)))
    # B2: float 资金量级 (1e5~2e9)
    for lo, hi, tag in regions[1:]:
        cands = []
        for o in range(lo, min(hi, n) - 4, 4):
            vs = [f32(x, o) for x in bufs]
            if all(v == v and 1e5 <= v <= 2e9 for v in vs) \
               and len(set(vs)) > 1 and max(vs) < 100 * min(vs):
                cands.append((o, vs))
        print(f"\n[B2 float 1e5~2e9] {tag} [0x{lo:06X},0x{hi:06X}): "
              f"{len(cands)} 处")
        for o, vs in cands[:20]:
            print(f"  0x{o:08X}: " +
                  " ".join(f"{k}={v:>13,.0f}" for k, v in zip(keys, vs)))
    # B3: double
    for lo, hi, tag in regions[1:]:
        cands = []
        for o in range(lo, min(hi, n) - 8, 4):
            vs = [f64(x, o) for x in bufs]
            if all(v == v and 1e5 <= v <= 2e9 for v in vs) \
               and len(set(vs)) > 1 and max(vs) < 100 * min(vs):
                cands.append((o, vs))
        print(f"\n[B3 double 1e5~2e9] {tag} [0x{lo:06X},0x{hi:06X}): "
              f"{len(cands)} 处")
        for o, vs in cands[:20]:
            print(f"  0x{o:08X}: " +
                  " ".join(f"{k}={v:>13,.0f}" for k, v in zip(keys, vs)))


# -------------------------------------------------- C: 赛事记录日期簇
def secC_comp_date():
    banner("C、赛事记录 +0x2C8 起字段 8 样本核对")
    CN_RE = re.compile(rb"(?:[\xe0-\xef][\x80-\xbf]{2}){2,24}")
    for k in FILES:
        b = load(k)
        names = []
        for m in CN_RE.finditer(b, 0x1F0000, min(len(b), 0x200000)):
            try:
                t = m.group().decode("utf-8")
            except UnicodeDecodeError:
                continue
            if any("\u4e00" <= c <= "\u9fff" for c in t):
                names.append(m.start())
        noff = Counter(o % 0x314 for o in names).most_common(1)[0][0]
        base = next(o for o in names if o % 0x314 == noff) - noff
        o = base + 0x2C8
        print(f"[{k}] rec0 +0x2C8: {hx(b, o, 26)}")


SECTIONS = {"A": secA_bl23, "B": secB_money, "C": secC_comp_date}


def main():
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    picks = [a for a in sys.argv[1:] if a.upper() in SECTIONS] or list(SECTIONS)
    for p in picks:
        SECTIONS[p.upper()]()
    print("\n完成。")


if __name__ == "__main__":
    main()
