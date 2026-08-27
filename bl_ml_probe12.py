#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第十一轮 (probe12): 资金收尾 + 补充固化。

probe11 结果: 万单位/float/double 宽扫无预算级候选;
球队区 6 处 10 万~70 万候选待定性。本轮:
  A. 球队记录内候选上下文: 0 基址换算定 (队号, 记录内偏移), 4 样本值;
  B. 跨模式扫描: BL 样本同区同条件扫描 (预算是 ML 概念, 用于排除);
     再放宽到千单位 + 球队记录全偏移直方图找"单队突出值";
  C. BL0 赛程表确认: 基址/日期偏移/首 3 条日期 + 比赛日序号字段。

用法: python bl_ml_probe12.py [节号...]   纯标准库, 输入只读。
"""
import os
import re
import sys
import struct
from collections import Counter

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")

FILES = {
    "BL0": "BL00000000.data", "BL1": "BL00000001.data",
    "BL2": "BL00000002.data", "BL3": "BL00000003.data",
    "ML0": "ML00000000.data", "ML1": "ML00000001.data",
    "ML2": "ML00000002.data", "ML13": "ML00000013.data",
}

_cache = {}
TEAM_START, TEAM_REC, TEAM_N = 0x100, 0x690, 700
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


def hx(b, o, n=32):
    return " ".join(f"{x:02X}" for x in b[o:o + n])


def banner(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


# -------------------------------------------------- A: 球队区候选定性
CANDS = (0x0006B768, 0x000A8FC8, 0x000A9658,
         0x000AB098, 0x000AB728, 0x000ACAD8)


def secA_team_cands():
    banner("A、球队记录内候选定性 (队号 + 记录内偏移 + 8 样本值)")
    for o in CANDS:
        rec = (o - TEAM_START) // TEAM_REC
        off = (o - TEAM_START) % TEAM_REC
        print(f"\n0x{o:08X} → 队#{rec} +0x{off:03X}")
        for k in FILES:
            b = load(k)
            print(f"  [{k}] {u32(b, o):>10,}  ctx={hx(b, o - 8, 24)}")


# -------------------------------------------------- B: 资金补充扫描
def secB_money_more():
    banner("B、资金补充扫描")
    keys = ("ML0", "ML1", "ML2", "ML13")
    bufs = [load(k) for k in keys]
    n = min(len(x) for x in bufs)
    # B1: 千单位, 动态区 + 配置区
    for lo, hi, tag in ((0x11F2C0, 0x194000, "动态区"),
                        (0x194000, min(0x1F0000, n), "配置区")):
        cands = []
        for o in range(lo, min(hi, n) - 4, 4):
            vs = [u32(x, o) for x in bufs]
            if all(1000000 <= v <= 2000000000 and v % 1000 == 0
                   for v in vs) and len(set(vs)) > 1 \
               and max(vs) < 20 * min(vs):
                cands.append((o, vs))
        print(f"\n[B1 千单位 u32≥100万] {tag}: {len(cands)} 处")
        for o, vs in cands[:20]:
            print(f"  0x{o:08X}: " +
                  " ".join(f"{k}={v:>12,}" for k, v in zip(keys, vs)))
    # B2: 球队记录内"用户队(#33?)突出值": 对每个记录内偏移,
    #     找某一队数值 >> 其他队众数的字段 (用户队资金可能独立存储)
    b = bufs[0]
    print("\n[B2 用户队突出值] 记录内偏移扫描 (队33值 ≥ 10×其他队中位)")
    import statistics
    hits = []
    for off in range(0, TEAM_REC - 4, 4):
        vals = [u32(b, TEAM_START + r * TEAM_REC + off)
                for r in range(TEAM_N)]
        v33 = vals[33]
        if v33 < 1000000:
            continue
        med = statistics.median(vals)
        if med > 0 and v33 >= 10 * med:
            hits.append((off, v33, med))
    for off, v33, med in hits[:20]:
        print(f"  +0x{off:03X}: 队33={v33:,}  全场中位={med:,.0f}")
    # B3: BL0/ML0 同偏移对比 (上述命中是否模式特有)
    if hits:
        a = load("BL0")
        print("\n[B3 BL0 同偏移值 (队33)]:")
        for off, *_ in hits[:10]:
            va = u32(a, TEAM_START + 33 * TEAM_REC + off)
            print(f"  +0x{off:03X}: BL0={va:,}")


# -------------------------------------------------- C: BL0 赛程固化
def secC_bl_sched():
    banner("C、BL0 赛程表固化")
    b = load("BL0")
    hits = [(m.start(), u16(b, m.start()), b[m.start() + 2],
             b[m.start() + 3]) for m in DATE_RE.finditer(b, 0x11F2C0, 0x400000)]
    off0 = Counter(o % 0x254 for o, *_ in hits).most_common(1)[0][0]
    first = next(o for o, *_ in hits if o % 0x254 == off0)
    base = first - off0
    print(f"BL0: 基址 0x{base:08X}, 日期@+0x{off0:X}, {len(hits)} 条")
    for r in range(3):
        o = base + r * 0x254
        y, mo, d = u16(b, o + off0), b[o + off0 + 2], b[o + off0 + 3]
        seq = u32(b, o + 0x150)
        rnd = u32(b, o + 0x160)
        first_evt = u32(b, o + 0x30)
        print(f"  #{r}: {y}-{mo:02d}-{d:02d} 比赛日序号={seq} "
              f"+0x160={rnd} 首赛事条目+0x30={first_evt}")
    # 表尾
    last = hits[-1][0]
    print(f"末条 @0x{last:08X}: "
          f"{hits[-1][1]}-{hits[-1][2]:02d}-{hits[-1][3]:02d}")


SECTIONS = {"A": secA_team_cands, "B": secB_money_more,
            "C": secC_bl_sched}


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
