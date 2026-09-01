#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第九轮 (probe10): 赛程表结构固化。

probe9 发现:
  - 日期三元组 (u16 年 2021~2023 + 月 + 日) 从 ~0x345560 起密集出现,
    间距众数 596 (0x254); BL0 7063 处 / ML0 11373 处;
  - 日期成组重复 (同一比赛日 3~10 场), 符合赛程表特征。
本轮:
  A. 表边界: 首/末三元组位置、表内命中数、跨度/步长核算;
  B. 记录字段解读: 以日期为锚点, 解读记录内 ±0x100 的
     球队/比分/阶段字段 (u32 1..800 候选);
  C. 8 样本交叉验证: 步长、首址、记录数;
  D. 日期语义: 按日期分组计数 (每比赛日场次数)、跨赛季值域。

用法: python bl_ml_probe10.py [节号...]   纯标准库, 输入只读。
"""
import os
import re
import sys
import struct
from collections import Counter, defaultdict

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
STRIDE = 0x254


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


def date_hits(b, lo=0x100000, hi=None):
    hi = len(b) if hi is None else min(hi, len(b))
    return [(m.start(), u16(b, m.start()), b[m.start() + 2],
             b[m.start() + 3]) for m in DATE_RE.finditer(b, lo, hi)]


# -------------------------------------------------- A: 表边界
def secA_bounds():
    banner("A、赛程表边界与密度 (主带 0x11F2C0~0x400000)")
    for k in FILES:
        b = load(k)
        hits = date_hits(b, 0x11F2C0, 0x400000)
        if not hits:
            print(f"[{k}] 无命中")
            continue
        gaps = Counter(hits[i + 1][0] - hits[i][0]
                       for i in range(len(hits) - 1))
        top = gaps.most_common(3)
        off0 = Counter(o % STRIDE for o, *_ in hits).most_common(1)[0][0]
        ok = sum(1 for o, *_ in hits if o % STRIDE == off0)
        span = hits[-1][0] - hits[0][0]
        print(f"[{k}] 命中 {len(hits):5d}  首@0x{hits[0][0]:08X}"
              f"({hits[0][1]}-{hits[0][2]:02d}-{hits[0][3]:02d})  "
              f"末@0x{hits[-1][0]:08X}  跨度0x{span:07X}  "
              f"对齐0x254 {ok}/{len(hits)}  间距top3={top}")


# -------------------------------------------------- B: 记录字段解读
def secB_fields():
    banner("B、BL0 记录字段解读 (前 3 条全量 + 球队候选标注)")
    b = load("BL0")
    hits = date_hits(b, 0x11F2C0, 0x400000)
    off0 = Counter(o % STRIDE for o, *_ in hits).most_common(1)[0][0]
    first = next(o for o, *_ in hits if o % STRIDE == off0)
    base = first - off0
    print(f"记录内日期偏移 +0x{off0:X}, 记录基址 0x{base:08X}")
    for r in range(3):
        o = base + r * STRIDE
        y, mo, d = u16(b, o + off0), b[o + off0 + 2], b[o + off0 + 3]
        print(f"\n#{r} @0x{o:08X}  日期 {y}-{mo:02d}-{d:02d}")
        for i in range(0, STRIDE, 16):
            row = hx(b, o + i, 16)
            # 标注: u32 ∈ [1,800] 的位置
            marks = []
            for j in range(0, 16, 4):
                v = u32(b, o + i + j)
                if 1 <= v <= 800:
                    marks.append(f"+{i+j:X}:{v}")
            print(f"  +0x{i:03X}: {row}  {' '.join(marks)}")


# -------------------------------------------------- C: 8 样本字段稳定性
def secC_cross():
    banner("C、8 样本: 日期偏移/基址/记录数一致性")
    rows = []
    for k in FILES:
        b = load(k)
        hits = date_hits(b, 0x11F2C0, 0x400000)
        if not hits:
            rows.append((k, 0, 0, 0, 0))
            continue
        off0 = Counter(o % STRIDE for o, *_ in hits).most_common(1)[0][0]
        ok = sum(1 for o, *_ in hits if o % STRIDE == off0)
        first = next(o for o, *_ in hits if o % STRIDE == off0)
        base = first - off0
        nrec = (hits[-1][0] - base) // STRIDE + 1
        rows.append((k, len(hits), ok, base, nrec))
    for k, n, ok, base, nrec in rows:
        print(f"[{k}] 命中 {n:5d} 对齐 {ok:5d} 基址 0x{base:08X} "
              f"估记录数 {nrec}")
    # BL0/BL1 同址记录对比: 结构同、日期不同?
    a, b = load("BL0"), load("BL1")
    hits = date_hits(a, 0x11F2C0, 0x400000)
    off0 = Counter(o % STRIDE for o, *_ in hits).most_common(1)[0][0]
    first = next(o for o, *_ in hits if o % STRIDE == off0)
    base = first - off0
    print(f"\nBL0 vs BL1 前 5 条记录日期:")
    for r in range(5):
        o = base + r * STRIDE
        da = (u16(a, o + off0), a[o + off0 + 2], a[o + off0 + 3])
        db = (u16(b, o + off0), b[o + off0 + 2], b[o + off0 + 3])
        same = a[o:o + STRIDE] == b[o:o + STRIDE]
        print(f"  #{r}: BL0={da[0]}-{da[1]:02d}-{da[2]:02d} "
              f"BL1={db[0]}-{db[1]:02d}-{db[2]:02d} 整条{'同' if same else '异'}")


# -------------------------------------------------- D: 日期语义
def secD_semantic():
    banner("D、日期分组: 每比赛日场次 + 赛季值域")
    for k in ("BL0", "ML0"):
        b = load(k)
        hits = date_hits(b, 0x11F2C0, 0x400000)
        days = Counter((y, mo, d) for _, y, mo, d in hits)
        hist = Counter(days.values())
        years = Counter(y for _, y, _, _ in hits)
        print(f"\n[{k}] {len(hits)} 条, 覆盖 {len(days)} 个日期; "
              f"年份分布 {sorted(years.items())}")
        print(f"  每比赛日场次数分布: {sorted(hist.items())[:10]}")
        top = sorted(days.items(), key=lambda x: -x[1])[:8]
        print(f"  场次最多的日期: {[((f'{y}-{m:02d}-{d:02d}'), c) for (y, m, d), c in top]}")


SECTIONS = {"A": secA_bounds, "B": secB_fields,
            "C": secC_cross, "D": secD_semantic}


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
