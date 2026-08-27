#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第十二轮 (probe13): 对阵记录解引用 + 资金复核。

probe12 结果:
  - 球队记录 +0x598: 万单位整数字段 (10万~70万 → 1亿~7亿),
    8 样本中 7 个恒定、随球队不同 → 疑转会预算;
  - 球队记录 +0x5B4: 队33 (用户队?) = 4294901975 (= -65321 有符号),
    其他队中位 ~1481 万 → 疑当前余额 (负数 = 负债);
  - 赛程记录 +0x30 起条目的第 4 u32 (如 0x601E5A) 像绝对指针。
本轮:
  A. 解引用: 取赛程记录条目指针, 看指向区域内容, 找对阵 (两个队号);
  B. 资金复核: +0x598/+0x5B4 全 700 队分布 + 8 样本 + 有符号解读;
  C. 赛程记录 +0x150 比赛日序号跨样本连续性。

用法: python bl_ml_probe13.py [节号...]   纯标准库, 输入只读。
"""
import os
import re
import sys
import struct
import statistics
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


def s32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def hx(b, o, n=32):
    return " ".join(f"{x:02X}" for x in b[o:o + n])


def banner(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


# -------------------------------------------------- A: 对阵记录解引用
def secA_deref():
    banner("A、赛程条目指针解引用 (BL0)")
    b = load("BL0")
    hits = [m.start() for m in DATE_RE.finditer(b, 0x11F2C0, 0x400000)]
    off0 = Counter(o % 0x254 for o in hits).most_common(1)[0][0]
    first = next(o for o in hits if o % 0x254 == off0)
    base = first - off0
    ptrs = []
    for r in range(2):
        o = base + r * 0x254
        for j in range(0x30, 0xE0, 0x10):
            evt = u16(b, o + j)          # 赛事条目 ID (u16, FF FF 空槽)
            if evt >= 0xFFFF:
                continue
            ptr = u32(b, o + j + 12)
            if 0x100 < ptr < len(b):
                ptrs.append((evt, ptr))
    print(f"取到 {len(ptrs)} 个 (赛事条目, 指针) 对; 前 6:")
    for evt, ptr in ptrs[:6]:
        print(f"\n  条目 id={evt} → 0x{ptr:08X}:")
        for i in range(0, 0x40, 16):
            marks = []
            for jj in range(0, 16, 4):
                v = u32(b, ptr + i + jj)
                if 1 <= v <= 800:
                    marks.append(f"+{i+jj:X}:{v}")
            print(f"    +0x{i:03X}: {hx(b, ptr + i, 16)}  {' '.join(marks)}")
    # 指针区成带判定: 指针值域
    allp = [p for _, p in ptrs]
    if not allp:
        print("无有效指针")
        return
    print(f"\n指针值域: [0x{min(allp):06X}, 0x{max(allp):06X}]")
    # 目标区找结构: 在首个指针处向后扫, 找等距重复头
    p0 = ptrs[0][1]
    gaps = Counter()
    heads = Counter()
    for o in range(p0, min(p0 + 0x20000, len(b) - 8), 4):
        heads[b[o:o + 4]] += 1
    print(f"目标区 0x{p0:06X}+0x20000 头部4字节 top5: "
          f"{[(s.hex(), c) for s, c in heads.most_common(5)]}")


# -------------------------------------------------- B: 资金字段复核
def secB_money_fields():
    banner("B、球队记录 +0x598/+0x5B4 复核")
    for k in ("BL0", "ML0", "ML2", "ML13"):
        b = load(k)
        v598 = [u32(b, TEAM_START + r * TEAM_REC + 0x598)
                for r in range(TEAM_N)]
        v5b4 = [s32(b, TEAM_START + r * TEAM_REC + 0x5B4)
                for r in range(TEAM_N)]
        d598 = Counter(v598)
        print(f"\n[{k}] +0x598 分布 top6: {d598.most_common(6)}")
        med = statistics.median(v5b4)
        out = [(r, v) for r, v in enumerate(v5b4)
               if abs(v) > 10 * max(abs(med), 1)]
        print(f"[{k}] +0x5B4(有符号) 中位={med:,.0f}; 离群队: "
              f"{[(r, f'{v:,}') for r, v in out[:8]]}")


# -------------------------------------------------- C: 比赛日序号
def secC_seq():
    banner("C、比赛日序号 +0x150 跨样本")
    for k in ("BL0", "ML0"):
        b = load(k)
        hits = [m.start() for m in DATE_RE.finditer(b, 0x11F2C0, 0x400000)]
        off0 = Counter(o % 0x254 for o in hits).most_common(1)[0][0]
        first = next(o for o in hits if o % 0x254 == off0)
        base = first - off0
        seqs = [u32(b, base + r * 0x254 + 0x150) for r in range(len(hits))]
        mono = all(seqs[i + 1] > seqs[i] for i in range(len(seqs) - 1))
        print(f"[{k}] {len(hits)} 条: 序号首={seqs[0]} 末={seqs[-1]} "
              f"严格递增={mono}")


SECTIONS = {"A": secA_deref, "B": secB_money_fields, "C": secC_seq}


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
