#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第八轮 (probe9): 终局判定 + 资金/赛程推进。

probe8 结论: 0xB00000~0xC80000 内中文串各仅 1 处 (用户球员),
全库球员名不在该带。本轮做终局判定与另两目标:
  A. 后段大带 [0xC80000, EOF) UTF-8 中文/大写全名/UTF-16LE 名判定
     (若全无 → 球员资料确认不存于 data);
  B. 后段大带值类型判定: u32 整数计数/直方图 + float 值域统计 +
     16~64 字节周期头部搜索 (找定长记录数组证据);
  C. 资金: 赛事记录 +0x2C0~+0x2E2 字段全样本解读 +
     4 ML 样本万位整候选扫描;
  D. 赛程: 日期三元组全文件扫描 + 球队 ID(1..800) 连续段扫描。

用法: python bl_ml_probe9.py [节号...]   纯标准库, 输入只读。
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
CN_RE = re.compile(rb"(?:[\xe0-\xef][\x80-\xbf]{2}){2,24}")
NAME_RE = re.compile(rb"[A-Z][A-Z.'-]{1,20} [A-Z][A-Z.'-]{1,24}")
U16NAME_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,40}")
DATE_RE = re.compile(rb"[\xe5-\xe7]\x07[\x01-\x0c][\x01-\x1f]")
COMP_STRIDE = 0x314


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


def hx(b, o, n=32):
    return " ".join(f"{x:02X}" for x in b[o:o + n])


def banner(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


def has_cjk(txt):
    return any("\u4e00" <= c <= "\u9fff" for c in txt)


# -------------------------------------------------- A: 后段带名串终判
def secA_names():
    banner("A、后段大带 [0xC80000, EOF) 名串终局判定")
    for k in ("BL0", "ML0"):
        b = load(k)
        lo = 0xC80000
        cn = []
        for m in CN_RE.finditer(b, lo):
            try:
                t = m.group().decode("utf-8")
            except UnicodeDecodeError:
                continue
            if has_cjk(t):
                cn.append((m.start(), t))
        an = []
        for m in NAME_RE.finditer(b, lo):
            s = m.group().decode("ascii").strip(".'- ")
            if sum(c.isalpha() for c in s) >= 6:
                an.append((m.start(), s))
        u16n = []
        for m in U16NAME_RE.finditer(b, lo):
            try:
                s = m.group().decode("utf-16-le")
            except UnicodeDecodeError:
                continue
            if sum(c.isalpha() for c in s) >= 5 and " " in s:
                u16n.append((m.start(), s))
        print(f"\n[{k}] UTF-8 中文 {len(cn)}; 大写全名 {len(an)}; "
              f"UTF-16LE 名 {len(u16n)}")
        for o, t in cn[:6]:
            print(f"    cn 0x{o:08X} {t[:20]!r}")
        for o, s in an[:6]:
            print(f"    an 0x{o:08X} {s!r}")
        for o, s in u16n[:6]:
            print(f"    u16 0x{o:08X} {s!r}")


# -------------------------------------------------- B: 后段带值类型
def secB_values():
    banner("B、后段大带值类型判定")
    b = load("BL0")
    for lo, hi, tag in ((0xCAAC90, min(0x1100EE5, len(b)), "BL后段大带"),
                        (0xC8B130, 0xCA8A58, "零散小带")):
        if lo >= len(b):
            continue
        n_int, n_float, n_fmag = 0, 0, 0
        fmag = []
        for o in range(lo, hi - 4, 4):
            v = u32(b, o)
            if 1 <= v <= 100000:
                n_int += 1
            f = f32(b, o)
            if f == f and 1e-6 < abs(f) < 1e10:
                n_float += 1
                if 0.01 <= abs(f) <= 2000:
                    n_fmag += 1
                    if len(fmag) < 8:
                        fmag.append((o, f))
        total = (hi - lo) // 4
        print(f"\n[{tag} 0x{lo:06X}~0x{hi:06X}] {total} 个 u32 槽: "
              f"小整数 {n_int} ({100*n_int//max(total,1)}%), "
              f"有效float {n_float} ({100*n_float//max(total,1)}%), "
              f"float@0.01~2000 {n_fmag}")
        for o, f in fmag:
            print(f"    0x{o:08X} = {f:.4f}")
        # 周期头搜索: 4 字节对齐, 找高频重复的 16 字节窗口签名
        sig = Counter()
        for o in range(lo, hi - 16, 64):
            sig[b[o:o + 4]] += 1
        top = sig.most_common(3)
        print(f"  每 64B 采样首 4 字节 top3: "
              f"{[(s.hex(), c) for s, c in top]}")


# -------------------------------------------------- C: 资金
def comp_bases(b):
    names = []
    for m in CN_RE.finditer(b, 0x1F0000, min(len(b), 0x200000)):
        try:
            t = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        if has_cjk(t):
            names.append(m.start())
    if not names:
        return 0, 0
    noff = Counter(o % COMP_STRIDE for o in names).most_common(1)[0][0]
    base = next(o for o in names if o % COMP_STRIDE == noff) - noff
    return base, (min(len(b), 0x200000) - base) // COMP_STRIDE


def secC_money():
    banner("C、资金: 赛事记录 +0x2C0~+0x2E2 + ML 万位整扫描")
    # C1: 赛事记录尾段字段 (8 样本)
    for k in ("BL0", "ML0", "ML13"):
        b = load(k)
        base, nrec = comp_bases(b)
        print(f"\n[{k}] 表 @0x{base:06X} ×{nrec}: 前 4 条 +0x2C0~+0x2E2:")
        for r in range(min(4, nrec)):
            o = base + r * COMP_STRIDE + 0x2C0
            vals = [u32(b, o + j) for j in range(0, 0x22, 4)]
            print(f"  #{r}: " + " ".join(f"{v:08X}" for v in vals))
    # C2: 4 ML 样本万位整候选
    keys = ("ML0", "ML1", "ML2", "ML13")
    bufs = [load(k) for k in keys]
    n = min(len(x) for x in bufs)
    for lo, hi in ((0x11F2C0, 0x194000), (0x194000, 0x1F0000)):
        cands = []
        for o in range(lo, min(hi, n) - 4, 4):
            v0 = u32(bufs[0], o)
            if not (500000 <= v0 <= 2000000000) or v0 % 10000 != 0:
                continue
            vals = [u32(x, o) for x in bufs]
            if all(100000 <= v <= 2000000000 for v in vals) \
               and len(set(vals)) > 1 \
               and all(v % 10000 == 0 for v in vals) \
               and max(vals) < 100 * min(vals):
                cands.append((o, vals))
        print(f"\n区 [0x{lo:06X}, 0x{hi:06X}): 强候选 {len(cands)} 处")
        for o, vs in cands[:25]:
            print(f"  0x{o:08X}: " +
                  "  ".join(f"{k}={v:>12,}" for k, v in zip(keys, vs)))


# -------------------------------------------------- D: 赛程
def secD_schedule():
    banner("D、赛程: 日期三元组 + 球队 ID 连续段")
    for k in ("BL0", "ML0"):
        b = load(k)
        hits = [(m.start(), u16(b, m.start()), b[m.start() + 2],
                 b[m.start() + 3]) for m in DATE_RE.finditer(b)]
        print(f"\n[{k}] 日期三元组 {len(hits)} 处")
        for o, y, mo, d in hits[:25]:
            print(f"  0x{o:08X}: {y}-{mo:02d}-{d:02d}")
        if len(hits) >= 2:
            gaps = Counter(hits[i + 1][0] - hits[i][0]
                           for i in range(len(hits) - 1))
            print(f"  间距 top6: {gaps.most_common(6)}")
    # 球队 ID 连续段 (BL0/ML0 各扫主数据区+赛事区)
    for k in ("BL0", "ML0"):
        b = load(k)
        runs = []
        start = None
        for o in range(0x11F2C0, min(0x280000, len(b) - 4), 4):
            v = u32(b, o)
            if 1 <= v <= 800:
                if start is None:
                    start = o
            else:
                if start is not None and o - start >= 96:
                    runs.append((start, o))
                start = None
        print(f"\n[{k}] 球队 ID(1..800) run ≥96B: {len(runs)} 段")
        for s, e in runs[:10]:
            vals = [u32(b, s + j) for j in range(0, min(e - s, 48), 4)]
            print(f"  [0x{s:06X}, 0x{e:06X}) {e-s}B 头12={vals}")


SECTIONS = {"A": secA_names, "B": secB_values,
            "C": secC_money, "D": secD_schedule}


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
