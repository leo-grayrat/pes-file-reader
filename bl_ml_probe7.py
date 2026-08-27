#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第六轮 (probe7): 三大核心字段实质定位。

目标:
  A. 全局名串普查: 全文件大写 ASCII 全名 / UTF-8 中文串落点, 判定球员名表是否存在;
  B. 球员记录模式: "u32 ID 重复两份 + 邻近中文名" 模式全文件搜索 (锚点 0xB7E2C4);
  C. 记录步长/条数交叉验证: 8 样本命中数与间距众数, 记录体对比;
  D. 赛事记录 +0x2C0~+0x2F0 候选字段 + 参赛 ID 值域 (与球员/球队 ID 空间关联);
  E. 资金候选: 4 个 ML 样本中 万位整数、量级合理、随存档变化的字段;
  F. 赛程: 日期三元组 (u16 年 + 月 + 日) 扫描 + 球队 ID 对连续段扫描。

用法: python bl_ml_probe7.py [节号...]   不带参数 = 全部节。
纯标准库。输入只读。
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
DUP_RE = re.compile(rb"([\x01-\xff][\x00-\xff]{3})\1")
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


def has_cjk(txt):
    return any("\u4e00" <= c <= "\u9fff" for c in txt)


def chinese_hits(b, lo=0, hi=None):
    hi = len(b) if hi is None else min(hi, len(b))
    out = []
    for m in CN_RE.finditer(b, lo, hi):
        try:
            t = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        if has_cjk(t):
            out.append((m.start(), t))
    return out


# -------------------------------------------------- A: 全局名串普查
def secA_census():
    banner("A、全局名串普查 (大写全名 / 中文串)")
    for k in ("BL0", "ML0"):
        b = load(k)
        names = []
        for m in NAME_RE.finditer(b):
            s = m.group().decode("ascii").strip(".'- ")
            if sum(c.isalpha() for c in s) >= 6:
                names.append((m.start(), s))
        cn = chinese_hits(b)
        print(f"\n[{k}] 大写全名 {len(names)} 个; 中文串 {len(cn)} 个")
        for o, s in names[:15]:
            print(f"  名 0x{o:08X} {s!r}")
        if len(names) > 15:
            print(f"  ... 共 {len(names)}")
        # 中文串落点分桶 (每 0x100000 一桶)
        buckets = Counter(o >> 20 for o, _ in cn)
        print(f"  中文串落点 (MB 桶, top10): "
              f"{[(f'0x{v:X}00000', c) for v, c in buckets.most_common(10)]}")
        # 中文串去重后抽样 (按桶各取 3)
        seen = set()
        shown = Counter()
        for o, t in cn:
            bk = o >> 20
            if shown[bk] < 3 and t not in seen:
                seen.add(t)
                shown[bk] += 1
                print(f"    0x{o:08X} {t[:24]!r}")


# -------------------------------------------------- B: 球员记录模式
def player_hits(b, lo=0, hi=None):
    """"u32 v 重复两份 (0x10000<=v<0x80000) 且 8~48 字节内有中文串"。"""
    hi = len(b) if hi is None else min(hi, len(b))
    cn = dict(chinese_hits(b, lo, hi))
    cn_offs = sorted(cn)
    hits = []
    import bisect
    for m in DUP_RE.finditer(b, lo, hi):
        v = u32(b, m.start())
        if not (0x10000 <= v < 0x80000):
            continue
        o = m.start()
        i = bisect.bisect_left(cn_offs, o + 8)
        if i < len(cn_offs) and cn_offs[i] <= o + 48:
            hits.append((o, v, cn[cn_offs[i]]))
    return hits


def secB_pattern():
    banner("B、球员记录模式搜索 (u32 ID 双份 + 邻近中文名)")
    b = load("BL0")
    hits = player_hits(b)
    print(f"BL0 命中 {len(hits)} 处")
    for o, v, t in hits[:40]:
        print(f"  0x{o:08X} id={v} 中文={t[:16]!r}")
    if len(hits) > 40:
        print(f"  ... 共 {len(hits)}")
    if len(hits) >= 2:
        gaps = Counter(hits[i + 1][0] - hits[i][0]
                       for i in range(len(hits) - 1))
        print(f"相邻间距 top8: {gaps.most_common(8)}")
        # 等差对齐校验
        s, _ = gaps.most_common(1)[0]
        off0 = Counter(o % s for o, _, _ in hits).most_common(1)[0][0]
        ok = sum(1 for o, _, _ in hits if o % s == off0)
        print(f"众数步长 0x{s:X}: 对齐 {ok}/{len(hits)}")


# -------------------------------------------------- C: 步长交叉验证
def secC_stride():
    banner("C、球员记录步长/条数 8 样本交叉验证")
    s0 = None
    for k in FILES:
        b = load(k)
        hits = player_hits(b)
        if not hits:
            print(f"[{k}] 命中 0")
            continue
        if len(hits) < 2:
            print(f"[{k}] 命中 {len(hits):5d}  首@0x{hits[0][0]:08X}  (不足两条, 无法统计间距)")
            continue
        gaps = Counter(hits[i + 1][0] - hits[i][0]
                       for i in range(len(hits) - 1))
        top = gaps.most_common(3)
        s = top[0][0]
        if s0 is None:
            s0 = s
        span = hits[-1][0] - hits[0][0]
        print(f"[{k}] 命中 {len(hits):5d}  首@0x{hits[0][0]:08X} "
              f"末@0x{hits[-1][0]:08X}  跨度0x{span:08X}  间距top3={top}")
    # 取 BL0 前两条命中做记录体对比 (步长 = 全局众数)
    b = load("BL0")
    hits = player_hits(b)
    if len(hits) >= 2 and s0:
        o1, o2 = hits[0][0], hits[1][0]
        print(f"\n记录体对比 (0x{o1:08X} vs 0x{o2:08X}, 步长0x{s0:X}):")
        for i in range(0, 0x80, 16):
            same = b[o1 + i:o1 + i + 16] == b[o2 + i:o2 + i + 16]
            print(f"  +0x{i:03X} {'==' if same else '!='} "
                  f"{hx(b, o1 + i, 16)} | {hx(b, o2 + i, 16)}")


# -------------------------------------------------- D: 赛事记录尾段字段
COMP_STRIDE = 0x314


def comp_bases(b):
    """沿用上轮结论: 名串@+0x2E2, 用余数众数定基址。"""
    names = []
    seg_lo, seg_hi = 0x1F0000, min(len(b), 0x200000)
    for m in CN_RE.finditer(b, seg_lo, seg_hi):
        try:
            t = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        if has_cjk(t):
            names.append(m.start())
    if not names:
        return [], names
    noff = Counter(o % COMP_STRIDE for o in names).most_common(1)[0][0]
    base = next(o for o in names if o % COMP_STRIDE == noff) - noff
    n = (min(len(b), 0x200000) - base) // COMP_STRIDE
    return base, n, noff


def secD_comp_fields():
    banner("D、赛事记录 +0x2C0~+0x2F4 候选字段 + 参赛 ID 值域")
    for k in ("BL0", "ML0"):
        b = load(k)
        base, nrec, noff = comp_bases(b)
        print(f"\n[{k}] 表基址 0x{base:06X}, {nrec} 条, 名串+0x{noff:X}")
        # +0x2C0~+0x2E2 按 u32 解读, 找"资金量级且千位整"字段
        slots = Counter()
        examples = {}
        for r in range(nrec):
            o = base + r * COMP_STRIDE
            if o + 0x2F4 > len(b):
                break
            for j in range(0x2C0, 0x2E2, 4):
                v = u32(b, o + j)
                if 100000 <= v <= 2000000000 and v % 1000 == 0:
                    slots[j] += 1
                    examples.setdefault(j, []).append((r, v))
        for j in sorted(slots):
            ex = examples[j][:4]
            print(f"  +0x{j:03X}: {slots[j]}/{nrec} 条命中, 例: "
                  f"{[(r, f'{v:,}') for r, v in ex]}")
        # 参赛 ID 值域
        allids = []
        for r in range(nrec):
            o = base + r * COMP_STRIDE + 0x40
            for j in range(0, 0x80, 4):
                v = u32(b, o + j)
                if v == 0xFFFFFFFF:
                    break
                allids.append(v)
        if allids:
            print(f"  参赛 ID 列表: 共 {len(allids)} 个, "
                  f"值域 [{min(allids)}, {max(allids)}]")


# -------------------------------------------------- E: 资金候选
def secE_money():
    banner("E、资金候选 (万位整数, 4 ML 样本交叉)")
    keys = ("ML0", "ML1", "ML2", "ML13")
    bufs = [load(k) for k in keys]
    n = min(len(x) for x in bufs)
    regions = ((0x11F2C0, 0x194000), (0x194000, 0x1F0000),
               (0x1F0000, min(0x280000, n)))
    for lo, hi in regions:
        cands = []
        for o in range(lo, hi - 4, 4):
            v0 = u32(bufs[0], o)
            if not (500000 <= v0 <= 2000000000) or v0 % 10000 != 0:
                continue
            vals = [u32(x, o) for x in bufs]
            if all(100000 <= v <= 2000000000 for v in vals) \
               and len(set(vals)) > 1:
                cands.append((o, vals))
        print(f"\n区 [0x{lo:06X}, 0x{hi:06X}): 候选 {len(cands)} 处")
        # 优先展示: 4 样本都万位整 且 变化幅度"温和" (<100 倍)
        strong = [(o, vs) for o, vs in cands
                  if all(v % 10000 == 0 for v in vs)
                  and max(vs) < 100 * min(vs)]
        for o, vs in (strong or cands)[:30]:
            print(f"  0x{o:08X}: " +
                  "  ".join(f"{k}={v:>13,}" for k, v in zip(keys, vs)))


# -------------------------------------------------- F: 赛程
def secF_schedule():
    banner("F、赛程: 日期三元组 + 球队 ID 对连续段")
    b = load("BL0")
    hits = [(m.start(), u16(b, m.start()), b[m.start() + 2],
             b[m.start() + 3]) for m in DATE_RE.finditer(b)]
    print(f"BL0 日期三元组 {len(hits)} 处 (u16年+月+日)")
    for o, y, mo, d in hits[:30]:
        print(f"  0x{o:08X}: {y}-{mo:02d}-{d:02d}")
    if len(hits) >= 2:
        gaps = Counter(hits[i + 1][0] - hits[i][0]
                       for i in range(len(hits) - 1))
        print(f"间距 top8: {gaps.most_common(8)}")
    # 球队 ID 对: 连续 4 字节对齐、值域 [1,800] 的 run
    print("\n球队 ID (1..800) 连续段扫描 [0x11F2C0, 0x280000):")
    runs = []
    o = 0x11F2C0
    start = None
    hi = min(0x280000, len(b) - 4)
    while o < hi:
        v = u32(b, o)
        if 1 <= v <= 800:
            if start is None:
                start = o
        else:
            if start is not None and o - start >= 64:
                runs.append((start, o))
            start = None
        o += 4
    if start is not None and hi - start >= 64:
        runs.append((start, hi))
    print(f"长度≥64B 的 run: {len(runs)} 段")
    for s, e in runs[:12]:
        vals = [u32(b, s + j) for j in range(0, min(e - s, 32), 4)]
        print(f"  [0x{s:08X}, 0x{e:08X}) {e-s}B  头8值={vals[:8]}")


SECTIONS = {"A": secA_census, "B": secB_pattern, "C": secC_stride,
            "D": secD_comp_fields, "E": secE_money, "F": secF_schedule}


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
