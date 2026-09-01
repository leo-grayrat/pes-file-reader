#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第十三轮 (probe14): 语义化 + 资金盲定位 + 对阵链。

结合 docs/exe_analysis.md 的 Lua 键池 (season_num/competition_id/fixture/
team_id/scorer/win_lose…) 做字段语义对齐:
  A. 赛事定义表记录逐槽语义分类 (76 条 × 0x314, 每 4 字节槽统计);
  B. 比赛日记录对阵链: +0x30 条目 / +0x170 区小整数枚举 + 指针分类,
     全记录值域普查找主队/客队候选;
  C. 资金盲定位一: 组间差分 —— A 组 (BL0/BL1/ML2, 713 比赛日)
     vs B 组 (ML0/ML1/ML13, 1473 比赛日), 万位整/浮点金额签名;
  D. 资金盲定位二: 进度对差分 (BL0↔BL1、ML0↔ML13) 动态区变动值
     中筛"金额样" (千/万位整、温和 Δ)。

用法: python bl_ml_probe14.py [节号...]   纯标准库, 输入只读。
"""
import os
import re
import sys
import struct
import statistics
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
CN_RE = re.compile(rb"(?:[\xe0-\xef][\x80-\xbf]{2}){2,24}")
COMP_STRIDE = 0x314
SCHED_STRIDE = 0x254
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


def hx(b, o, n=32):
    return " ".join(f"{x:02X}" for x in b[o:o + n])


def banner(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


def comp_base(b):
    names = []
    for m in CN_RE.finditer(b, 0x1F0000, min(len(b), 0x200000)):
        try:
            t = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        if any("\u4e00" <= c <= "\u9fff" for c in t):
            names.append(m.start())
    noff = Counter(o % COMP_STRIDE for o in names).most_common(1)[0][0]
    base = next(o for o in names if o % COMP_STRIDE == noff) - noff
    nrec = (min(len(b), 0x200000) - base) // COMP_STRIDE
    return base, nrec, noff


def sched_base(b):
    hits = [m.start() for m in DATE_RE.finditer(b, 0x11F2C0, 0x400000)]
    if not hits:
        return None, 0, 0
    off0 = Counter(o % SCHED_STRIDE for o in hits).most_common(1)[0][0]
    first = next(o for o in hits if o % SCHED_STRIDE == off0)
    return first - off0, len(hits), off0


# -------------------------------------------------- A: 赛事表逐槽语义
def secA_comp_semantics():
    banner("A、赛事定义表逐槽语义分类 (BL0, 76 条)")
    b = load("BL0")
    base, nrec, noff = comp_base(b)
    print(f"基址 0x{base:06X}, {nrec} 条, 名串+0x{noff:X}")
    for j in range(0, 0x314, 4):
        vals = []
        for r in range(nrec):
            o = base + r * COMP_STRIDE + j
            if o + 4 <= len(b):
                vals.append(u32(b, o))
        if not vals:
            continue
        un = set(vals)
        n_ff = sum(1 for v in vals if v == 0xFFFFFFFF)
        tag = ""
        if len(un) == 1:
            v = vals[0]
            tag = f"常量 {v} (0x{v:X})" if v not in (0, 0xFFFFFFFF) else \
                  ("零" if v == 0 else "全 FF")
        elif len(un) <= 12 and n_ff < nrec * 0.5:
            tag = f"小枚举 {sorted(un)[:12]}"
        elif n_ff >= nrec * 0.5:
            tag = f"FF 主导 ({n_ff}/{nrec})"
        elif all(1 <= v <= 1200 or v == 0xFFFFFFFF for v in vals):
            tag = f"ID 列值域 [{min(v for v in vals if v != 0xFFFFFFFF)}," \
                  f"{max(vals)}]"
        elif all(v == 0 or 10000 <= v <= 2000000000 for v in vals) \
                and sum(1 for v in vals if v >= 10000) >= 3:
            tag = f"金额候选 [{min(vals):,}~{max(vals):,}]"
        if tag:
            print(f"  +0x{j:03X}: {tag}")


# -------------------------------------------------- B: 比赛日对阵链
def secB_fixture():
    banner("B、比赛日记录: +0x170 区小整数与指针普查 (BL0)")
    b = load("BL0")
    base, nrec, off0 = sched_base(b)
    print(f"基址 0x{base:08X}, {nrec} 条")
    # +0x170 起按 20 字节假设条目 (u32 值 + u32 指针 + 00000000 + 附加)
    small_vals = Counter()
    ptrs_hi = Counter()
    n_slots = 0
    for r in range(nrec):
        o = base + r * SCHED_STRIDE + 0x170
        while o + 16 <= base + r * SCHED_STRIDE + SCHED_STRIDE:
            v = u32(b, o)
            p = u32(b, o + 4)
            if v == 0xFFFFFFFF:
                break
            if 1 <= v <= 800:
                small_vals[v] += 1
            if 0x100 < p < len(b):
                ptrs_hi[(p >> 16) & 0xFF] += 1
                n_slots += 1
            o += 20
    print(f"+0x170 区条目 (步长 20 假设): 指针槽 {n_slots} 个")
    print(f"  小整数值域: [{min(small_vals)}, {max(small_vals)}], "
          f"独立值 {len(small_vals)} 个")
    print(f"  值频次 top10: {small_vals.most_common(10)}")
    print(f"  指针高字节分布: {ptrs_hi.most_common(6)}")
    # +0x30 条目区: 第 2 个 u32 (j+4) 普查
    second = []
    for r in range(min(50, nrec)):
        o = base + r * SCHED_STRIDE + 0x30
        for j in range(0, 0xB0, 0x10):
            if u16(b, o + j) >= 0xFFFF:
                break
            second.append(u32(b, o + j + 4))
    print(f"\n+0x30 条目第 2 u32: {len(second)} 个, "
          f"值域 [0x{min(second):X}, 0x{max(second):X}], "
          f"独立 {len(set(second))}")
    # 抽 3 条记录完整展示 +0x170 区
    print("\n记录 0/1/2 的 +0x160~+0x230:")
    for r in range(3):
        o = base + r * SCHED_STRIDE
        print(f"  #{r}: {hx(b, o + 0x160, 0x30)}")
        print(f"      {hx(b, o + 0x190, 0x30)}")


# -------------------------------------------------- C: 组间差分 (资金)
def money_sig(b, o):
    v = u32(b, o)
    if 50000 <= v <= 2000000000 and v % 1000 == 0:
        return ("int", v)
    f = f32(b, o)
    if f == f and 1e5 <= f <= 2e9 and abs(f) < 1e10:
        return ("float", f)
    return None


def secC_group_diff():
    banner("C、资金组间差分: A=(BL0,BL1,ML2) vs B=(ML0,ML1,ML13)")
    GA = ("BL0", "BL1", "ML2")
    GB = ("ML0", "ML1", "ML13")
    bufs = {k: load(k) for k in GA + GB}
    n = min(len(bufs[k]) for k in GA + GB)
    regions = ((0x100, 0x11F2C0, "头部+球队区"),
               (0x11F2C0, 0x194000, "动态区"),
               (0x194000, min(0x1F0000, n), "配置区"))
    for lo, hi, tag in regions:
        hits = []
        for o in range(lo, hi - 4, 4):
            sa = [money_sig(bufs[k], o) for k in GA]
            sb = [money_sig(bufs[k], o) for k in GB]
            if not all(sa) or not all(sb):
                continue
            ta = {s for s, _ in sa}
            tb = {s for s, _ in sb}
            va = [v for _, v in sa]
            vb = [v for _, v in sb]
            # 组内一致 (同类签名且值接近), 组间显著不同
            if len(ta) == 1 and len(tb) == 1 and \
               max(va) < 3 * max(min(va), 1) and max(vb) < 3 * max(min(vb), 1):
                ma, mb = statistics.mean(va), statistics.mean(vb)
                if ma > 0 and mb > 0 and (mb / ma > 1.5 or ma / mb > 1.5):
                    hits.append((o, ta.pop(), va, vb))
        print(f"\n{tag} [0x{lo:06X}, 0x{hi:06X}): 组间系统差异 {len(hits)} 处")
        for o, t, va, vb in hits[:30]:
            print(f"  0x{o:08X} ({t}): A={[f'{v:,.0f}' for v in va]} "
                  f"B={[f'{v:,.0f}' for v in vb]}")


# -------------------------------------------------- D: 进度对差分
def secD_progress_diff():
    banner("D、进度对差分诊断 (动态区+配置区)")
    for ka, kb in (("BL0", "BL1"), ("ML0", "ML13")):
        a, b = load(ka), load(kb)
        n = min(len(a), len(b))
        nchg = 0
        big = []          # 任一端 ≥ 100000 的变动值 (不看整除)
        rounds = []       # 双端千位整的金额样
        for o in range(0x11F2C0, min(0x500000, n) - 4, 4):
            va, vb = u32(a, o), u32(b, o)
            if va == vb:
                continue
            nchg += 1
            hi_v = max(va, vb)
            if hi_v >= 100000:
                big.append((o, va, vb))
            if all(50000 <= v <= 2000000000 for v in (va, vb)) \
               and va % 1000 == 0 and vb % 1000 == 0:
                rounds.append((o, va, vb))
        print(f"\n[{ka}↔{kb}] 变动 u32 共 {nchg} 个; "
              f"其中任一端≥100,000 的 {len(big)} 个; 双端千位整 {len(rounds)} 个")
        print("千位整金额样:")
        for o, va, vb in rounds[:40]:
            print(f"  0x{o:08X}: {va:>13,} → {vb:>13,}  Δ={vb-va:+,}")
        # 大值变动按值域分档统计 (看量级构成)
        mag = Counter()
        for o, va, vb in big:
            m = max(va, vb)
            mag[10 ** len(str(m))] += 1
        print(f"大值变动量级分布: {sorted(mag.items())}")
        # 抽最大绝对值的 15 个看语义 (含 float/有符号试读)
        big_sorted = sorted(big, key=lambda t: -abs(t[2] - t[1]))[:15]
        print("|Δ| top15:")
        for o, va, vb in big_sorted:
            fa = struct.unpack_from("<f", a, o)[0]
            fb = struct.unpack_from("<f", b, o)[0]
            sa = struct.unpack_from("<i", a, o)[0]
            sb_ = struct.unpack_from("<i", b, o)[0]
            print(f"  0x{o:08X}: {va:,}→{vb:,}  (s:{sa:,}→{sb_:,}) "
                  f"(f:{fa:.4g}→{fb:.4g})")
        if big:
            mod_dist = Counter(o % 0x314 for o, *_ in big).most_common(3)
            mod_dist2 = Counter(o % 0x254 for o, *_ in big).most_common(3)
            print(f"大值变动偏移 mod 0x314 top3: {mod_dist}")
            print(f"大值变动偏移 mod 0x254 top3: {mod_dist2}")
        # 连续段检测: 任一端在 [10000, 2e9] 的变动 4 字节, 找 ≥12 字节连续带 (数组错位)
        cand = []
        for o in range(0x11F2C0, min(0x500000, n) - 4, 4):
            va, vb = u32(a, o), u32(b, o)
            if va != vb and (10000 <= va <= 2000000000
                             or 10000 <= vb <= 2000000000):
                cand.append(o)
        runs = []
        if cand:
            s0 = cand[0]
            p = cand[0]
            for o in cand[1:]:
                if o - p > 4:
                    if p - s0 >= 12:
                        runs.append((s0, p + 4))
                    s0 = o
                p = o
            if p - s0 >= 12:
                runs.append((s0, p + 4))
        print(f"变动中值连续带 (≥12B, 值∈[10000,2e9]) {len(runs)} 条:")
        for s, e in runs[:25]:
            print(f"  [0x{s:08X},0x{e:08X}) {e-s}B: "
                  f"{ka}={u32(a, s):,}..{u32(a, e-4):,}  "
                  f"{kb}={u32(b, s):,}..{u32(b, e-4):,}")


SECTIONS = {"A": secA_comp_semantics, "B": secB_fixture,
            "C": secC_group_diff, "D": secD_progress_diff}


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
