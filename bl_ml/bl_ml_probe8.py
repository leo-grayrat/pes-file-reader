#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第七轮 (probe8): 球员记录带深挖。

probe7 发现:
  - BL0 球员记录模式 (u32 双份 id=143939 + 中文名) 仅命中 0xB7E2C4 一处;
  - ML0 在 0xB7F300/0xB7F30E 有中文名串 (BL0 同区对应 0xB7E2CC), 两模式错位 ~0x1031;
  - 推测 0xB00000~0xC20000 存在"每球员一大块"的稀疏名表。
本轮:
  A. ML0 0xB7F300 与 BL0 0xB7E2C4 邻域大窗 dump 对比, 找记录头特征;
  B. 0xB00000~0xC80000 中文串 64KB 精细分桶 (BL0/ML0), 看是否等距分布;
  C. 放宽模式: "任意 u32(1000..400000) + ≤16 字节内中文串" 全带扫描,
     聚类间距定记录步长与条数;
  D. 步长候选确定后: 逐记录提取 (id?, 中文名, ASCII 名) 前 30 条验证真实性。

用法: python bl_ml_probe8.py [节号...]   纯标准库, 输入只读。
"""
import os
import re
import sys
import struct
import bisect
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


def chinese_hits(b, lo, hi):
    out = []
    for m in CN_RE.finditer(b, lo, min(hi, len(b))):
        try:
            t = m.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        if has_cjk(t):
            out.append((m.start(), t))
    return out


# -------------------------------------------------- A: 邻域大窗对比
def secA_windows():
    banner("A、BL0 0xB7E2C4 与 ML0 0xB7F300 邻域对比")
    for k, anchor in (("BL0", 0xB7E2C4), ("ML0", 0xB7F300)):
        b = load(k)
        print(f"\n[{k}] anchor=0x{anchor:08X}, 前后 0x80:")
        for o in range(anchor - 0x80, anchor + 0x80, 16):
            print(f"  0x{o:08X}: {hx(b, o, 16)}")
        # 前后找最近的非零块起点
        p = anchor
        while p > 0 and b[p - 1:p] != b"\x00":
            p -= 1
        print(f"  所在非零块起点: 0x{p:08X} (距 anchor 0x{anchor-p:X})")


# -------------------------------------------------- B: 精细分桶
def secB_buckets():
    banner("B、0xB00000~0xC80000 中文串 64KB 分桶")
    for k in ("BL0", "ML0"):
        b = load(k)
        hits = chinese_hits(b, 0xB00000, min(0xC80000, len(b)))
        buckets = Counter(o >> 16 for o, _ in hits)
        print(f"\n[{k}] 中文串共 {len(hits)} 个; 64KB 桶分布:")
        for bk in sorted(buckets):
            bar = "#" * min(buckets[bk], 60)
            print(f"  0x{bk:03X}0000: {buckets[bk]:4d} {bar}")
        # 前 12 个串内容
        for o, t in hits[:12]:
            print(f"  0x{o:08X} {t[:20]!r}")


# -------------------------------------------------- C: 放宽模式扫描
def loose_hits(b, lo=0xB00000, hi=0xC80000):
    cn = chinese_hits(b, lo, hi)
    cn_offs = [o for o, _ in cn]
    out = []
    for co, txt in cn:
        # 中文名前 16 字节内找"像 ID 的 u32"
        best = None
        for j in range(4, 20, 4):
            if co - j < lo:
                break
            v = u32(b, co - j)
            if 1000 <= v <= 400000:
                best = (co - j, v)
                break
        out.append((co, txt, best))
    return out


def secC_loose():
    banner("C、放宽模式: 中文名前 ≤16B 有 u32(1k..400k) 候选")
    for k in ("BL0", "ML0"):
        b = load(k)
        hits = loose_hits(b)
        with_id = [h for h in hits if h[2]]
        print(f"\n[{k}] 中文串 {len(hits)}, 带 ID 候选 {len(with_id)}")
        ids = Counter()
        for co, txt, best in with_id[:20]:
            print(f"  cn@0x{co:08X} {txt[:14]!r}  id@0x{best[0]:08X}={best[1]}")
        # 中文串自身间距众数 (不依赖 ID)
        allc = chinese_hits(b, 0xB00000, 0xC80000)
        if len(allc) >= 2:
            gaps = Counter(allc[i + 1][0] - allc[i][0]
                           for i in range(len(allc) - 1))
            print(f"  中文串间距 top8: {gaps.most_common(8)}")


# -------------------------------------------------- D: 记录枚举验证
def secD_enum():
    banner("D、按间距众数枚举记录 (前 30 条)")
    b = load("BL0")
    allc = chinese_hits(b, 0xB00000, 0xC80000)
    if len(allc) < 3:
        print("中文串过少, 跳过")
        return
    gaps = Counter(allc[i + 1][0] - allc[i][0]
                   for i in range(len(allc) - 1))
    print(f"间距 top5: {gaps.most_common(5)}")
    s, cnt = gaps.most_common(1)[0]
    if cnt < 5:
        print("众数间距支持不足, 改用逐条列举:")
        for o, t in allc[:30]:
            print(f"  0x{o:08X} {t[:24]!r}")
        return
    off0 = Counter(o % s for o, _ in allc).most_common(1)[0][0]
    base = next(o for o, _ in allc if o % s == off0) - off0
    ok = sum(1 for o, _ in allc if o % s == off0)
    nrec = (allc[-1][0] - base) // s + 1
    print(f"步长 0x{s:X}, 基址(名串基) 0x{base:08X}, 对齐 {ok}/{len(allc)}, "
          f"估记录数 {nrec}")
    # 逐条: 名串 + 往前 0x10 + ASCII 名搜索
    NAME_RE = re.compile(rb"[A-Z][A-Z .'&-]{2,30}[A-Z]")
    for r in range(min(30, nrec)):
        o = base + r * s
        nm = b[o:o + 36].split(b"\x00")[0]
        try:
            nm = nm.decode("utf-8")
        except UnicodeDecodeError:
            nm = nm.decode("latin1")
        # 记录内 ASCII 名 (名串后 0x100 内)
        am = NAME_RE.search(b, o, min(o + 0x120, len(b)))
        ascii_nm = am.group().decode() if am else "-"
        prev = hx(b, o - 0x10, 16)
        print(f"  #{r:3d} @0x{o:08X} 中={nm[:14]!r} ASCII={ascii_nm!r} "
              f"prev16={prev}")


SECTIONS = {"A": secA_windows, "B": secB_buckets,
            "C": secC_loose, "D": secD_enum}


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
