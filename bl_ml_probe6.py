#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第五轮验证 (probe6)。

probe5 发现:
  - 0x1F0000~0x200000: 赛事定义表, UTF-8 中文赛事名间距 0x314, 内嵌 u32 ID 列表;
  - BL0 0xB7E309/0xB7E346: 球员名 'DARIO ESSUGO' 两处, 其后有 u16 年份 (E7 07 = 2023);
  - 0x1F2A3C: u32 = 0x004FFFFF 等, 非 count, 需重解读。
本轮验证:
  A. 赛事记录边界: 以名串对齐反推记录基址/步长, 逐条列出;
  B. 0xB7E000 邻域大写姓名串全集 + 间距, 定球员名表;
  C. 'DARIO ESSUGO' 记录结构细读 (u16 年份/计数字段);
  D. 资金候选: ML0 中 1e6~2e9 的 u32, 与 ML13 对比变化者 (赛程推进证据)。

用法: python bl_ml_probe6.py [节号...]   不带参数 = 全部节。
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


# -------------------------------------------------- A: 赛事记录结构
def secA_comp():
    banner("A、赛事表记录结构: 名串等距 0x314 反推")
    b = load("BL0")
    names = []
    seg = b[0x1F0000:0x200000]
    for m in re.finditer(rb"(?:[\xe0-\xef][\x80-\xbf]{2})[\x80-\xbf\xe0-\xef\x20-\x7e]{5,40}",
                         seg):
        try:
            txt = m.group().decode("utf-8")
            if any("\u4e00" <= c <= "\u9fff" for c in txt):
                names.append((0x1F0000 + m.start(), txt))
        except UnicodeDecodeError:
            pass
    print(f"中文赛事名 {len(names)} 个; 相邻间距: "
          f"{Counter(names[i+1][0]-names[i][0] for i in range(len(names)-1)).most_common(4)}")
    stride = 0x314
    # 名串偏移可能有 ASCII 前缀干扰, 用余数众数定记录内偏移;
    # 取与 name_off 同余的首个名串定基址。
    name_off = Counter(o % stride for o, _ in names).most_common(1)[0][0]
    base = next(o for o, _ in names if o % stride == name_off) - name_off
    # 校验: 所有名串是否都落在 base + r*stride + name_off
    ok = sum(1 for o, _ in names if (o - base - name_off) % stride == 0)
    print(f"记录内名串偏移 +0x{name_off:X}, 基址 0x{base:06X}, "
          f"对齐校验 {ok}/{len(names)}")
    print(f"逐条记录 (前 12): 名@+0x{name_off:X}")
    for r in range(min(12, len(names))):
        o = base + r * stride
        nm = b[o + name_off:o + name_off + 48].split(b"\x00")[0]
        try:
            nm = nm.decode("utf-8")
        except UnicodeDecodeError:
            nm = nm.decode("latin1")
        # 记录头 16 字节
        print(f"  #{r:2d} @0x{o:06X}: head={hx(b, o, 16)}  名={nm!r}")
    # 记录尾部是否有 ID 列表 (在名串之后找首个连续递增段)
    o = base
    print(f"\n记录 #0 全量解读 (0x{o:06X} 起 {stride} 字节):")
    for i in range(0, stride, 16):
        print(f"  +0x{i:03X}: {hx(b, o + i, 16)}")


# -------------------------------------------------- B: 球员名表
def secB_names():
    banner("B、0xB00000~0xC1C6EF 大写姓名串全集")
    NAME_RE = re.compile(rb"[A-Z][A-Z .'&-]{3,30}[A-Z]")
    for k in ("BL0", "ML0"):
        b = load(k)
        hits = []
        for m in NAME_RE.finditer(b, 0xB00000, min(len(b), 0xC1C6EF)):
            s = m.group().decode("ascii").strip(" .'&-")
            if sum(c.isalpha() for c in s) >= 5 and " " in s:
                hits.append((m.start(), s))
        print(f"\n[{k}] 含空格大写串 {len(hits)} 个:")
        for o, s in hits[:30]:
            print(f"  0x{o:08X} {s!r}")
        if len(hits) > 30:
            print(f"  ... 共 {len(hits)} 个")
        if len(hits) >= 2:
            gaps = Counter(hits[i + 1][0] - hits[i][0]
                           for i in range(len(hits) - 1))
            print(f"  相邻间距 top6: {gaps.most_common(6)}")


# -------------------------------------------------- C: DARIO ESSUGO 记录细读
def secC_essugo():
    banner("C、BL0 'DARIO ESSUGO' 记录细读")
    b = load("BL0")
    p = b.find(b"DARIO ESSUGO")
    # 记录起点: 往前找最近的 16 字节对齐的 非零-结构 起点 (显示 0x100 上下文)
    print(f"名串 @0x{p:06X}; 往前 0x60 字节:")
    for o in range(p - 0x60, p, 0x10):
        print(f"  0x{o:08X}: {hx(b, o, 16)}")
    # 名串之后 0x140 逐 16 行, 标注 u16 年份
    print(f"\n名串之后 0x140 字节 (标注 u16 年份/常见小整数):")
    for o in range(p + 16, p + 0x140, 16):
        marks = []
        for j in range(0, 16, 2):
            v = u16(b, o + j)
            if 2015 <= v <= 2035:
                marks.append(f"+{j:X}:年{v}")
        line = hx(b, o, 16)
        print(f"  0x{o:08X}: {line}  {'; '.join(marks)}")
    # 两份名字: 相对同一记录基址的偏移
    p2 = b.find(b"DARIO ESSUGO", p + 1)
    print(f"\n两处名串: 0x{p:06X} 与 0x{p2:06X}, 相距 0x{p2-p:X}")


# -------------------------------------------------- D: 资金候选
def secD_money():
    banner("D、ML0 资金候选 (1e6~2e9 u32, 与 ML13 不同值者)")
    a, b = load("ML0"), load("ML13")
    n = min(len(a), len(b))
    # 扫描重点区: 0x11F2C0~0x194000 (动态区) 与 0x1F0000~0x200000
    for lo, hi in ((0x11F2C0, 0x194000), (0x1F0000, 0x200000),
                   (0x194000, 0x1F0000)):
        hi = min(hi, n)
        hits = []
        for o in range(lo, hi - 4, 4):
            va = u32(a, o)
            vb = u32(b, o)
            if 1000000 <= va <= 2000000000 and va != vb and \
               1000000 <= vb <= 2000000000:
                hits.append((o, va, vb))
        print(f"\n区 [0x{lo:06X}, 0x{hi:06X}): 双样本都在资金值域且变化: {len(hits)} 处")
        for o, va, vb in hits[:25]:
            print(f"  0x{o:08X}: ML0={va:>13,}  ML13={vb:>13,}  Δ={vb-va:+,}")


SECTIONS = {"A": secA_comp, "B": secB_names, "C": secC_essugo, "D": secD_money}


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
