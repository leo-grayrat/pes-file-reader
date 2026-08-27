#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第四轮验证 (probe5)。

针对 probe4 发现做结构验证:
  A. 0x1F2A3C count=4 → 0x1F2AC4 起 4 个球员 ID: 全样本交叉验证;
  B. 0x1F468C 分队 ID 表: 记录步长 0x314、每队头部结构、队数验证;
  C. 0x370000~0x3F0000 球员记录带: u16 年月对密度 + 记录步长 0xB8 假设验证;
  D. 0xB7E309 'DARIO ESSUGO' 邻域: 姓名槽定位与步长;
  E. 球队记录 +0x54 float 解读;
  F. 0x1F2A42 起 UTF-8 串解码 (疑联赛/赛事名)。

用法: python bl_ml_probe5.py [节号...]   不带参数 = 全部节。
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
TEAM_START, TEAM_REC, TEAM_N = 0x100, 0x690, 700

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


def f32(b, o):
    return struct.unpack_from("<f", b, o)[0]


def hx(b, o, n=32):
    return " ".join(f"{x:02X}" for x in b[o:o + n])


def banner(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


# -------------------------------------------------- A: count 与 ID 列表交叉验证
def secA_count():
    banner("A、0x1F2A3C count 与 0x1F2AC4 ID 列表 (全样本)")
    for k in FILES:
        b = load(k)
        cnt = u32(b, 0x1F2A3C)
        ids = [u32(b, 0x1F2AC4 + 4 * i) for i in range(16)]
        shown = [f"0x{v:X}" for v in ids[:min(cnt + 1, 16)]]
        if cnt < 16:
            shown.append(f"第{cnt + 1}个=0x{ids[cnt]:X}" +
                         (" (FF哨兵)" if ids[cnt] == 0xFFFFFFFF else ""))
        print(f"  [{k}] count={cnt}  IDs={shown}")


# -------------------------------------------------- B: 分队 ID 表
def secB_squad():
    banner("B、0x1F468C 分队 ID 表")
    REC, IDOFF = 0x314, 0x1F468C
    for k in ("BL0", "ML0", "ML13"):
        b = load(k)
        print(f"\n[{k}] 假设记录 0x314: 前 8 条的 头部24B + ID序列(前5..尾2)")
        for r in range(8):
            o = IDOFF + r * REC
            head = hx(b, o, 24)
            # ID 段: 从 +0x14 起到记录尾, 取非负小整数
            ids = []
            for i in range(o + 0x14, o + REC, 4):
                v = u32(b, i)
                if v < 0x7FFFFFFF:
                    ids.append(v)
            shown = ids[:5] + (["..."] if len(ids) > 7 else []) + ids[-2:]
            print(f"  #{r} @0x{o:06X} head={head}")
            print(f"       IDs({len(ids)}): {shown}")
        # 记录间连续性: 各记录 ID 是否恰好衔接上一队末尾+1
        join_ok = 0
        prev_end = None
        for r in range(40):
            o = IDOFF + r * REC
            ids = [u32(b, i) for i in range(o + 0x14, o + REC, 4)
                   if u32(b, i) < 0x7FFFFFFF]
            if ids and prev_end is not None and ids[0] == prev_end + 1:
                join_ok += 1
            prev_end = ids[-1] if ids else prev_end
        print(f"  前40条中 '首ID=上队尾ID+1' 成立 {join_ok} 次")
    # 0x1F468C 上方: 是否有队数/表头
    b = load("BL0")
    print("\n[BL0] 0x1F4640~0x1F468C 表头区:")
    for o in range(0x1F4640, 0x1F468C, 4):
        v = u32(b, o)
        print(f"  0x{o:06X}: {v:10d} 0x{v:08X}")


# -------------------------------------------------- C: 球员记录带
def secC_player_band():
    banner("C、0x300000~0x450000: u16 年月对密度图 (每 0x10000 一格)")
    ym_re = re.compile(rb"[\xe0-\xec]\x07[\x01-\x0c]\x00")
    for k in ("BL0", "ML0"):
        b = load(k)
        print(f"\n[{k}]:")
        for blk in range(0x30, 0x46):
            s, e = blk << 16, (blk + 1) << 16
            hits = [m.start() for m in ym_re.finditer(b, s, min(e, len(b)))]
            if hits:
                print(f"  0x{s:06X}~0x{e:06X}: {len(hits)} 个, "
                      f"首个@0x{hits[0]:06X} 末个@0x{hits[-1]:06X}")
    # 对首个密集区验证步长 0xB8
    b = load("BL0")
    hits = [m.start() for m in ym_re.finditer(b, 0x370000, 0x3F0000)]
    if hits:
        gaps = Counter(hits[i + 1] - hits[i] for i in range(len(hits) - 1))
        print(f"\n[BL0] 该带内相邻年月对间距 top8: "
              f"{[(f'{g:03X}', c) for g, c in gaps.most_common(8)]}")
        base = hits[0]
        print(f"[BL0] 以首个@0x{base:06X} 为基准, 每 0xB8 采样 (前10条):")
        for i in range(10):
            o = base + i * 0xB8
            y, m = u16(b, o), u16(b, o + 2)
            good = 2015 <= y <= 2030 and 1 <= m <= 12
            print(f"  @0x{o:06X}: ym={y}-{m:02d} {'OK' if good else '..'}  "
                  f"rec-8: {hx(b, o-8, 8)}")


# -------------------------------------------------- D: 姓名槽
def secD_nameslot():
    banner("D、'DARIO ESSUGO' 邻域 (BL0 0xB7E2E0 起)")
    b = load("BL0")
    for o in range(0xB7E2E0, 0xB7E4E0, 16):
        ascii_part = "".join(chr(x) if 32 <= x < 127 else "."
                             for x in b[o:o + 16])
        print(f"  0x{o:08X}: {hx(b, o, 16)}  {ascii_part}")
    # 以 0xB7E309 为槽内偏移, 试常见步长找后续姓名
    print("\n以 0xB7E309 为姓名槽起点偏移, 步长候选扫描 (前12槽是否为大写字母开头):")
    base = 0xB7E309
    for stride in (56, 60, 64, 88, 104, 112, 128, 144, 160, 176, 184, 200,
                   216, 232, 248, 264, 280, 296, 312, 0x690):
        hit = 0
        sample = ""
        for i in range(1, 13):
            o = base + i * stride
            if o + 3 < len(b) and 65 <= b[o] <= 90:
                hit += 1
                if not sample:
                    m = re.match(rb"[\x20-\x7e]{3,}", b[o:o + 24])
                    sample = m.group().decode() if m else ""
        if hit >= 8:
            print(f"  步长 {stride} (0x{stride:X}): {hit}/12 命中  样例 {sample!r}")


# -------------------------------------------------- E: 球队记录 +0x54 float
def secE_teamfloat():
    banner("E、球队记录 +0x54 的 float 解读 (700 队)")
    b = load("BL0")
    vals = [f32(b, TEAM_START + r * TEAM_REC + 0x54) for r in range(TEAM_N)]
    nz = [v for v in vals if v != 0]
    print(f"  非零 {len(nz)}/700, 范围 {min(nz):.2f} ~ {max(nz):.2f}, "
          f"均值 {sum(nz)/len(nz):.2f}")
    for r in (0, 1, 4, 7, 33, 100, 699):
        o = TEAM_START + r * TEAM_REC
        name = b[o + 0x55:o + 0x75].split(b"\x00")[0].decode("ascii", "replace")
        print(f"  队#{r} {name[:18]:<18} +0x54={f32(b, o+0x54):.2f}")


# -------------------------------------------------- F: UTF-8 串解码
def secF_utf8():
    banner("F、0x1F0000~0x200000 内 UTF-8 中文字符串")
    b = load("BL0")
    seg = b[0x1F0000:0x200000]
    # 连续多字节序列 (E4-E9 开头) 提取
    for m in re.finditer(rb"(?:[\xe0-\xef][\x80-\xbf]{2}|[\x20-\x7e]){4,}", seg):
        raw = m.group()
        if any(x >= 0xE0 for x in raw):
            try:
                txt = raw.decode("utf-8").strip()
                if any("\u4e00" <= c <= "\u9fff" for c in txt):
                    print(f"  0x{0x1F0000 + m.start():06X}: {txt!r}")
            except UnicodeDecodeError:
                pass
    # 0x1F2A40 记录细读
    o = 0x1F2A40
    print(f"\n[BL0] 0x1F2A40 记录细读:")
    print(f"  +00 u32 = 0x{u32(b, o):08X}")
    print(f"  +04 u16 = 0x{u16(b, o+4):04X}")
    print(f"  +06 u16 = 0x{u16(b, o+6):04X} ({u16(b, o+6)})")
    print(f"  +08 u16 = 0x{u16(b, o+8):04X} ({u16(b, o+8)})")
    print(f"  +0A u16 = 0x{u16(b, o+0xA):04X} ({u16(b, o+0xA)})")
    print(f"  +0C u32 = {u32(b, o+0xC)}")
    m = re.match(rb"(?:[\xe0-\xef][\x80-\xbf]{2}|[\x20-\x7e])+", b[o+0x10:o+0x40])
    if m:
        try:
            print(f"  +10 串 = {m.group().decode('utf-8')!r}")
        except UnicodeDecodeError:
            print(f"  +10 串(原始) = {hx(b, o+0x10, 24)}")


SECTIONS = {
    "A": secA_count, "B": secB_squad, "C": secC_player_band,
    "D": secD_nameslot, "E": secE_teamfloat, "F": secF_utf8,
}


def main():
    picks = [a for a in sys.argv[1:] if a.upper() in SECTIONS] or list(SECTIONS)
    for p in picks:
        SECTIONS[p.upper()]()
    print("\n完成。")


if __name__ == "__main__":
    main()