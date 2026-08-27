#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第三轮深挖 (probe4)。

基于 probe3 的发现做定向深挖:
  - probe3 在 BL0 0xB7E309 发现明文球员名 'DARIO ESSUGO' → 找球员姓名表;
  - 0x11F2C0~0x170000 有由 00~27 小整数组成的洗牌序列 → 疑赛程/排序表;
  - 0x194000 区块含 'FF FF F7 07' 模式 → 探记录边界;
  - ML 0x1F2AD4 起有连续递增 u32 (0x5AF=1455...) → 疑球员 ID 列表;
  - 未找到日期/资金 → 扩大编码假设 (u16 年月 / float)。

用法: python bl_ml_probe4.py [节号...]   不带参数 = 全部节。
节号: 1 球员姓名表 2 洗牌序列 3 F707记录 4 ID列表区 5 资金日期补扫
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
TEAM_END = TEAM_START + TEAM_REC * TEAM_N   # 0x11F2C0
NAME_RE = re.compile(rb"[A-Z][A-Z .'&-]{2,38}")

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


# ---------------------------------------------------------------- 节1 球员姓名表
def find_names(b, region, minlen=6):
    """在 region=(s,e) 内找大写姓名串: 全大写字母+空格标点, 且含 >=2 字母。"""
    out = []
    for m in NAME_RE.finditer(b[region[0]:region[1]]):
        s = m.group().decode("ascii").rstrip(" .'&-")
        if len(s) >= minlen and sum(c.isalpha() for c in s) >= 4:
            out.append((region[0] + m.start(), s))
    return out


def sec1_names():
    banner("一、球员姓名表定位")
    for k in ("BL0", "ML0"):
        b = load(k)
        names = find_names(b, (0x200000, 0xC1C6EF))
        print(f"\n[{k}] 0x200000~0xC1C6EF 姓名样串 {len(names)} 个")
        if not names:
            continue
        for o, s in names[:15]:
            print(f"  0x{o:08X} {s!r}  前8字节:{hx(b, o-8, 8)}")
        # 间隔分布: 相邻姓名偏移差
        diffs = Counter(names[i + 1][0] - (names[i][0] + len(names[i][1]) + 1)
                        for i in range(len(names) - 1) if i < 3000)
        print(f"  相邻串间隔分布 top6: {diffs.most_common(6)}")
        # 固定长度槽位检测: 以首个姓名偏移为基准, 尝试槽长 32..64
        base = names[0][0]
        for slot in (32, 36, 40, 48, 60, 64):
            hit = 0
            for i in range(2, min(40, len(names))):
                o = base + i * slot
                if o + 4 < len(b) and b[o:o + 1].isalpha():
                    hit += 1
            if hit >= 20:
                print(f"  槽长 {slot}: 前40槽中 {hit} 个以字母开头 ← 定长候选")
    # 所有样本里 'DARIO ESSUGO' 落点
    print("\n全样本 'DARIO ESSUGO' 落点:")
    for k in FILES:
        b = load(k)
        o = b.find(b"DARIO ESSUGO")
        while o >= 0:
            print(f"  [{k}] 0x{o:08X}")
            o = b.find(b"DARIO ESSUGO", o + 1)


# ---------------------------------------------------------------- 节2 洗牌序列
def sec2_shuffle():
    banner("二、0x11F2C0~0x194000: 小整数洗牌序列区块")
    for k in ("BL0", "ML0"):
        b = load(k)
        seg = b[TEAM_END:0x194000]
        nz = sum(1 for x in seg if x)
        vals = [x for x in seg if x]
        print(f"\n[{k}] 段长 0x{len(seg):X}, 非零 {nz} 字节 "
              f"({100.0*nz/len(seg):.1f}%), 值域 {min(vals):02X}~{max(vals):02X}")
        vc = Counter(vals)
        print(f"  值分布 top10: {[(f'{v:02X}', c) for v, c in vc.most_common(10)]}")
        # 找非零 run 的起止与长度分布
        runs = []
        for m in re.finditer(rb"[^\x00]{8,}", seg):
            runs.append((m.start() + TEAM_END, m.end() + TEAM_END))
        lc = Counter((e - s) for s, e in runs)
        print(f"  非零 run {len(runs)} 个, 长度分布 top8: {lc.most_common(8)}")
        # 常见 run 长度 -> 记录单位推测; 抽 2 个样例展示
        for s, e in runs[:6]:
            print(f"  run [0x{s:06X},0x{e:06X}) len={e-s}: {hx(b, s, min(28, e-s))}")
        # run 起点间距是否恒定
        if len(runs) > 10:
            gaps = Counter(runs[i + 1][0] - runs[i][0] for i in range(len(runs) - 1))
            print(f"  run 起点间距 top5: {[(f'{g:04X}', c) for g, c in gaps.most_common(5)]}")


# ---------------------------------------------------------------- 节3 F707 记录
def sec3_f707():
    banner("三、0x194000 区块内 'FF FF F7 07' 模式分析")
    for k in ("BL0", "ML0"):
        b = load(k)
        locs = []
        o = b.find(b"\xff\xff\xf7\x07", 0x194000, 0xC1C6EF)
        while o >= 0 and len(locs) < 6000:
            locs.append(o)
            o = b.find(b"\xff\xff\xf7\x07", o + 1, 0xC1C6EF)
        print(f"\n[{k}] 模式出现 {len(locs)} 次")
        if not locs:
            continue
        gaps = Counter(locs[i + 1] - locs[i] for i in range(len(locs) - 1))
        print(f"  相邻间距 top8: {[(f'{g:04X}', c) for g, c in gaps.most_common(8)]}")
        d0 = gaps.most_common(1)[0][0] if gaps else 0
        ok = sum(c for g, c in gaps.items() if g == d0)
        print(f"  众数间距 0x{d0:X}, 精确符合 {ok}/{len(locs)-1} 次")
        # 展示 4 条记录 (以众数间距为记录长)
        if d0:
            for idx in range(4):
                o = locs[0] + idx * d0
                if o + 8 <= len(b):
                    print(f"  @0x{o:06X}: {hx(b, o, min(40, d0))}")
        # 区块起点结构: 前 0x40 字节与首个模式的关系
        print(f"  区块头 0x194000: {hx(b, 0x194000, 16)}")
        print(f"  首个模式 @0x{locs[0]:06X} (距区块头 0x{locs[0]-0x194000:X})")


# ---------------------------------------------------------------- 节4 ID 列表区
def sec4_idlist():
    banner("四、0x1F0000~0x200000: 递增 ID 列表与周边")
    for k in ("ML0", "BL0"):
        b = load(k)
        print(f"\n[{k}]")
        # 找连续递增 u32 序列 (步长1, 长度>=8)
        runs = []
        i = 0x1F0000
        while i < 0x200000 - 8:
            v = u32(b, i)
            if 1 <= v < 100000 and all(u32(b, i + 4 * t) == v + t for t in range(8)):
                j = i
                vv = v
                while j + 4 < 0x200000 and u32(b, j) == vv:
                    j += 4
                    vv += 1
                runs.append((i, (j - i) // 4, v))
                i = j
            else:
                i += 4
        for s, cnt, v0 in runs[:12]:
            print(f"  递增u32 @0x{s:06X}: {cnt} 个, 自 {v0} 起")
        # 0x1F2A00 附近逐行 hexdump
        for o in range(0x1F2A00, 0x1F2C00, 0x40):
            nz = sum(1 for x in b[o:o + 0x40] if x != 0xFF and x != 0)
            if nz:
                print(f"  0x{o:06X}: {hx(b, o, 48)}")
        # FF 填充检测: 该窗口是否大量 0xFF
        ff = sum(1 for x in b[0x1F0000:0x200000] if x == 0xFF)
        nz = sum(1 for x in b[0x1F0000:0x200000] if x not in (0, 0xFF))
        print(f"  0x1F0000~0x200000: FF={ff/1024:.1f}KB 有效非零非FF={nz/1024:.1f}KB")


# ---------------------------------------------------------------- 节5 资金日期补扫
def sec5_money_date():
    banner("五、资金/日期补扫 (float 金额, u16 年月, 球队记录内)")
    # 5a: float 金额扫描 (0x200000 起, 4字节对齐)
    for k in ("BL0", "ML0"):
        b = load(k)
        start, end = 0x200000, min(len(b), 0xC1C6EF)
        count = (end - start) // 4
        arr = struct.unpack_from(f"<{count}f", b, start)
        hits = []
        for i, v in enumerate(arr):
            if 1e5 <= v <= 3e8 and v == round(v, -3):
                hits.append((start + i * 4, v))
        print(f"\n[{k}] float 金额候选 (1e5~3e8, 千位整): {len(hits)} 处")
        for o, v in hits[:15]:
            print(f"  0x{o:08X}: {v:,.0f}")
    # 5b: u16 年月对 (year 2019~2027, month 1~12 紧邻) —— 用正则加速:
    # 年 2019~2027 小端 = E3 07 ~ EB 07, 月 01 00 ~ 0C 00
    ym_re = re.compile(rb"[\xe3-\xeb]\x07[\x01-\x0c]\x00")
    for k in ("BL0", "ML0"):
        b = load(k)
        hits = []
        for m in ym_re.finditer(b, TEAM_END, min(len(b), 0xC1C6EF)):
            y, mo = u16(b, m.start()), u16(b, m.start() + 2)
            hits.append((m.start(), y, mo))
            if len(hits) >= 60:
                break
        print(f"\n[{k}] u16(年)+u16(月) 候选: {len(hits)} 处")
        for o, y, m in hits[:15]:
            print(f"  0x{o:08X}: {y}-{m:02d}  后续: {hx(b, o+4, 12)}")
    # 5c: 球队记录内 0x00~0x55 的 u32 值域统计 (找队级数值字段)
    b = load("BL0")
    print("\n[BL0] 球队记录内前 0x55 字节: 各 4 字节槽的非零值样例")
    for off in range(0, 0x55, 4):
        vals = set()
        for r in range(TEAM_N):
            v = u32(b, TEAM_START + r * TEAM_REC + off)
            if v:
                vals.add(v)
            if len(vals) > 4:
                break
        if vals:
            sample = sorted(vals)[:4]
            print(f"  +0x{off:02X}: {len(vals)}种 样例 {sample}")


SECTIONS = {
    "1": sec1_names, "2": sec2_shuffle, "3": sec3_f707,
    "4": sec4_idlist, "5": sec5_money_date,
}


def main():
    picks = [a for a in sys.argv[1:] if a in SECTIONS] or list(SECTIONS)
    for p in picks:
        SECTIONS[p]()
    print("\n完成。")


if __name__ == "__main__":
    main()
