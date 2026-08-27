#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第二轮探测 (probe3)。

输入: decoded/ 下已解密的 data 块 (只读, 绝不修改)。
已知前提 (来自 docs/HANDOFF.md / bl_ml_analyze.py / probe2.py):
  - data +0x10/+0x14 = 700 (球队记录数)
  - 球队记录数组: 0x100 起, 700 条, 每条 0x690 字节, 队名/口号在 +0x55
  - 球队区结束于 0x11F2C0, 其后 padding; 0x194000 疑为阵型/战术区块
本脚本目标: 定位球员记录数组 / 资金 / 日期等字段, 产出可复核的证据。

用法: python bl_ml_probe3.py [节号...]   不带参数 = 全部节。
节号: 1 样本概览  2 区块地图  3 字符串聚类  4 周期搜索
      5 动态区对比 6 数值字段扫描 7 0x194000 区块 8 队内动态直方图
纯标准库。输出刻意限量, 避免刷屏。
"""
import os
import re
import sys
import struct
from collections import Counter

BASE = os.path.dirname(os.path.abspath(__file__))
DEC = os.path.join(BASE, "decoded")

FILES = {
    "BL0": "BL00000000.data",
    "BL1": "BL00000001.data",
    "BL2": "BL00000002.data",
    "BL3": "BL00000003.data",
    "ML0": "ML00000000.data",
    "ML1": "ML00000001.data",
    "ML2": "ML00000002.data",
    "ML13": "ML00000013.data",
}
TEAM_START = 0x100
TEAM_REC = 0x690
TEAM_N = 700
TEAM_END = TEAM_START + TEAM_REC * TEAM_N   # 0x11F2C0
FMT_OFF = 0x194000
NONZERO = bytes(x for x in range(1, 256))   # 保留备用

_cache = {}


def load(key):
    if key not in _cache:
        with open(os.path.join(DEC, FILES[key]), "rb") as f:
            _cache[key] = f.read()
    return _cache[key]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def hexdump(b, o, n=32):
    return " ".join(f"{x:02X}" for x in b[o:o + n])


def banner(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


# ---------------------------------------------------------------- 节1 概览
def sec1_overview():
    banner("一、样本概览: 大小 / 头部关键字段 / 球队区抽查")
    print(f"{'样本':<5} {'大小':>9}  {'+00':>4} {'+04':>4} {'+08':>10} "
          f"{'+0C':>6} {'+10':>4} {'+14':>4} {'+20':>4} {'+50(指针)':>12}")
    for k in FILES:
        b = load(k)
        row = [len(b), u32(b, 0), u32(b, 4), u32(b, 8), u32(b, 0xC),
               u32(b, 0x10), u32(b, 0x14), u32(b, 0x20), u32(b, 0x50)]
        print(f"{k:<5} {row[0]:>9}  {row[1]:>4} {row[2]:>4} {row[3]:>10} "
              f"{row[4]:>6} {row[5]:>4} {row[6]:>4} {row[7]:>4} 0x{row[8]:08X}")
    print("\n球队区抽查 (记录内 +0x55 处 ASCII 串):")
    for k in ("BL0", "ML0"):
        b = load(k)
        shown = 0
        for r in range(TEAM_N):
            o = TEAM_START + r * TEAM_REC + 0x55
            m = re.match(rb"[\x20-\x7e]+", b[o:o + 40])
            if m and len(m.group()) >= 3:
                print(f"  [{k}] #{r:3d} @0x{o:06X}: {m.group().decode('ascii')}")
                shown += 1
                if shown >= 8:
                    break


# ---------------------------------------------------------------- 节2 区块地图
def data_bands(b, min_len=256, min_gap=1024):
    """把文件切成非零数据带: 以 >= min_gap 的连续零间隙为分隔,
    带长 >= min_len 才记录。返回 [(start, end, gap_after)]。
    用 re 找零 run, 避开 bytes.find 多字节子串匹配的坑。"""
    bands = []
    prev = 0
    zero_re = re.compile(rb"\x00{" + str(min_gap).encode() + rb",}")
    for m in zero_re.finditer(b):
        if m.start() - prev >= min_len:
            bands.append([prev, m.start(), m.end() - m.start()])
        prev = m.end()
    if len(b) - prev >= min_len:
        bands.append([prev, len(b), 0])
    return [tuple(t) for t in bands]


def sec2_bands():
    banner("二、非零数据带地图 (带 >=256B, 间隙 >=1KB 才算分隔)")
    for k in ("BL0", "ML0", "BL3", "ML13"):
        b = load(k)
        print(f"\n[{k}] 大小 0x{len(b):X}:")
        for s, e, gap in data_bands(b):
            tag = ""
            if s < TEAM_END:
                tag = " <- 含头部+球队区"
            if s <= FMT_OFF < e:
                tag = " <- 含 0x194000 区块"
            print(f"  [0x{s:08X}, 0x{e:08X}) len=0x{e-s:08X} "
                  f"({(e-s)//1024}KB) 后隙={gap//1024}KB{tag}")


# ---------------------------------------------------------------- 节3 字符串聚类
def ascii_strings(b, start, end, minlen=4):
    res = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, b[start:end]):
        s = m.group().decode("ascii")
        if sum(c.isalpha() for c in s) >= 3:
            res.append((start + m.start(), s))
    return res


def utf16_strings(b, start, end, minlen=4):
    res = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, b[start:end]):
        s = m.group().decode("utf-16-le")
        if sum(c.isalpha() for c in s) >= 3:
            res.append((start + m.start(), s))
    return res


def cluster(items, gap):
    bands = []
    for o, s in items:
        if bands and o - bands[-1][1] < gap:
            bands[-1][1] = o + len(s)
            bands[-1][2].append((o, s))
        else:
            bands.append([o, o + len(s), [(o, s)]])
    return bands


def sec3_strings():
    banner("三、字符串落点聚类 (球队区之后; 每类列前 10 大带, 每带最多 6 样例)")
    for k in ("BL0", "ML0"):
        b = load(k)
        for label, func in (("ASCII", ascii_strings), ("UTF-16LE", utf16_strings)):
            ss = func(b, TEAM_END, len(b))
            if not ss:
                print(f"\n[{k}] {label}: 无")
                continue
            bands = sorted(cluster(ss, 0x4000), key=lambda t: -len(t[2]))[:10]
            print(f"\n[{k}] {label}: 共 {len(ss)} 串")
            for s, e, items in bands:
                print(f"  带 [0x{s:08X}, 0x{e:08X}) {len(items)} 串")
                for o, txt in items[:6]:
                    print(f"      0x{o:08X} {txt[:48]!r}")


# ---------------------------------------------------------------- 节4 周期搜索
def find_period(b, start, end, strides=None, maxrec=4000, minrec=8, ratio=0.4):
    """候选定长记录检测: 记录头前4字节的众数重复率 >= ratio。"""
    if strides is None:
        strides = list(range(0x40, 0x501, 0x10)) + [0x690, 0x800, 0x1000, 0x2000]
    hits = {}
    for st in strides:
        cnt = min(maxrec, (end - start) // st)
        if cnt < minrec:
            continue
        heads = Counter()
        for o in range(start, start + cnt * st, st):
            heads[bytes(b[o:o + 4])] += 1
        magic, top = heads.most_common(1)[0]
        if magic != b"\x00\x00\x00\x00" and top >= cnt * ratio:
            hits[st] = (magic, top, cnt)
    return hits


def sec4_period():
    banner("四、球队区之后: 定长记录周期搜索 (记录头前4字节重复率>=40%)")
    for k in ("BL0", "ML0"):
        b = load(k)
        for s, e, _ in data_bands(b):
            if s < TEAM_END or e - s < 0x4000:
                continue
            hits = find_period(b, s, e)
            if hits:
                best = sorted(hits.items(), key=lambda kv: -kv[1][1] / kv[1][2])
                print(f"\n[{k}] 带 [0x{s:08X}, 0x{e:08X}) 候选步长:")
                for st, (magic, top, cnt) in best[:6]:
                    print(f"  步长 0x{st:04X} ({st:5d}): 头 {magic.hex()} "
                          f"重复 {top}/{cnt} = {100.0*top/cnt:.1f}%")
            else:
                print(f"\n[{k}] 带 [0x{s:08X}, 0x{e:08X}) 未找到周期")
    # 0x194000 区块内部小步长自检
    b = load("BL0")
    end = min(len(b), FMT_OFF + 0x400000)
    hits = find_period(b, FMT_OFF, end, strides=list(range(8, 0x400, 8)))
    if hits:
        print("\n[BL0] 0x194000 区块内部小步长自检 (前4字节):")
        for st, (magic, top, cnt) in sorted(hits.items())[:8]:
            print(f"  步长 0x{st:03X}: 头 {magic.hex()} 重复 {top}/{cnt}")
    else:
        print("\n[BL0] 0x194000 区块内 8~0x400 步长无重复头")


# ---------------------------------------------------------------- 节5 动态区对比
def diff_runs(a, b, start, end, minlen=16, limit=40):
    runs = []
    i = start
    while i < end:
        if a[i] != b[i]:
            j = i
            while j < end and a[j] != b[j]:
                j += 1
            if j - i >= minlen:
                runs.append((i, j))
                if len(runs) >= limit:
                    return runs
            i = j
        else:
            i += 1
    return runs


def sec5_diff():
    banner("五、多存档逐字节对比: 变动带 (球队区之后, 连续变动>=16字节)")
    for ka, kb in (("BL0", "BL1"), ("ML0", "ML13"), ("BL0", "ML0")):
        a, b = load(ka), load(kb)
        n = min(len(a), len(b))
        runs = diff_runs(a, b, TEAM_END, n)
        print(f"\n[{ka} vs {kb}] 0x{TEAM_END:X} 之后变动带 (前{len(runs)}个, "
              f"文件长 0x{len(a):X} vs 0x{len(b):X}):")
        for s, e in runs:
            print(f"  [0x{s:08X}, 0x{e:08X}) len={e-s:6d} "
                  f"A={hexdump(a, s, 12)} B={hexdump(b, s, 12)}")


# ---------------------------------------------------------------- 节6 数值字段扫描
def scan_values(a, b, start, end, lim=20):
    if end > min(len(a), len(b)):
        end = min(len(a), len(b))
    count = (end - start) // 4
    va = struct.unpack_from(f"<{count}I", a, start)
    vb = struct.unpack_from(f"<{count}I", b, start)
    cats = {"日期型": [], "epoch型": [], "资金候选": []}
    for i in range(count):
        v = va[i]
        if 20190101 <= v <= 20261231:
            d, m = divmod(v, 100)
            y, m2 = divmod(d, 100)
            if 1 <= m <= 12 and 1 <= m2 <= 31:
                cats["日期型"].append(start + i * 4)
        if 1550000000 <= v <= 1850000000:
            cats["epoch型"].append(start + i * 4)
        if 10000 <= v <= 300000000 and v % 1000 == 0 and vb[i] != v:
            cats["资金候选"].append(start + i * 4)
    return cats


def sec6_values():
    banner("六、数值字段扫描 (球队区之后, 4字节对齐)")
    for ka, kb in (("BL0", "BL1"), ("ML0", "ML13")):
        a, b = load(ka), load(kb)
        print(f"\n[{ka} vs {kb}]:")
        cats = scan_values(a, b, TEAM_END, min(len(a), len(b)))
        for name, hits in cats.items():
            if not hits:
                print(f"  {name}: 无")
                continue
            print(f"  {name}: {len(hits)} 处 (前20)")
            for o in hits[:20]:
                av, bv = u32(a, o), u32(b, o)
                print(f"    0x{o:08X}: A={av:>12d}  B={bv:>12d}")


# ---------------------------------------------------------------- 节7 0x194000
def sec7_fmt():
    banner("七、0x194000 区块: 全样本恒定性 + 内容摘要")
    blobs = {k: load(k)[FMT_OFF:FMT_OFF + 0x10000] for k in FILES}
    ref = blobs["BL0"]
    for k, blob in blobs.items():
        diff = sum(1 for i in range(min(len(ref), len(blob)))
                   if ref[i] != blob[i])
        print(f"  [{k}] 与 BL0 相比前64KB 差异 {diff} 字节 "
              f"head: {hexdump(blob, 0, 16)}")
    b = load("BL0")
    print("\n[BL0] 0x194000 起每 0x100 一行摘要 (前 16 行):")
    for r in range(16):
        o = FMT_OFF + r * 0x100
        nz = sum(1 for x in b[o:o + 0x100] if x)
        print(f"  +0x{r*0x100:04X}: 非零 {nz:3d}/256  {hexdump(b, o, 16)}")
    heads = Counter()
    for o in range(FMT_OFF, FMT_OFF + 0x10000, 8):
        heads[bytes(b[o:o + 8])] += 1
    print("\n[BL0] 该区块内 8 字节指纹 top5:")
    for pat, c in heads.most_common(5):
        print(f"  {pat.hex()} x{c}")


# ---------------------------------------------------------------- 节8 队内直方图
def sec8_team_hist():
    banner("八、球队记录内动态偏移直方图 (BL0 vs BL1, 模 0x690)")
    a, b = load("BL0"), load("BL1")
    n = min(len(a), len(b), TEAM_END)
    hist = Counter()
    for i in range(TEAM_START, n):
        if a[i] != b[i]:
            hist[(i - TEAM_START) % TEAM_REC] += 1
    if not hist:
        print("  无差异")
        return
    print(f"  总差异 {sum(hist.values())} 字节, 落在 {len(hist)} 个记录内偏移上")
    offs = sorted(hist)
    runs = []
    for o in offs:
        if runs and o == runs[-1][1]:
            runs[-1] = (runs[-1][0], o + 1)
        else:
            runs.append((o, o + 1))
    for s, e in runs[:40]:
        tot = sum(hist[x] for x in range(s, e))
        print(f"  +0x{s:03X}~+0x{e-1:03X} ({e-s}B): {tot} 次  "
              f"A={hexdump(a, TEAM_START + s, min(16, e - s))} "
              f"B={hexdump(b, TEAM_START + s, min(16, e - s))}")


SECTIONS = {
    "1": sec1_overview, "2": sec2_bands, "3": sec3_strings,
    "4": sec4_period, "5": sec5_diff, "6": sec6_values,
    "7": sec7_fmt, "8": sec8_team_hist,
}


def main():
    picks = [a for a in sys.argv[1:] if a in SECTIONS] or list(SECTIONS)
    for p in picks:
        SECTIONS[p]()
    print("\n完成。")


if __name__ == "__main__":
    main()
