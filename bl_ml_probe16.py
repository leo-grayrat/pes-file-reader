#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bl_ml_probe16 —— 资金字段定位（后段大带差分专项）

背景：probe14/15 已穷举 0x500000 之前的盲定位均零命中（见 docs/bl_ml_structure.md 3.1），
判定"动态余额在已扫区不存在或非常规编码"，且明确"未扫区域 = 0x500000 之后"。
本探针聚焦后段大带（0x500000~EOF，重点 0xCAAC90 起的 float 稀疏表），
用跨进度 ML 档差分找"金额候选"。

金额知识（docs/community_findings.md）：
  单位 = 100 欧元（int 存储）；财务字段 8 个，成对/成组出现：
  转会预算、薪资预算、转播权、赞助、球迷会、商品、门票、奖金。
  运行时是"大对象连续字段区"→ 存档里大概率也相邻。

用法：
  python bl_ml_probe16.py diff      # 后段大带差异位置分布
  python bl_ml_probe16.py ints      # 差异位置按 int32 读值的值域直方图
  python bl_ml_probe16.py floats    # 差异位置按 float32 读值的值域直方图
  python bl_ml_probe16.py clusters  # 相邻"金额候选"簇
"""
import struct
import collections
import sys

D = r"decoded"
PAIRS = [("ML00000000", "ML00000013"), ("ML00000000", "ML00000001"),
         ("ML00000001", "ML00000013"), ("ML00000002", "ML00000013")]


def load(name):
    with open(f"{D}/{name}.data", "rb") as f:
        return f.read()


def diff_positions(a, b, lo, hi):
    """返回 [lo,hi) 内 4 字节对齐、值不同的偏移列表。"""
    n = min(len(a), len(b))
    hi = min(hi, n - 4)
    pos = []
    i = (lo // 4) * 4
    while i < hi:
        if a[i:i+4] != b[i:i+4]:
            pos.append(i)
        i += 4
    return pos


def cmd_diff():
    a = load("ML00000000"); b = load("ML00000013")
    n = min(len(a), len(b))
    print(f"ML0 len={len(a)}  ML13 len={len(b)}  min={n}")
    # 分区统计
    zones = [(0x000000, 0x11F2C0, "球队区"),
             (0x11F2C0, 0x194000, "配置区"),
             (0x194000, 0x200000, "0x194000+赛事表"),
             (0x200000, 0x500000, "赛程/足中段"),
             (0x500000, 0xCAAC90, "后段前部"),
             (0xCAAC90, n, "后段float大带")]
    print("\n=== 分区差异（4字节对齐，u32 槽）===")
    for lo, hi, name in zones:
        pos = diff_positions(a, b, lo, hi)
        print(f"  {name:16s} [{lo:08X},{hi:08X})  差异 u32 槽数 = {len(pos)}")


def value_hist(a, b, lo, hi, mode):
    pos = diff_positions(a, b, lo, hi)
    hist = collections.Counter()
    samples = []
    for p in pos:
        va = struct.unpack_from("<I", a, p)[0]
        vb = struct.unpack_from("<I", b, p)[0]
        for v in (va, vb):
            if mode == "int":
                sv = struct.unpack("<i", struct.pack("<I", v))[0]
            else:
                sv = struct.unpack("<f", struct.pack("<I", v))[0]
            # 粗分桶（log10 量级）
            mag = int(abs(sv)) if sv != 0 else 0
            if mag == 0:
                key = "0"
            elif mag < 1000:
                key = "<1e3"
            elif mag < 10000:
                key = "1e3~1e4"
            elif mag < 100000:
                key = "1e4~1e5"
            elif mag < 1000000:
                key = "1e5~1e6"
            elif mag < 10000000:
                key = "1e6~1e7"
            elif mag < 100000000:
                key = "1e7~1e8"
            else:
                key = ">=1e8"
            hist[key] += 1
            samples.append((p, va, vb))
    return hist, samples, pos


def cmd_ints():
    a = load("ML00000000"); b = load("ML00000013")
    n = min(len(a), len(b))
    hist, samples, pos = value_hist(a, b, 0x500000, n - 4, "int")
    print(f"=== 后段(0x500000+) 差异 u32 槽 {len(pos)} 个，int32 值域分布 ===")
    for k in ["0", "<1e3", "1e3~1e4", "1e4~1e5", "1e5~1e6", "1e6~1e7", "1e7~1e8", ">=1e8"]:
        print(f"  {k:10s} : {hist.get(k, 0)}")


def cmd_floats():
    a = load("ML00000000"); b = load("ML00000013")
    n = min(len(a), len(b))
    hist, samples, pos = value_hist(a, b, 0x500000, n - 4, "float")
    print(f"=== 后段(0x500000+) 差异 u32 槽 {len(pos)} 个，float32 值域分布 ===")
    for k in ["0", "<1e3", "1e3~1e4", "1e4~1e5", "1e5~1e6", "1e6~1e7", "1e7~1e8", ">=1e8"]:
        print(f"  {k:10s} : {hist.get(k, 0)}")


def cmd_clusters():
    """在后段找相邻的金额候选簇（int32 读法，量级 1e4~1e8，间距<=8字节连续）。"""
    a = load("ML00000000"); b = load("ML00000013")
    n = min(len(a), len(b))
    pos = diff_positions(a, b, 0x500000, n - 4)
    print(f"后段差异槽总数 = {len(pos)}")

    def is_money(v):
        # 存储值 = 欧元/100；合理范围 ~1e3(10万欧) ~ 1e7(10亿欧)
        if v == 0:
            return False
        if 1000 <= v <= 10_000_000:
            return True
        return False

    # 只看两侧都变化的槽，且 int 值在金额量级
    hot = []
    for p in pos:
        va = struct.unpack_from("<I", a, p)[0]
        vb = struct.unpack_from("<I", b, p)[0]
        if is_money(va) or is_money(vb):
            hot.append((p, va, vb))

    print(f"金额量级(1e3~1e7 u32)差异槽数 = {len(hot)}")

    # 聚簇（相邻差异槽间距 <= 16 字节归为一簇）
    clusters = []
    cur = []
    for p, va, vb in hot:
        if cur and p - cur[-1][0] > 16:
            clusters.append(cur)
            cur = []
        cur.append((p, va, vb))
    if cur:
        clusters.append(cur)

    clusters.sort(key=lambda c: -len(c))
    print(f"相邻聚簇数 = {len(clusters)}（按簇大小降序）")
    for c in clusters[:20]:
        base = c[0][0]
        print(f"\n  簇 @ 0x{base:08X}  共 {len(c)} 个槽，跨度 0x{c[-1][0]-base:X}")
        for p, va, vb in c[:12]:
            print(f"    0x{p:08X}:  ML0={va:>10d}  ML13={vb:>10d}   (float {struct.unpack('<f', struct.pack('<I', va))[0]:.3g} / {struct.unpack('<f', struct.pack('<I', vb))[0]:.3g})")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "diff"
    {"diff": cmd_diff, "ints": cmd_ints, "floats": cmd_floats, "clusters": cmd_clusters}[cmd]()