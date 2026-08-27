#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BL/ML data 结构逆向第十四轮 (probe15): 对阵结构 + 资金记录级差分。

probe14 结果:
  - 比赛日 +0x170 区条目实际为 16 字节: [u32 小整数值][u32 ?][u32 0][u32 指针];
  - 进度对差分: 动态区无千位整金额样变动值 (强负证据);
  - 赛事表逐槽: +0x04C ID 列、+0x050 枚举[1..5]、+0x2C0/+0x2C4 枚举、
    +0x2CC~+0x2DC 金额候选。
本轮:
  A. +0x170 区按 16 字节重扫: 小整数语义 (对照球队号 1..800 / 赛事条目),
     指针目标区结构, 找主客队对;
  B. 赛事实例区 (0x60xxxx 带) 嵌套链解析: 槽内两指针解引用找队号对;
  C. 资金: 记录级组间差分 —— 赛程表记录内逐偏移 (两组各自基址对齐)
     + 球队记录内逐偏移;
  D. 赛事表金额候选槽 (+0x2CC/+0x2D4/+0x2D8/+0x2DC) 与记录语义核对。

用法: python bl_ml_probe15.py [节号...]   纯标准库, 输入只读。
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
COMP_STRIDE = 0x314
SCHED_STRIDE = 0x254
DATE_RE = re.compile(rb"[\xe5-\xe7]\x07[\x01-\x0c][\x01-\x1f]")
TEAM_START, TEAM_REC, TEAM_N = 0x100, 0x690, 700


def load(key):
    if key not in _cache:
        with open(os.path.join(DEC, FILES[key]), "rb") as f:
            _cache[key] = f.read()
    return _cache[key]


def u8(b, o):
    return b[o]


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def s32(b, o):
    return struct.unpack_from("<i", b, o)[0]


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
    return base, nrec


def sched_base(b):
    hits = [m.start() for m in DATE_RE.finditer(b, 0x11F2C0, 0x400000)]
    if not hits:
        return None, 0
    off0 = Counter(o % SCHED_STRIDE for o in hits).most_common(1)[0][0]
    first = next(o for o in hits if o % SCHED_STRIDE == off0)
    return first - off0, len(hits)


# -------------------------------------------------- A: +0x174 区 16 字节条目
def collect_entries(b, base, nrec, maxrec=None):
    """条目自 +0x174 起, 16 字节: [match_idx][aux][0][ptr], 空槽 idx=FFFF。"""
    out = []
    for r in range(min(nrec, maxrec) if maxrec else nrec):
        o = base + r * SCHED_STRIDE + 0x174
        end = base + r * SCHED_STRIDE + SCHED_STRIDE
        while o + 16 <= end:
            idx, aux, z, p = u32(b, o), u32(b, o + 4), u32(b, o + 8), u32(b, o + 12)
            if idx >= 0xFFFF:
                break
            out.append((r, p, idx, aux))
            o += 16
    return out


def secA_entries16():
    banner("A、比赛日 +0x174 区条目普查 (BL0/ML0)")
    for k in ("BL0", "ML0"):
        b = load(k)
        base, nrec = sched_base(b)
        ents = collect_entries(b, base, nrec)
        print(f"\n[{k}] 基址 0x{base:08X}, {nrec} 条记录, 条目 {len(ents)} 个")
        idxs = [e[2] for e in ents]
        ptrs = [e[1] for e in ents]
        auxs = [e[3] for e in ents]
        print(f"  match_idx: 值域 [{min(idxs)}, {max(idxs)}], "
              f"独立 {len(set(idxs))}, 连续={len(set(idxs)) == max(idxs) - min(idxs) + 1}")
        # 与 +0x160 轮次/条数关系: 每记录条目数分布
        per_rec = Counter(e[0] for e in ents)
        print(f"  每记录条目数分布: {Counter(per_rec.values()).most_common(5)}")
        print(f"  指针值域 [0x{min(ptrs):X}, 0x{max(ptrs):X}], "
              f"独立 {len(set(ptrs))}/{len(ptrs)}")
        print(f"  aux 非零占比: {sum(1 for v in auxs if v)}/{len(auxs)}, "
              f"样例 {[hex(v) for v in auxs[:5] if v]}")
        # idx 与记录序号 +0x150 对照 (全局场次号?)
        seq = u32(b, base + ents[0][0] * SCHED_STRIDE + 0x150)
        print(f"  首条目所在记录序号={seq}, idx={ents[0][2]}")
    # 解引用抽 3 个指针看实例槽内容 (BL0)
    b = load("BL0")
    base, nrec = sched_base(b)
    ents = collect_entries(b, base, nrec, maxrec=3)
    print("\nBL0 前 3 条目指针解引用:")
    for r, p, idx, aux in ents[:3]:
        print(f"  rec{r} idx={idx} aux=0x{aux:X} → 0x{p:X}:")
        for i in range(0, 64, 16):
            print(f"    +0x{i:02X}: {hx(b, p + i, 16)}")


# -------------------------------------------------- B: 实例区嵌套链
def secB_instance_chain():
    banner("B、赛事实例槽解析 (BL0)")
    b = load("BL0")
    base, nrec = sched_base(b)
    ents = collect_entries(b, base, nrec, maxrec=60)
    ptrs = [e[1] for e in ents]
    print(f"样本指针 {len(ptrs)} 个")
    # 槽内指针样偏移普查 (扫 0x80 字节)
    inner = Counter()
    for p in ptrs:
        for i in range(0, 0x80, 4):
            if p + i + 4 > len(b):
                break
            v = u32(b, p + i)
            if 0x100 < v < len(b):
                inner[i] += 1
    print(f"槽内指针样偏移 (出现≥半): "
          f"{[(hex(k), c) for k, c in inner.most_common(12) if c >= len(ptrs) // 2]}")
    # 槽内小整数普查: 找 1..800 (队号) 与赛事条目 ID 对应槽位
    small = Counter()
    for p in ptrs:
        for i in range(0, 0x80, 4):
            v = u32(b, p + i)
            if 1 <= v <= 800:
                small[i] += 1
    print(f"槽内小整数(1..800)槽位: "
          f"{[(hex(k), c) for k, c in small.most_common(12) if c >= 20]}")
    # 抽 4 个槽完整 hex 展示 0x80 字节
    print("\n前 4 个槽完整内容:")
    for p in ptrs[:4]:
        print(f"  槽 @ 0x{p:X}:")
        for i in range(0, 0x80, 16):
            print(f"    +0x{i:02X}: {hx(b, p + i, 16)}")
    # 槽内按 16 字节 [u32 flag][u32 ptr][u32 a][u32 b] 解析, 统计 a 值域 (疑全局场次号)
    av = Counter()
    valid = 0
    for p in ptrs:
        for i in range(0, 0x200, 16):
            if p + i + 16 > len(b):
                break
            fl, ip, a, bb = (u32(b, p + i), u32(b, p + i + 4),
                             u32(b, p + i + 8), u32(b, p + i + 12))
            if ip == 0 or a >= 0xFFFF:
                break
            valid += 1
            av[a] += 1
    if av:
        print(f"\n槽内条目 {valid} 条, a 值域 [{min(av)}, {max(av)}], "
              f"独立 {len(av)}, 频次 top5 {av.most_common(5)}")
    # 比赛日记录前半部 dump (找队号字段)
    print("\n记录 0/5 的 +0x00~+0x170 (前半部):")
    for r in (0, 5):
        o = base + r * SCHED_STRIDE
        print(f"  记录 {r}:")
        for i in range(0, 0x170, 16):
            print(f"    +0x{i:03X}: {hx(b, o + i, 16)}")


def secB2_result_rec():
    banner("B2、+0x30 条目 f2 指针解引用 (疑比赛结果记录)")
    b = load("BL0")
    base, nrec = sched_base(b)
    ents = []       # (match_id, f2, flags)
    for r in range(min(8, nrec)):
        o = base + r * SCHED_STRIDE
        for j in range(0x30, 0xE0, 0x10):
            mid = u32(b, o + j)
            if mid >= 0xFFFF:
                continue
            f2 = u32(b, o + j + 4)
            if 0x100 < f2 < len(b):
                ents.append((r, j, mid, f2))
    print(f"有效 f2 指针 {len(ents)} 个")
    # 展示前 4 个目标 0x60 字节
    for r, j, mid, f2 in ents[:4]:
        print(f"\n  rec{r}+0x{j:X} match_id={mid} → f2=0x{f2:X}:")
        for i in range(0, 0x60, 16):
            print(f"    +0x{i:02X}: {hx(b, f2 + i, 16)}")
    # 目标内容普查: 找相邻 (u16 1..800, u16 1..800) 队号对的最佳槽位 (跨条目一致)
    pair_off = Counter()
    vals_by_off = {}
    for r, j, mid, f2 in ents:
        for i in range(0, 0x80, 2):
            if f2 + i + 4 > len(b):
                break
            a1, a2 = u16(b, f2 + i), u16(b, f2 + i + 2)
            if 1 <= a1 <= 800 and 1 <= a2 <= 800 and a1 != a2:
                pair_off[i] += 1
                vals_by_off.setdefault(i, []).append((a1, a2, mid))
    print(f"\n队号对候选槽位 (频次≥15): "
          f"{[(hex(k), c) for k, c in pair_off.most_common(10) if c >= 15]}")
    for i, c in pair_off.most_common(6):
        if c >= 15:
            print(f"  +0x{i:X} 样例: "
                  f"{[(a1, a2, mid) for a1, a2, mid in vals_by_off[i][:8]]}")


# -------------------------------------------------- C: 记录级组间差分
def rec_diff(bufs, keys, bases, stride, nrec_min, label):
    """逐记录偏移比较: 各样本在各自基址上同偏移取值, 组内均值差。"""
    res = []
    for j in range(0, stride - 3, 4):
        means = []
        ok = True
        for k in keys:
            b = bufs[k]
            base = bases[k]
            vals = []
            for r in range(nrec_min):
                o = base + r * stride + j
                if o + 4 > len(b):
                    ok = False
                    break
                vals.append(u32(b, o))
            if not ok:
                break
            means.append(sum(vals) / len(vals))
        if not ok:
            continue
        ma = sum(means[:len(keys) // 2]) / (len(keys) // 2)
        mb = sum(means[len(keys) // 2:]) / (len(keys) // 2)
        if max(ma, mb) > 1000 and max(ma, mb) > 2 * max(min(ma, mb), 1):
            res.append((j, means))
    print(f"\n{label}: 组间均值差 >2× 且量级>1000 的记录内偏移 {len(res)} 个:")
    for j, means in res[:30]:
        print(f"  +0x{j:03X}: 组A={[f'{m:,.0f}' for m in means[:len(keys)//2]]} "
              f"组B={[f'{m:,.0f}' for m in means[len(keys)//2:]]}")


def secC_record_diff():
    banner("C、记录级组间差分: A=(BL0,BL1,ML2) vs B=(ML0,ML1,ML13)")
    GA, GB = ("BL0", "BL1", "ML2"), ("ML0", "ML1", "ML13")
    bufs = {k: load(k) for k in GA + GB}
    keys = GA + GB
    # 赛程表记录
    bases = {k: sched_base(bufs[k])[0] for k in keys}
    nrecs = {k: sched_base(bufs[k])[1] for k in keys}
    nrec_min = min(nrecs[k] for k in keys if bases[k])
    print(f"各组赛程基址: {{ {', '.join(f'{k}:0x{bases[k]:X}({nrecs[k]})' for k in keys)} }}")
    rec_diff(bufs, keys, bases, SCHED_STRIDE, min(nrec_min, 200),
             "赛程记录 (步长0x254, 前200条)")
    # 球队记录: 基址全为 0x100
    tbases = {k: TEAM_START for k in keys}
    rec_diff(bufs, keys, tbases, TEAM_REC, TEAM_N, "球队记录 (步长0x690, 700条)")


# -------------------------------------------------- D: 赛事表金额候选核对
def secD_comp_money():
    banner("D、赛事表金额候选槽语义核对 (BL0/ML0)")
    for k in ("BL0", "ML0"):
        b = load(k)
        base, nrec = comp_base(b)
        print(f"\n[{k}] 基址 0x{base:06X}, {nrec} 条")
        for j in (0x04C, 0x050, 0x1FC, 0x2C0, 0x2C4, 0x2C8,
                  0x2CC, 0x2D0, 0x2D4, 0x2D8, 0x2DC):
            vals = [u32(b, base + r * COMP_STRIDE + j) for r in range(nrec)]
            un = sorted(set(vals))
            if len(un) <= 10:
                print(f"  +0x{j:03X}: {un}")
            else:
                print(f"  +0x{j:03X}: [{min(vals):,}~{max(vals):,}] "
                      f"独立{len(un)} 样例{[f'{v:,}' for v in vals[:5]]}")
        # 与记录名对照: 输出前 6 条的名 + 关键槽
        for r in range(6):
            o = base + r * COMP_STRIDE
            nm = ""
            m = CN_RE.search(b[o + 0x2C0:o + 0x314])
            if m:
                try:
                    nm = m.group().decode("utf-8", "replace")[:18]
                except Exception:
                    pass
            cid = u32(b, o + 0x04C)
            typ = u32(b, o + 0x050)
            m1 = s32(b, o + 0x2CC)
            m2 = s32(b, o + 0x2D4)
            yr = u16(b, o + 0x2C8)
            print(f"  #{r:2d} '{nm}' id={cid} typ={typ} 年={yr} "
                  f"+2CC={m1:,} +2D4={m2:,}")


def secB3_inner():
    banner("B3、索引表内层指针解引用 (找队号)")
    b = load("BL0")
    base, nrec = sched_base(b)
    # rec0+0x60 的 f2=0x19FBD 型索引表: 8 字节 [u24=8][u32 ptr][u8 seq]
    f2 = u32(b, base + 0x60 + 4)
    print(f"rec0+0x60 f2=0x{f2:X}, 内层条目:")
    inner = []
    for i in range(0, 0x80, 8):
        o = f2 + i
        if b[o] != 0x08 or b[o + 1] != 0 or b[o + 2] != 0:
            break
        # 按 [3字节头][u32 ptr][1字节 seq] 读: ptr = b[o+3:o+7]
        p = struct.unpack_from("<I", b, o + 3)[0]
        inner.append((p, b[o + 7]))
        print(f"  +0x{i:02X}: ptr=0x{p:06X} seq={b[o+7]}")
    # 解引用前 3 个内层指针, dump 0x60 字节 + 扫队号对 (u16 与 u8)
    for p, seq in inner[:3]:
        if not (0x100 < p < len(b)):
            continue
        print(f"\n  → 0x{p:X} (seq {seq}):")
        for i in range(0, 0x60, 16):
            print(f"    +0x{i:02X}: {hx(b, p + i, 16)}")
        pairs = []
        for i in range(0, 0x100, 2):
            if p + i + 4 > len(b):
                break
            a1, a2 = u16(b, p + i), u16(b, p + i + 2)
            if 1 <= a1 <= 800 and 1 <= a2 <= 800 and a1 != a2:
                pairs.append((i, a1, a2))
        print(f"    u16 队号对: {pairs[:8]}")
    # 全量: 前 8 记录所有 +0x30 条目的内层指针目标区找队号对槽位统计
    pair_off = Counter()
    for r in range(min(8, nrec)):
        o = base + r * SCHED_STRIDE
        for j in range(0x30, 0xE0, 0x10):
            mid = u32(b, o + j)
            if mid >= 0xFFFF:
                continue
            f2v = u32(b, o + j + 4)
            if not (0x100 < f2v < len(b) - 0x100):
                continue
            # 尝试把 f2 目标当 8 字节索引条目数组解内层指针 (最多 40 条)
            for i in range(0, 0x140, 8):
                oo = f2v + i
                if oo + 8 > len(b) or b[oo] != 0x08 or b[oo + 1]:
                    break
                ip = struct.unpack_from("<I", b, oo + 3)[0]
                if not (0x100 < ip < len(b) - 0x40):
                    continue
                for k in range(0, 0x40, 2):
                    a1, a2 = u16(b, ip + k), u16(b, ip + k + 2)
                    if 1 <= a1 <= 800 and 1 <= a2 <= 800 and a1 != a2:
                        pair_off[(i, k)] += 1
    print(f"\n内层目标队号对槽位 (频次≥10) 前 10: "
          f"{[(f'idx+0x{i:X},tgt+0x{k:X}', c)
             for (i, k), c in pair_off.most_common(10) if c >= 10]}")
    # 全区域找“哨兵头” 4B 00 00 00 37 8A 05 00 14 00 FF FF 定步长/条数 (阶段表数组)
    pat = bytes.fromhex("4B000000378A05001400FFFF")
    hits = []
    o = b.find(pat)
    while o != -1 and len(hits) < 200:
        hits.append(o)
        o = b.find(pat, o + 1)
    gaps = Counter(hits[i + 1] - hits[i] for i in range(len(hits) - 1))
    print(f"\n阶段表哨兵头命中 {len(hits)} 个, "
          f"首 0x{hits[0]:X}" + (f" 末 0x{hits[-1]:X}" if hits else ""))
    print(f"相邻间距分布: {gaps.most_common(5)}")
    if len(hits) < 2:
        print("唯一命中 → 非重复数组, 为单条阶段记录 (异构堆块)")
        return
    # 验证: 若步长稳定, 按步长读 12 条看队号列表一致性 (每记录 +0x44 起 u16 列)
    g = gaps.most_common(1)[0][0]
    print(f"按步长 0x{g:X} 抽样 8 条的 +0x44 起 20 个 u16:")
    for r in range(8):
        o = hits[0] + r * g
        if o + 0x70 > len(b):
            break
        vs = [u16(b, o + 0x44 + i * 2) for i in range(20)]
        n_valid = sum(1 for v in vs if 1 <= v <= 800)
        print(f"  #{r} @0x{o:X}: 有效队号 {n_valid}/20 首5={vs[:5]}")


SECTIONS = {"A": secA_entries16, "B": secB_instance_chain,
            "B2": secB2_result_rec, "B3": secB3_inner,
            "C": secC_record_diff, "D": secD_comp_money}


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
