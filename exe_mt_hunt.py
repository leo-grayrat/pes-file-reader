#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_mt_hunt.py — 用「加密算法指纹」反向定位 exe 中的存档加解密例程（只读 mmap）。

思路（回答"已知密钥能不能帮 exe 逆向"）：
  密钥本身可以不在 exe 里（已证伪：MASTERKEY_PES21 各种变体 0 命中），
  但【算法必然在】——游戏要解密存档，MT19937 的实现就必须编译进 exe。
  于是拿 pes_decrypt.py 已知算法的特征常量当"鱼钩"去钓代码：
    找到 MT19937 函数群 → 找到 crypt_stream / crypt_header 例程
    → 从周边代码读存档分块逻辑（320B 加密头 / 208B 文件头 / desc/logo/data/serial）。

常量分级：
  tier-A（低噪声，强证据，期望误报 ~109/常量，靠聚集定性）：
     0x9908B0DF MATRIX_A、0x6C078965 init_genrand 乘子、
     0x0019660D / 0x5D588B65 init_by_array 两乘子、0x012B8B2A 种子 19650218、
     0x9D2C5680 / 0xEFC60000 tempering 掩码
  tier-B（高噪声，仅用于 tier-A 命中处的邻近确认）：
     0x80000000 UPPER_MASK、0x7FFFFFFF LOWER_MASK、624 N、397 M、5489 默认种子

严格只读：仅 mmap 读取，绝不执行/加载其代码，绝不写入目标文件。
用法：
  python exe_mt_hunt.py "resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe"
"""
import mmap
import os
import re
import struct
import sys

# ---- tier-A：MT19937 特征常量（来自 pes_decrypt.py 的已知实现）----
TIER_A = [
    (0x9908B0DF, "MATRIX_A (twisting)"),
    (0x6C078965, "1812433253 init_genrand 乘子"),
    (0x0019660D, "1664525 init_by_array 乘子1"),
    (0x5D588B65, "1566083941 init_by_array 乘子2"),
    (0x012B8B2A, "19650218 init_by_array 固定种子"),
    (0x9D2C5680, "tempering 掩码 (y<<7)"),
    (0xEFC60000, "tempering 掩码 (y<<15)"),
]

# ---- tier-B：高噪声，只在 tier-A 命中附近做确认 ----
TIER_B = [
    (0x80000000, "UPPER_MASK"),
    (0x7FFFFFFF, "LOWER_MASK"),
    (624, "N=624"),
    (397, "M=397"),
    (5489, "默认种子 5489"),
]

# ---- PES 存档结构尺寸（解密器已知常量，用于邻近确认）----
PES_SIZES = [
    (320, "ENCRYPTION_HEADER_SIZE"),
    (208, "FILE_HEADER_SIZE"),
    (256, "头内 XOR 区 256"),
    (64, "滚动密钥/块 64"),
]

CAP = 512
CLUSTER_WIN = 0x10000   # 64KB 内算同一聚集区（一个函数群通常在此范围内）


def find_all(mm, pat, cap=CAP):
    hits = []
    start = 0
    while True:
        i = mm.find(pat, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
        if len(hits) >= cap:
            break
    return hits


def dump_ctx(mm, off, span=0x180):
    """列印命中处周边的可打印字符串，用于判断函数归属。"""
    lo = max(0, off - span)
    hi = min(len(mm), off + span)
    raw = mm[lo:hi]
    asc = re.findall(rb'[\x20-\x7e]{6,}', raw)
    return [s.decode('latin1') for s in asc]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path or not os.path.isfile(path):
        print("用法: python exe_mt_hunt.py <exe 路径>")
        return 1
    size = os.path.getsize(path)
    print("目标: %s（%d 字节，只读 mmap，绝不执行）" % (path, size))

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # ---------- tier-A 搜索 ----------
            print("=" * 76)
            print("[tier-A] MT19937 特征常量搜索（低噪声，强证据）")
            all_hits = []          # (off, name)
            for val, name in TIER_A:
                pat = struct.pack("<I", val)
                hits = find_all(mm, pat)
                print("  %-34s 0x%08X -> %d 处 %s"
                      % (name, val, len(hits),
                         ("[示例 " + ", ".join("0x%X" % h for h in hits[:5]) + "]") if hits else ""))
                for h in hits:
                    all_hits.append((h, name))

            if not all_hits:
                print("\n  tier-A 全 0 命中：该 exe 未内联标准 MT19937 常量")
                print("  （可能用了查表实现/编译器优化成非立即数形式，或加密在 DLL 里）")
                return 0

            # ---------- 聚集分析 ----------
            print("=" * 76)
            print("[聚集分析] 不同常量在 0x%X 窗口内的共现 —— 共现越多越像 MT19937 函数体"
                  % CLUSTER_WIN)
            all_hits.sort()
            clusters = []
            cur = [all_hits[0]]
            for item in all_hits[1:]:
                if item[0] - cur[-1][0] <= CLUSTER_WIN:
                    cur.append(item)
                else:
                    clusters.append(cur)
                    cur = [item]
            clusters.append(cur)

            scored = []
            for c in clusters:
                names = sorted(set(n for _, n in c))
                scored.append((len(names), c[0][0], c[-1][0], names, len(c)))
            scored.sort(reverse=True)

            print("  共 %d 个聚集区，按「不同常量数」排序，取前 6：" % len(scored))
            best_regions = []
            for nuniq, lo, hi, names, cnt in scored[:6]:
                print("  ★ 0x%08X~0x%08X：%d 个不同常量 / %d 处命中" % (lo, hi, nuniq, cnt))
                for n in names:
                    print("       - %s" % n)
                best_regions.append((lo, hi, nuniq))

            # ---------- 最佳区域：tier-B 邻近确认 + 上下文字符串 ----------
            if best_regions:
                print("=" * 76)
                print("[邻近确认] 在最佳聚集区内核对 tier-B 高噪声常量与 PES 结构尺寸")
                lo, hi, _ = best_regions[0]
                pad = 0x2000
                region_lo = max(0, lo - pad)
                region_hi = min(len(mm), hi + pad)
                region = mm[region_lo:region_hi]
                for val, name in TIER_B + PES_SIZES:
                    pat = struct.pack("<I", val & 0xFFFFFFFF)
                    hits = find_all(mm, pat, cap=64)
                    near = [h for h in hits if region_lo <= h <= region_hi]
                    print("  %-28s -> 区内 %d 处（全文件 %d 处）%s"
                          % (name, len(near), len(hits),
                             ("偏移 " + ", ".join("0x%X" % n for n in near[:4])) if near else ""))

                print("=" * 76)
                print("[上下文字符串] 最佳聚集区周边（判断函数归属/调用者）")
                for s in dump_ctx(mm, lo, span=0x400)[:25]:
                    print("   %s" % s)

            # ---------- 结论 ----------
            print("=" * 76)
            top_n = best_regions[0][2] if best_regions else 0
            if top_n >= 4:
                print("结论：发现 ≥4 个 MT19937 特征常量共现于 0x%X ~ 0x%X，"
                      % (best_regions[0][0], best_regions[0][1]))
                print("      基本可判定为 MT19937 实现所在区域。")
                print("      下一步：以该区间为锚，反汇编周边函数，定位 crypt_stream /")
                print("      crypt_header，进而读出存档分块（320/208/desc/logo/data/serial）逻辑。")
            elif top_n >= 2:
                print("结论：有 %d 个常量共现，疑似 MT19937，但证据偏弱，需反汇编确认。" % top_n)
            else:
                print("结论：常量命中分散、无共现，可能非标准 MT19937 内联实现。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
