#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_xref_mt.py — 定位「谁调用了 MT19937」：暴力扫 x86-64 call rel32 求交叉引用。

为什么不用反汇编器：找 xref 只需扫 E8 操作码。x86-64 的 call rel32 编码为
    E8 <int32 rel>
    目标 = 该指令下一条地址 + rel = (call_off + 5) + rel
误报估算：468MB 内 E8 出现约 1.8M 次，目标落进 2KB 窗口的概率约 1500/2^32，
          期望误报 ≈ 0.6 个 —— 误报极低，无需反汇编器即可定性。

找到了调用点，就等于找到了「存档加解密例程」，进而能读它如何切分
320B 加密头 / 208B 文件头 / desc / logo / data / serial —— 这正是
"搞清楚存档每一部分干什么"要摸的代码。

严格只读：仅 mmap 读取，绝不执行/加载其代码，绝不写入目标文件。
用法：
  python exe_xref_mt.py <exe> [区域起始] [区域结束]
  默认区域 = 正版 1.07.00 中实测到的 MSVC std::mt19937 + std::seed_seq 实现区
"""
import mmap
import os
import re
import struct
import sys

# 实测：0x1414CE0 起为 std::mt19937::init_genrand 循环（含 0x6C078965 / 5489 / 624 / 625）
#       0x14151B4 / 0x141522F 为 std::seed_seq 的两个 LCG 乘子 1664525 / 1566083941
DEFAULT_LO = 0x1414C00
DEFAULT_HI = 0x1415400

CTX_SPAN = 0x120


def find_all(mm, pat, cap):
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


def caller_ctx(mm, off, span=CTX_SPAN):
    """调用点前后的可打印字符串（用来猜调用者模块/日志）。"""
    lo = max(0, off - span)
    hi = min(len(mm), off + span)
    raw = mm[lo:hi]
    asc = re.findall(rb'[\x20-\x7e]{6,}', raw)
    return [s.decode('latin1') for s in asc]


def main():
    if len(sys.argv) < 2:
        print("用法: python exe_xref_mt.py <exe> [lo] [hi]")
        return 1
    path = sys.argv[1]
    if not os.path.isfile(path):
        print("找不到文件: %s" % path)
        return 1
    lo = int(sys.argv[2], 0) if len(sys.argv) > 2 else DEFAULT_LO
    hi = int(sys.argv[3], 0) if len(sys.argv) > 3 else DEFAULT_HI
    size = os.path.getsize(path)
    print("目标: %s（%d 字节，只读）" % (path, size))
    print("MT19937 区域: 0x%X ~ 0x%X（%d 字节）" % (lo, hi, hi - lo))

    callers = []
    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            print("扫描 E8 call rel32 ...")
            pos = 0
            n_e8 = 0
            while True:
                i = mm.find(b"\xE8", pos)
                if i < 0:
                    break
                n_e8 += 1
                if i + 5 <= len(mm):
                    rel = struct.unpack_from("<i", mm, i + 1)[0]
                    tgt = i + 5 + rel
                    if lo <= tgt <= hi:
                        callers.append((i, tgt))
                pos = i + 1
            print("  共检查 %d 个 E8 字节，命中目标区域的调用 %d 处" % (n_e8, len(callers)))

            if not callers:
                print("\n无 call 指向该区域。可能调用经由寄存器/虚表/导入表，")
                print("或该区域是数据（常量表）而非代码入口。")
                return 0

            print("=" * 76)
            print("调用点（call 指令所在文件偏移 → 目标）")
            for c_off, tgt in callers:
                print("  0x%08X  call  0x%08X" % (c_off, tgt))

            print("=" * 76)
            print("调用者上下文（周边可打印串，用于判断归属模块）")
            seen_ctx = set()
            for c_off, tgt in callers[:40]:
                strs = caller_ctx(mm, c_off)
                key = tuple(strs[:3])
                if key in seen_ctx:
                    continue
                seen_ctx.add(key)
                print("  --- call @0x%08X → 0x%08X ---" % (c_off, tgt))
                for s in strs[:8]:
                    print("      %s" % s)
                if not strs:
                    print("      （周边无可打印串）")

    print("=" * 76)
    print("结论：上述调用点即 MT19937/seed_seq 的调用者。")
    print("      下一步：这些调用者里应有 crypt_stream / crypt_header ——")
    print("      即存档加解密例程，从它可读出分块(320/208/desc/logo/data/serial)逻辑。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
