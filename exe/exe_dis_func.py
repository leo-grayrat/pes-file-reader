#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_dis_func.py — 完整反汇编一段文件偏移，并可选反查「谁调用了这段里的某个地址」。

用途：在 exe_dis_callers.py 锁定候选函数之后，逐条读它的指令，确认它是不是
crypt_stream / crypt_header，以及它如何被上层调用（从而定位存档分块逻辑）。

地址口径：整个文件按 flat image 处理（base=0，偏移即地址），与 exe_dis_callers.py 一致。

只读：仅 mmap 读取，绝不执行/加载其代码，绝不写入目标文件。

用法：
  python exe_dis_func.py <exe> <start_hex> [end_hex]          # 完整反汇编
  python exe_dis_func.py <exe> <start_hex> <end_hex> xref     # 额外反查调用者
"""
import mmap
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def dump(md, mm, start, end):
    code = mm[start:end]
    n = 0
    for ins in md.disasm(code, start):
        raw = mm[ins.address:ins.address + ins.size]
        print("  0x%08X: %-24s %-8s %s"
              % (ins.address, raw.hex(), ins.mnemonic, ins.op_str))
        n += 1
    print("  （共 %d 条）" % n)
    return n


def find_xrefs(mm, lo, hi, whole=True):
    """扫 call rel32 / jmp rel32，目标落在 [lo,hi) 内。"""
    out = []
    pos = 0
    n = 0
    while True:
        i = mm.find(b"\xE8", pos)
        if i < 0:
            break
        n += 1
        if i + 5 <= len(mm):
            rel = struct.unpack_from("<i", mm, i + 1)[0]
            tgt = i + 5 + rel
            if lo <= tgt < hi:
                out.append((i, tgt))
        pos = i + 1
    return out, n


def func_start_hint(mm, off, back=0x200):
    """向前找 int3 填充，猜测函数真实入口。"""
    lo = max(0, off - back)
    seg = mm[lo:off]
    idx = None
    for k in range(len(seg) - 1, -1, -1):
        if seg[k] == 0xCC:
            continue
        idx = k
        break
    if idx is None:
        return None
    return lo + idx + 1


def main():
    if len(sys.argv) < 3:
        print("用法: python exe_dis_func.py <exe> <start> [end] [xref]")
        return 1
    path = sys.argv[1]
    start = int(sys.argv[2], 0)
    end = int(sys.argv[3], 0) if len(sys.argv) > 3 else start + 0x400
    do_xref = len(sys.argv) > 4 and sys.argv[4].lower() == "xref"
    size = os.path.getsize(path)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print("目标: %s（%d 字节，只读）" % (path, size))

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            hint = func_start_hint(mm, start)
            print("函数入口猜测(向前找 int3): 0x%08X" % (hint if hint else -1))
            print("=" * 78)
            print("反汇编 0x%08X ~ 0x%08X" % (start, end))
            dump(md, mm, start, end)

            if do_xref:
                print("=" * 78)
                print("反查调用者：call rel32 目标落在 0x%08X ~ 0x%08X" % (start, end))
                xrefs, n_e8 = find_xrefs(mm, start, end)
                print("  扫描 %d 个 E8，命中 %d 处（期望误报≈%.2f）"
                      % (n_e8, len(xrefs), n_e8 * (end - start) / (1 << 32)))
                for c_off, tgt in xrefs:
                    h = func_start_hint(mm, c_off)
                    print("    0x%08X  call 0x%08X   (调用者函数起点≈0x%08X)"
                          % (c_off, tgt, h if h else 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
