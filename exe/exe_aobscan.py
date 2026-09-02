#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_aobscan.py — 在 exe 里按 AOB 字节签名定位注入点，并反汇编周围代码。

用法：
  python exe_aobscan.py "48 8B 40 2C 48 89 02"           # 单签名
  python exe_aobscan.py "F7 7D 18 48 83 C4 30" --around 0x40 --func
  python exe_aobscan.py --file aob.txt                   # 每行一个名字=hex
只读 mmap，不写目标 exe。签名含空格或 ',' 分隔的 hex；'??' 表示通配。
"""
import mmap
import os
import re
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(BASE, "resources", "Patch 1.07.00",
                   "eFootball PES 2021", "PES2021.exe")


def parse_pat(s):
    s = s.replace(",", " ").strip()
    pat, mask = [], []
    for tok in s.split():
        if tok in ("??", "**", "?"):
            pat.append(0)
            mask.append(0)
        else:
            pat.append(int(tok, 16))
            mask.append(0xFF)
    return bytes(pat), bytes(mask)


def find_pat(mm, pat, mask, lo=0, hi=None):
    if hi is None:
        hi = len(mm)
    out = []
    n = len(pat)
    pos = lo
    while True:
        i = mm.find(bytes(pat), pos, hi)
        if i < 0:
            break
        ok = True
        for k in range(n):
            if mask[k] and mm[i + k] != pat[k]:
                ok = False
                break
        if ok:
            out.append(i)
        pos = i + 1
    return out


def func_start(mm, off, back=0x4000):
    lo = max(0, off - back)
    idx = mm.rfind(b"\xcc", lo, off)
    if idx < 0:
        return None
    while idx + 1 < off and mm[idx + 1] == 0xCC:
        idx += 1
    return idx + 1


def disassemble(md, mm, start, size):
    out = []
    for ins in md.disasm(mm[start:start + size], start):
        out.append(ins)
        if ins.mnemonic == "ret":
            break
    return out


def main():
    argv = list(sys.argv[1:])
    around = 0x10
    do_func = False
    if "--around" in argv:
        i = argv.index("--around")
        around = int(argv[i + 1], 0)
        del argv[i:i + 2]
    if "--func" in argv:
        do_func = True
        argv.remove("--func")
    specs = []
    if "--file" in argv:
        i = argv.index("--file")
        fn = argv[i + 1]
        for line in open(fn, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                name, pat = line.split("=", 1)
                specs.append((name.strip(), pat.strip()))
            else:
                specs.append((os.path.basename(fn), line))
    else:
        for a in argv:
            specs.append((a[:24], a))
    if not specs:
        print(__doc__)
        return 1

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print("目标:", EXE)
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for name, patstr in specs:
                pat, mask = parse_pat(patstr)
                hits = find_pat(mm, pat, mask)
                print("=" * 88)
                print("%s  (%dB) 命中 %d 处" % (name, len(pat), len(hits)))
                for h in hits[:8]:
                    lo = h - around
                    if lo < 0:
                        lo = 0
                    print("  @ 0x%08X  函数起点≈0x%X"
                          % (h, func_start(mm, h) if do_func or around < 0x30 else 0))
                    if around:
                        for ins in disassemble(md, mm, lo, around * 2 + len(pat) + 0x20):
                            if ins.address >= h + len(pat) + 0x10 and ins.address > h:
                                continue
                            print("     0x%08X  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
    return 0


if __name__ == "__main__":
    sys.exit(main())