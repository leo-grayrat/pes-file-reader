#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_frame_ctor.py — 反汇编 ReplayFrame 构造器，提取「帧级字段写入」与「子对象构造调用」。

目标函数（flat 文件偏移 = 地址，与 exe_dis_func.py 一致）：
  ReplayFrame 构造器 @ 0x00A89C10，分配 0x1fb0 (8112B) 单帧缓冲。

只读 mmap，不执行、不写。capstone 反汇编。

输出两类信息：
  A. 字段写入：mov* ptr [reg + 0x<DISP>], <imm>  —— 记录 (base_reg, disp, imm, size)
  B. 子对象构造：call rel32 <target>  —— 记录 (call_site, target)
  C. 子对象指针取址：lea reg, [reg + 0x<DISP>]  —— 记录 (disp)

按 disp 排序后，低 disp = 帧对象直接字段；高 disp（≥0x1000）= 内嵌子对象字段。
"""
import mmap
import re
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = "resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe"
START = 0x00A89C10
# 构造器可能较长（分配 0x1fb0 并初始化各子对象）；扫 0x1500 字节足够覆盖
END = START + 0x1500

WRITE_RE = re.compile(r"^(?P<sz>byte|word|dword|qword) ptr \[(?P<reg>\w+)\s*\+\s*0x(?P<off>[0-9A-Fa-f]+)\]\s*,\s*(?P<val>.*)$")
LEA_RE = re.compile(r"^\[(?P<reg>\w+)\s*\+\s*0x(?P<off>[0-9A-Fa-f]+)\]$")


def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            code = mm[START:END]
            writes = []          # (off, size_bytes, reg, val_str, addr)
            calls = []           # (call_site, target)
            leas = []            # (off, reg, addr)
            for ins in md.disasm(code, START):
                s = ins.mnemonic
                op = ins.op_str
                # 字段写入
                m = WRITE_RE.match(op)
                if m and s.startswith("mov"):
                    sz_map = {"byte": 1, "word": 2, "dword": 4, "qword": 8}
                    off = int(m.group("off"), 16)
                    writes.append((off, sz_map[m.group("sz")], m.group("reg"),
                                   m.group("val"), ins.address))
                # 子对象构造调用
                elif s == "call":
                    if op.startswith("0x"):
                        tgt = int(op, 16)
                        calls.append((ins.address, tgt))
                # 子对象指针取址
                elif s == "lea":
                    # op 形如 "rdx, [rcx + 0x6b8]"
                    parts = op.split(",", 1)
                    if len(parts) == 2:
                        inner = parts[1].strip()
                        lm = LEA_RE.match(inner)
                        if lm:
                            off = int(lm.group("off"), 16)
                            leas.append((off, lm.group("reg"), ins.address))

    print("=== A. 字段写入（按帧内偏移排序）===")
    print("  %-6s %-4s %-5s %-12s %-10s" % ("off", "sz", "reg", "imm", "ins@"))
    for off, sz, reg, val, addr in sorted(writes, key=lambda x: x[0]):
        print("  0x%04X  %-4d %-5s %-12s 0x%08X" % (off, sz, reg, val, addr))

    print("\n=== B. 子对象构造调用 call rel32 ===")
    for csite, tgt in sorted(calls):
        print("  0x%08X  call 0x%08X" % (csite, tgt))

    print("\n=== C. 子对象指针取址 lea reg,[reg+off] ===")
    for off, reg, addr in sorted(leas):
        print("  0x%04X  (lea %s) @0x%08X" % (off, reg, addr))

    # 统计：字段写入覆盖到的最高偏移（推断帧对象真实尺寸下限）
    if writes:
        maxw = max(off + sz for off, sz, *_ in writes)
        print("\n字段写入最高覆盖到 0x%04X (+%d) = 帧对象尺寸下限参考" % (maxw, maxw))


if __name__ == "__main__":
    sys.exit(main())
