#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_pe_const.py — PES2021 exe 的 PE 段感知常量解析与转储。

背景：本仓其他工具用"flat 口径"（文件偏移即地址）反汇编代码；但 PES exe 的
.data1 段 RVA=0x1000 != filePtr=0x600（Δ=0xA00），直接按 flat 偏移读 RIP-relative
目标会读错位置。本工具读 PE 段表做 RVA<->fileOffset 换算：

用法：
  python exe_pe_const.py --va 0x2543430                 # 按 RVA(VA-ImageBase) 转储
  python exe_pe_const.py --rip 0x1533156 0x10102d2      # 指令flat地址 + RIP disp32
  python exe_pe_const.py --rip 0x12DE728 0x128BBFF      # movsd xmm,[rip+disp]
  python exe_pe_const.py --sections                      # 只列段表
只读 mmap。
"""
import mmap
import os
import struct
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(BASE, "resources", "Patch 1.07.00",
                   "eFootball PES 2021", "PES2021.exe")
IMAGE_BASE = 0x140000000


def load_sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e:e + 4] == b"PE\0\0"
    coff = e + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    optsz = struct.unpack_from("<H", data, coff + 16)[0]
    sec0 = coff + 20 + optsz
    secs = []
    for i in range(nsec):
        s = sec0 + i * 40
        name = data[s:s + 8].rstrip(b"\0").decode("latin1", "replace")
        vs = struct.unpack_from("<I", data, s + 8)[0]
        rva = struct.unpack_from("<I", data, s + 12)[0]
        rsz = struct.unpack_from("<I", data, s + 16)[0]
        ptr = struct.unpack_from("<I", data, s + 20)[0]
        secs.append((name, rva, vs, ptr, rsz))
    return secs


def rva_to_off(secs, rva):
    for name, rva0, vs, ptr, rsz in secs:
        if rva0 <= rva < rva0 + rsz:
            return ptr + (rva - rva0), name
    return None, None


def off_to_rva(secs, off):
    for name, rva0, vs, ptr, rsz in secs:
        if ptr <= off < ptr + rsz:
            return rva0 + (off - ptr), name
    return None, None


def resolve_rip(secs, insn_flat, disp, size=0):
    """指令 flat 文件偏移 + 符号 disp32 -> 目标 VA/RVA/文件偏移。

    RIP 相对目标是"下一条指令地址 + disp"，需加指令长度 size。
    """
    rva, name = off_to_rva(secs, insn_flat)
    if rva is None:
        return None, None, None, None, 0
    if not size:
        # 用 capstone 解析指令长度
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        with open(EXE, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                ins = next(iter(md.disasm(mm[insn_flat:insn_flat + 16], insn_flat)))
                size = ins.size
    tgt_va = IMAGE_BASE + rva + size + disp
    tgt_rva = tgt_va - IMAGE_BASE
    tgt_off, tgt_name = rva_to_off(secs, tgt_rva)
    return tgt_va, tgt_rva, tgt_off, tgt_name, size


def dump(mm, off, nbytes=16):
    if off is None or off < 0 or off + nbytes > len(mm):
        return None
    return mm[off:off + nbytes]


def main():
    argv = list(sys.argv[1:])
    if "--sections" in argv:
        data = open(EXE, "rb").read()
        print("image_base=0x%X  size=%d" % (IMAGE_BASE, len(data)))
        print("%-9s %-10s %-10s %-10s %-10s" % ("name", "RVA", "vSize", "filePtr", "fSize"))
        for name, rva, vs, ptr, rsz in load_sections(data):
            print("%-9s 0x%08X 0x%08X 0x%08X 0x%08X" % (name, rva, vs, ptr, rsz))
        return 0
    data = open(EXE, "rb").read()
    secs = load_sections(data)
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            if "--rip" in argv:
                i = argv.index("--rip")
                insn = int(argv[i + 1], 0)
                disp = int(argv[i + 2], 0)
                va, rva, off, name, size = resolve_rip(secs, insn, disp)
                print("指令 flat=0x%X disp=%+d sz=%d -> VA=0x%X RVA=0x%X off=0x%X sec=%s"
                      % (insn, disp, size, va, rva, off, name))
                b = dump(mm, off)
                if b is None:
                    print("  越界/未解析")
                else:
                    print("  bytes: %s" % b.hex(" "))
                    print("  u32@0 : 0x%08X" % struct.unpack_from("<I", b, 0)[0])
                    print("  u32@4 : 0x%08X" % struct.unpack_from("<I", b, 4)[0])
                    print("  f32@0 : %r" % (struct.unpack_from("<f", b, 0)[0],))
                    print("  f64@0 : %r" % (struct.unpack_from("<d", b, 0)[0],))
            elif "--va" in argv:
                i = argv.index("--va")
                va = int(argv[i + 1], 0)
                # 若传入的是 flat 文件偏移（< ImageBase），按"flat 即 RVA"处理
                if va >= IMAGE_BASE:
                    rva = va - IMAGE_BASE
                else:
                    rva = va
                off, name = rva_to_off(secs, rva)
                print("RVA=0x%X -> off=0x%X sec=%s" % (rva, off, name))
                b = dump(mm, off)
                if b is None:
                    print("  越界/未解析")
                else:
                    for k in range(0, min(32, len(b)), 4):
                        print("  +0x%02X u32=0x%08X f32=%r" %
                              (k, struct.unpack_from("<I", b, k)[0],
                               struct.unpack_from("<f", b, k)[0]))
            else:
                print(__doc__)
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
