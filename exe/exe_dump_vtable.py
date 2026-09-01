#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_dump_vtable.py — dump 回放帧类 vtable(0x1bcea5c)，逐个反汇编虚方法，
找含「正确槽步长 add/imul reg,0x12C(300)」且邻域出现 248(blob)/20(pose)/10(槽数) 的槽写出方法。

修复：0x12C 作为步长必须是真正的 add/imul 指令，而不是 `mov byte ptr [rcx+0x12c],1`
（后者是 C6 81 ...，modrm=0x81，会把 0x12c 当偏移）。判定：
  - `add r/m, 0x12C` : 字节 ...81 <modrm> 2C 01 00 00 且前导(操作码位)是 0x81（可选 REX.W 48）
  - `imul r, r/m, 0x12C` : 字节 ...69 <modrm> 2C 01 00 00 且操作码位 0x69
  - `add eax, 0x12C` : 05 2C 01 00 00
只读 mmap。
用法：python exe_dump_vtable.py <exe>
"""
import mmap
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

VTABLE = 0x1BCEA5C
NENT = 28
WINDOW = 0x160

NEED = {
    "248(0xF8:blob)":  b"\xF8\x00\x00\x00",
    "40(0x28:poseB)":  b"\x28\x00\x00\x00",
    "20(0x14:poseN)":  b"\x14\x00\x00\x00",
    "10(0x0A:slots)":  b"\x0A\x00\x00\x00",
    "8112(0x1FB0:frame)": b"\xB0\x1F\x00\x00",
}


def find_real_stride(mm, lo, hi):
    """在 [lo,hi) 内找真正的 add/imul reg,0x12C(300)。返回命中偏移列表。"""
    out = []
    imm = b"\x2C\x01\x00\x00"
    pos = lo
    while True:
        i = mm.find(imm, pos, hi)
        if i < 0:
            break
        b1 = mm[i - 1]        # modrm (for 81/69 forms)
        b2 = mm[i - 2]        # opcode or REX+opcode
        b3 = mm[i - 3]        # REX (optional)
        # add eax, imm32 : 05 id
        if b1 == 0x05 and False:
            pass
        # add r/m32, imm32 : 81 /0 id   (opcode at i-2 == 0x81, modrm at i-1)
        if b2 == 0x81 and b1 not in (0xC6, 0xC7):
            out.append(i)      # 81 /0
            pos = i + 1
            continue
        # imul r32, r/m32, imm32 : 69 /r id  (opcode at i-2 == 0x69)
        if b2 == 0x69:
            out.append(i)
            pos = i + 1
            continue
        # add eax, imm32 : 05 id  (opcode at i-1 == 0x05)
        if b1 == 0x05:
            out.append(i)
            pos = i + 1
            continue
        pos = i + 1
    return out


def main():
    if len(sys.argv) < 2:
        print("用法: python exe_dump_vtable.py <exe>")
        return 1
    path = sys.argv[1]
    size = os.path.getsize(path)
    print("目标: %s (%d 字节，只读)" % (path, size))

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # 1) dump vtable
            print("=" * 70)
            print("vtable @ 0x%08X, %d 项：" % (VTABLE, NENT))
            entries = []
            for k in range(NENT):
                a = VTABLE + k * 8
                fn = struct.unpack_from("<Q", mm, a)[0]
                entries.append(fn)
                print("  [%2d] 0x%08X" % (k, fn))
            # 2) 逐个反汇编，找槽写出方法
            print("=" * 70)
            print("逐虚方法扫描（真实 0x12C 步长 + 邻域 248/40/20/10）：")
            results = []
            for k, fn in enumerate(entries):
                if fn < 0x1000 or fn >= size:
                    continue
                strides = find_real_stride(mm, fn, fn + WINDOW)
                if not strides:
                    continue
                # 邻域评分
                seg = mm[fn: fn + 0x800]
                score = 0
                det = {}
                for name, ib in NEED.items():
                    c = seg.count(ib)
                    if c:
                        score += min(c, 5)
                        det[name] = c
                results.append((len(strides), score, k, fn, det, strides[0]))
            results.sort(key=lambda r: (r[0], r[1]), reverse=True)
            for ns, sc, k, fn, det, fst in results[:20]:
                print("  vidx=%2d fn=0x%08X  0x12C步长命中=%d  邻域分=%d  %s"
                      % (k, fn, ns, sc, det))
            # 3) 反汇编 top 候选
            top = [fn for _, _, _, fn, _, _ in results[:4]]
            if not top:
                top = [fn for _, _, _, fn, _, _ in results[:2]]
            out = "exe_vtable_cand.txt"
            with open(out, "w") as fo:
                fo.write("回放帧类 vtable 虚方法候选（槽写出函数）\n\n")
                for fn in top:
                    fo.write("==== 虚方法 vidx  fn=0x%08X  反汇编 0x%08X~0x%08X ====\n"
                             % (fn, fn, fn + 0x600))
                    for ins in md.disasm(mm[fn: fn + 0x600], fn):
                        raw = mm[ins.address:ins.address + ins.size]
                        fo.write("  0x%08X: %-22s %-8s %s\n"
                                 % (ins.address, raw.hex(), ins.mnemonic, ins.op_str))
                    fo.write("\n")
            print("=" * 70)
            print("top %d 虚方法反汇编 -> %s" % (len(top), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
