#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_find_slot_writer.py — 定位回放帧内「槽包填充函数」。

数据侧：每帧 8112B = 16B 头 + 4096B 状态表(256x16B) + 4000B 事件区；
事件区 = 16B 子头 + 10 槽包(槽间距 300B)，每槽 = 12B 头 + 20x i16(=40B) + 248B blob。
所以填充函数必然出现：槽步长 0x12C(300) 的 add/imul，且邻域内应有
  blob 大小 0xF8(248)、pose 字节 0x28(40)、pose 个数 0x14(20)、槽数 0x0A(10)。

本脚本：
  1) 全文件扫 0x12C(300) 作为 add/imul/mov 的 imm32（字节 2C 01 00 00，前导 81/69/C7/05）。
  2) 对每个命中，±0x600 内扫描 0xF8/0x28/0x14/0x0A 的 mov-imm 出现次数，评分。
  3) 输出高分地址并反汇编窗口到 exe_find_slot_cand.txt。
只读 mmap。
用法：python exe_find_slot_writer.py <exe>
"""
import mmap
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# 槽步长 0x12C(300) 的 imm32 小端 = 2C 01 00 00，前导 opcode
STRIDE_MARKERS = {0x81: "add", 0x69: "imul", 0x05: "add-eax", 0xC7: "mov"}

NEED = {
    "248(0xF8:blob)":  b"\xF8\x00\x00\x00",
    "40(0x28:poseB)":  b"\x28\x00\x00\x00",
    "20(0x14:poseN)":  b"\x14\x00\x00\x00",
    "10(0x0A:slots)":  b"\x0A\x00\x00\x00",
    "8112(0x1FB0:frame)": b"\xB0\x1F\x00\x00",
}


def find_stride(mm):
    """返回所有 'add/imul reg, 0x12C(300)' 处的偏移。

    真正的步长指令（排除 C6 81 / C7 81 这类 'mov [reg+0x12c], imm' 脏标记）：
      - add r/m32, imm32  : ... 81 <modrm> 2C 01 00 00   (操作码在 i-2 == 0x81，可选 REX.W 48)
      - imul r32,r/m32,imm32 : ... 69 <modrm> 2C 01 00 00 (操作码在 i-2 == 0x69)
      - add eax, imm32    : 05 2C 01 00 00              (操作码在 i-1 == 0x05)
    注意：mov byte [rcx+0x12c],1 = C6 81 2C 01 00 00 01，其 i-2 = 0xC6（非 0x81），
    被本规则排除。
    """
    hits = []
    imm = b"\x2C\x01\x00\x00"
    pos = 0
    n = len(mm)
    while True:
        i = mm.find(imm, pos)
        if i < 0:
            break
        b1 = mm[i - 1]        # modrm（add/imul 形式）或操作码（add-eax 形式）
        b2 = mm[i - 2]        # 操作码（add/imul 形式）或 REX（imul/add 带 REX.W）
        real = False
        if b2 == 0x81 and b1 not in (0xC6, 0xC7):
            real = True
        elif b2 == 0x69:
            real = True
        elif b1 == 0x05:
            real = True
        if real:
            op = "add" if (b2 == 0x81 or b1 == 0x05) else "imul"
            hits.append((i - (2 if b1 != 0x05 else 1), op))
        pos = i + 1
    return hits


def score_neighborhood(mm, anchor, radius):
    lo = max(0, anchor - radius)
    hi = min(len(mm), anchor + radius)
    seg = mm[lo:hi]
    s = 0
    detail = {}
    for name, ib in NEED.items():
        c = seg.count(ib)
        if c:
            s += min(c, 4)  # 封顶，避免噪声主导
            detail[name] = c
    return s, detail


def main():
    if len(sys.argv) < 2:
        print("用法: python exe_find_slot_writer.py <exe>")
        return 1
    path = sys.argv[1]
    size = os.path.getsize(path)
    print("目标: %s (%d 字节，只读)" % (path, size))

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            hits = find_stride(mm)
            print("=" * 70)
            print("0x12C(300) 作为 add/imul/mov imm32 的命中: %d 处" % len(hits))

            scored = []
            for off, op in hits:
                s, detail = score_neighborhood(mm, off, 0x600)
                if s >= 2:
                    scored.append((s, off, op, detail))
            scored.sort(reverse=True)
            print("邻域内(score>=2)候选: %d" % len(scored))
            for s, off, op, detail in scored[:30]:
                print("  score=%d  off=0x%08X  op=%s  %s" % (s, off, op, detail))

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            top = [off for _, off, _, _ in scored[:6]]
            out = "exe_find_slot_cand.txt"
            with open(out, "w") as fo:
                fo.write("回放槽包填充候选函数\n锚=0x12C(300) add/imul 步长，邻域含 248/40/20/10\n\n")
                for a in top:
                    start = a - 0x200
                    end = a + 0x600
                    fo.write("==== 候选 off=0x%08X  反汇编 0x%08X~0x%08X ====\n" % (a, start, end))
                    for ins in md.disasm(mm[start:end], start):
                        raw = mm[ins.address:ins.address + ins.size]
                        fo.write("  0x%08X: %-22s %-8s %s\n"
                                 % (ins.address, raw.hex(), ins.mnemonic, ins.op_str))
                    fo.write("\n")
            print("=" * 70)
            print("top %d 候选反汇编 -> %s" % (len(top), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
