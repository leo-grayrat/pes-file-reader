#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_find_frame_ctrs.py — 在官方 PES2021.exe 里搜索回放事件流的"结构特征立即数"，
定位帧网格 / 槽包 / blob 的写出函数（静态、只读 mmap）。

数据侧已闭环（50/50）：
  frame_size = 8112 (0x1FB0)   frame_count = 660 (0x294)
  slot_stride = 300 (0x12C)    blob = 248 (0xF8)     pose = 20 x i16
事件流 0x51B1C0 = 8112*660，由比赛实录引擎的 vtable 虚方法填充，保存到时整段拷入 buffer。

本脚本：
  1) 全文件搜 4 字节小端立即数 immediate 的字节型（B0 1F 00 00 / 94 02 00 00 / 2C 01 00 00 /
     F8 00 00 00 / 14 00 00 00），但只保留"紧跟在 mov 系 opcode 之后"的，过滤数据节噪声。
  2) 以最特异的 0x1FB0(8112) 为锚，扫描其 ±0x800 内是否同时出现 0x12C(300)/0x294(660)，
     给候选窗口打分，输出高分地址。
  3) 对高分地址，反汇编其前后窗口写入 exe_find_frame_cand.txt 供人工阅读。

只读：mmap 读，绝不写/执行目标文件。
用法：python exe_find_frame_ctrs.py <exe>
"""
import mmap
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# 目标立即数（小端 4 字节）：name -> bytes
TARGETS = {
    "8112(0x1FB0:frame_size)": b"\xB0\x1F\x00\x00",
    "660(0x294:frame_count)":  b"\x94\x02\x00\x00",
    "300(0x12C:slot_stride)":  b"\x2C\x01\x00\x00",
    "248(0xF8:blob)":          b"\xF8\x00\x00\x00",
    "20(0x14:pose_i16)":       b"\x14\x00\x00\x00",
}

# mov 系 opcode：操作数紧跟 4 字节 imm（过滤掉纯数据节里的巧合命中）
MOV_OPS = {
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,  # mov eax/ecx/edx/ebx/esp/ebp/esi/edi, imm32
    0x41B8, 0x41B9, 0x41BA, 0x41BB, 0x41BC, 0x41BD, 0x41BE, 0x41BF,  # mov r8d..r15d, imm32
    0xC7,  # mov r/m32, imm32 (含 REX 0x41/0x45 + C7)
}


def find_imm_in_mov(mm, imm_bytes):
    """返回所有 'opcode + imm_bytes' 的偏移（opcode 属于 mov 系）。"""
    hits = []
    pos = 0
    n = len(mm)
    while True:
        i = mm.find(imm_bytes, pos)
        if i < 0:
            break
        # 前导字节 = opcode（可能带 REX 前缀 0x41/0x45）
        pre = mm[i - 1]
        pre2 = mm[i - 2] if i >= 2 else 0
        if pre in MOV_OPS:
            hits.append(i - 1)
        elif (pre2 in (0x41, 0x45)) and pre == 0xC7:
            hits.append(i - 2)
        pos = i + 1
    return hits


def scan_neighborhood(mm, anchor, radius, need):
    """anchor 处为 0x1FB0 命中；看 ±radius 内是否含 need 集合的立即数。返回计数。"""
    lo = max(0, anchor - radius)
    hi = min(len(mm), anchor + radius)
    seg = mm[lo:hi]
    cnt = 0
    for name, ib in need.items():
        if ib in seg:
            cnt += 1
    return cnt


def main():
    if len(sys.argv) < 2:
        print("用法: python exe_find_frame_ctrs.py <exe>")
        return 1
    path = sys.argv[1]
    size = os.path.getsize(path)
    print("目标: %s (%d 字节，只读)" % (path, size))

    need = {
        "300(0x12C:slot_stride)": TARGETS["300(0x12C:slot_stride)"],
        "660(0x294:frame_count)": TARGETS["660(0x294:frame_count)"],
        "248(0xF8:blob)": TARGETS["248(0xF8:blob)"],
        "20(0x14:pose_i16)": TARGETS["20(0x14:pose_i16)"],
    }

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # 1) 各立即数的命中数（粗筛）
            print("=" * 70)
            print("立即数命中数（仅计 mov 系 opcode 后的）：")
            base = {}
            for name, ib in TARGETS.items():
                hs = find_imm_in_mov(mm, ib)
                base[name] = hs
                print("  %-26s %d 处" % (name, len(hs)))

            # 2) 以 0x1FB0 为锚，评分邻域
            print("=" * 70)
            print("以 8112(0x1FB0) 为锚，±0x800 内同时出现其余常数的候选：")
            anchor_hits = base["8112(0x1FB0:frame_size)"]
            scored = []
            for a in anchor_hits:
                score = scan_neighborhood(mm, a, 0x800, need)
                if score >= 1:
                    scored.append((score, a))
            scored.sort(reverse=True)
            print("  候选（score=邻域内命中常数数, 共 %d）" % len(scored))
            for score, a in scored[:40]:
                print("    score=%d  off=0x%08X" % (score, a))

            # 3) 对 top 候选反汇编窗口
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True
            top = [a for _, a in scored[:6]]
            if not top:
                top = [a for _, a in scored[:3]]
            out_path = "exe_find_frame_cand.txt"
            with open(out_path, "w") as out:
                out.write("回放帧/槽写出候选函数反汇编\n")
                out.write("锚=8112(0x1FB0)，score>=1 的 top 候选\n\n")
                for a in top:
                    start = a - 0x180
                    end = a + 0x500
                    out.write("==== 候选锚 off=0x%08X  反汇编 0x%08X~0x%08X ====\n"
                              % (a, start, end))
                    code = mm[start:end]
                    for ins in md.disasm(code, start):
                        raw = mm[ins.address:ins.address + ins.size]
                        out.write("  0x%08X: %-22s %-8s %s\n"
                                  % (ins.address, raw.hex(), ins.mnemonic, ins.op_str))
                    out.write("\n")
            print("=" * 70)
            print("top %d 候选反汇编已写入 %s" % (len(top), out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
