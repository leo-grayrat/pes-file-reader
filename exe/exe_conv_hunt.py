#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_conv_hunt.py — 在 exe 里找「240B/312B 磁盘记录 → 380B 运行时球员对象」的转换例程。

思路：
  纯拷贝例程 0x00AF6290（380B→380B，66 个调用者）已经确认是运行时复制，不是装载器。
  装载器应同时具备两个特征：
    A. 出现 imul 0x17C(380) 或 0x138(312) / 0xF0(240) 之一（步长鱼钩）；
    B. 反汇编里对两个不同基址寄存器分别做「源区(0x00~0xF0)读」与「目标区(0xF0~0x17C)写」，
       即 field-by-field 转换而非整块 memcpy。
  本工具先扫指定代码区间里所有 imul 命中点，按所属函数归组，
  再对每个函数反汇编出「字段访问摘要」（读/写偏移直方图），便于一眼识别转换器。

地址口径：flat image（文件偏移即地址）。只读 mmap，绝不执行/加载目标代码。

用法：
  python exe_conv_hunt.py 0xAF0000 0xB50000            # 扫区间内 380 步长命中 + 函数摘要
  python exe_conv_hunt.py 0xAF0000 0xB50000 --strides 0xF0 0x138 0x17C 0x690
  python exe_conv_hunt.py 0x1020000 0x1050000 --strides 0xF0 0x138 0x17C
"""
import mmap
import os
import re
import struct
import sys
from collections import Counter, defaultdict

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(BASE, "resources", "Patch 1.07.00",
                   "eFootball PES 2021", "PES2021.exe")

RE_IMUL = re.compile(r"^(r[a-z0-9]+), (r[a-z0-9]+), (0x[0-9a-f]+)$")
RE_SIMPLE = re.compile(r"^\[(r[a-z0-9]+)(?:\s*\+\s*(0x[0-9a-f]+|\d+))?\]$")
SIZE_OF = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16}


def find_imul_imm(mm, value):
    """找以 value 为立即数的 imul reg,reg,imm 指令偏移。"""
    out = []
    n = len(mm)
    pos = 0
    while True:
        i = mm.find(b"\x69", pos, n - 6)
        if i < 0:
            break
        modrm = mm[i + 1]
        if modrm >= 0xC0 and mm[i + 2:i + 6] == struct.pack("<i", value):
            prev = mm[i - 1] if i > 0 else 0
            out.append(i - 1 if 0x40 <= prev <= 0x4F else i)
        pos = i + 1
    return out


def func_start(mm, off, back=0x2000):
    """向前找 int3 填充，取最后一个连续 CC 后的地址作为函数入口猜测。"""
    lo = max(0, off - back)
    idx = mm.rfind(b"\xcc", lo, off)
    if idx < 0:
        return None
    while idx + 1 < off and mm[idx + 1] == 0xCC:
        idx += 1
    return idx + 1


def disasm_func(md, mm, start, limit=0x3000):
    out = []
    for ins in md.disasm(mm[start:start + limit], start):
        if ins.mnemonic in ("int3", "hlt", "ud2"):
            break
        out.append(ins)
        if ins.mnemonic == "ret":
            nxt = mm[ins.address + ins.size:ins.address + ins.size + 2]
            if nxt[:1] == b"\xcc" or nxt[:2] == b"\x90\x90" or not nxt:
                break
    return out


def summarize(mm, start, strides):
    """反汇编一个函数，返回摘要。"""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = disasm_func(md, mm, start)
    if not insns:
        return None
    end = insns[-1].address + insns[-1].size
    imuls = Counter()
    reads = Counter()
    writes = Counter()
    calls = Counter()
    for ins in insns:
        mn = ins.mnemonic
        if mn == "imul":
            m = RE_IMUL.match(ins.op_str)
            if m:
                imuls[int(m.group(3), 0)] += 1
        elif mn in ("call", "jmp"):
            t = ins.op_str
            if t.startswith("0x"):
                calls[int(t, 0)] += 1
        if mn not in ("mov", "movzx", "movsx", "movsxd", "movups",
                      "movaps", "movdqu", "lea", "add", "cmp", "or", "and", "xor", "test"):
            continue
        for piece, is_dst in ((ins.op_str, False),):
            pass
        # 手动按逗号拆（内存操作数里无顶层逗号）
        parts = split_ops(ins.op_str)
        for idx, piece in enumerate(parts):
            if not piece or "[" not in piece:
                continue
            m = RE_SIMPLE.match(piece[piece.index("["):])
            if not m:
                continue
            base = m.group(1)
            if base in ("rsp", "rbp", "rip"):
                continue
            disp = int(m.group(2), 0) if m.group(2) else 0
            size = 4
            for k, v in SIZE_OF.items():
                if piece.startswith(k + " ptr"):
                    size = v
                    break
            # 目的操作数 = 第一个参数
            if idx == 0 and mn.startswith("mov") and not mn.startswith("movzx"):
                writes[(base, disp)] += size
            else:
                reads[(base, disp)] += size
    return {
        "start": start, "end": end, "n": len(insns),
        "imuls": dict(imuls), "calls": dict(calls),
        "reads": dict(reads), "writes": dict(writes),
    }


def split_ops(op_str):
    depth = 0
    for i, ch in enumerate(op_str):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        elif ch == "," and depth == 0:
            return op_str[:i].strip(), op_str[i + 1:].strip()
    return op_str.strip(), None


def main():
    argv = list(sys.argv[1:])
    strides = [0x17C]
    if "--strides" in argv:
        i = argv.index("--strides")
        strides = [int(a, 0) for a in argv[i + 1:i + 1 + 8]]
        del argv[i:i + 1 + 8]
    if len(argv) < 2:
        print(__doc__)
        return 1
    lo = int(argv[0], 0)
    hi = int(argv[1], 0)

    if not os.path.exists(EXE):
        print("找不到目标 exe：%s" % EXE)
        return 1
    print("目标: %s（%d 字节，只读 mmap，flat 口径）" % (EXE, os.path.getsize(EXE)))
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for stride in strides:
                hits = [h for h in find_imul_imm(mm, stride) if lo <= h < hi]
                print("=" * 90)
                print("步长 0x%X (%d)：区间 0x%X~0x%X 命中 %d 处"
                      % (stride, stride, lo, hi, len(hits)))
                owners = defaultdict(list)
                for h in hits:
                    st = func_start(mm, h)
                    owners[st].append(h)
                if not owners:
                    print("  （无命中）")
                    continue
                for st in sorted(owners, key=lambda k: (-len(owners[k]), k if k else 0)):
                    pts = owners[st]
                    owner = st if st is not None else pts[0]
                    if st is None:
                        print("  函数起点未定，跳过 0x%X（%d 处）" % (pts[0], len(pts)))
                        continue
                    s = summarize(mm, owner, strides)
                    if not s:
                        continue
                    # 挑出"转换器"线索：同时存在 240/312/380 两种以上 imul，或读写跨越 0xF0 分界
                    big = sorted([v for v in s["imuls"] if v in (0xF0, 0x138, 0x17C, 0x690)])
                    has_r_low = any(d < 0xF0 for (b, d) in s["reads"])
                    has_w_hi = any(d >= 0xF0 for (b, d) in s["writes"])
                    flag = ""
                    if len(big) >= 2:
                        flag += " ★多步长"
                    if has_r_low and has_w_hi:
                        flag += " ◆低读高写"
                    print("  函数 0x%08X~0x%08X %4dB %3d条  步长[%s]%s"
                          % (s["start"], s["end"], s["end"] - s["start"],
                             s["n"], ",".join("%x" % v for v in big), flag))
                    print("      imul分布: %s"
                          % " ".join("%d(0x%X)x%d" % (v, v, c)
                                     for v, c in sorted(s["imuls"].items()) if v > 1 or c >= 1))
                    if len(pts) <= 4:
                        print("      命中点: %s" % ", ".join("0x%X" % p for p in pts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
