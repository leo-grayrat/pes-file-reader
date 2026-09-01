#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_dis_callers.py — 把「调用了 MT19937 的 14 个点」还原成所属函数，并给每个函数打常量指纹。

为什么需要它：
  exe_xref_mt.py 只找到了 call 指令本身，但 call 指令在哪个函数里、函数内部还用了
  什么常量，才是判断「这是不是存档加解密例程」的依据。手工解 hex 太慢，这里用
  capstone 做线性反汇编。

函数边界怎么定（无符号表时的启发式）：
  MSVC /O2 会在函数之间填 int3(0xCC) 对齐。从一个 call 点向前 0x400 字节内逐字节
  试起点做线性反汇编，要求反汇编流恰好在 call_off 处落在一整条 call 指令上；
  取满足条件的最大起点（最贴近真实入口的那个）。向下则解到出现 int3 为止。

地址口径：整个文件按 flat image 处理（base=0，偏移即地址）。这样指令边界是准的，
call/jmp 的 rel32 目标在文件内也自洽；只在与 IDA（imagebase=0x140000000）对照时
才有节对齐差 Δ，本脚本不依赖外部地址。

只读：仅 mmap 读取，绝不执行/加载其代码，绝不写入目标文件。

用法：
  python exe_dis_callers.py <exe> <call_off_hex> [call_off_hex ...]
"""
import mmap
import os
import sys
from collections import Counter

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

# 存档加解密相关的"指纹常量"（来自 pes_decrypt.py 的已知算法）
#   crypt_stream : init_by_array(key,16) + 4×genrand + ror/rol 15,11,7,13
#   crypt_header : master_key 64B, header_key 取自 input[256:320], xor 64B
#   文件结构     : 320B 加密头 + 208B 文件头 + desc/logo/data/serial
FINGERPRINT = {
    16: "init_by_array 的 key 长度(16×uint32=64B 主密钥)",
    15: "ror(_,15)",
    11: "rol(_,11)",
    7: "rol(_,7)",
    13: "ror(_,13)",
    64: "主密钥长度 64B / xor 64B",
    320: "加密头 320B",
    208: "文件头 208B",
    256: "header_key 起点 input[256]",
    624: "MT19937 N",
    397: "MT19937 M",
    5489: "MT19937 默认种子",
}

BACK_SCAN = 0x400
FWD_SCAN = 0x4000


def linear_dis(md, code, base):
    """线性反汇编，返回 [(addr, size, mnemonic, op_str)]。"""
    out = []
    for ins in md.disasm(code, base):
        out.append((ins.address, ins.size, ins.mnemonic, ins.op_str, ins))
    return out


def find_func_start(md, mm, call_off):
    """向前试探起点，找到能让反汇编流恰好在 call_off 处落在整条 call 上的最大起点。"""
    lo = max(0, call_off - BACK_SCAN)
    chunk = mm[lo:call_off + 16]
    best = None
    for cand in range(lo, call_off):
        off_in_chunk = cand - lo
        seq = linear_dis(md, chunk[off_in_chunk:], cand)
        for (addr, size, mn, op, _ins) in seq:
            if addr == call_off:
                if mn == "call":
                    best = cand  # 取最大（循环里后面的 cand 更大，会覆盖）
                break
            if addr > call_off:
                break
    return best


def disasm_func(md, mm, start, limit=FWD_SCAN):
    """从 start 向下反汇编，遇到 int3 / hlt / 连续非法即停。"""
    code = mm[start:start + limit]
    out = []
    for ins in md.disasm(code, start):
        if ins.mnemonic in ("int3", "hlt", "ud2"):
            break
        out.append(ins)
        if ins.mnemonic == "ret":
            # ret 后再看 2 字节是否就是 int3，是则说明函数到此结束
            nxt = mm[ins.address + ins.size:ins.address + ins.size + 2]
            if nxt[:1] == b"\xcc" or nxt[:2] == b"\x90\x90" or not nxt:
                break
    return out


def summarize(md, mm, call_off, tgt):
    start = find_func_start(md, mm, call_off)
    print("=" * 78)
    print("call @0x%08X -> 0x%08X" % (call_off, tgt))
    if start is None:
        print("  （无法确定所属函数起点，跳过）")
        return None
    insns = disasm_func(md, mm, start)
    if not insns:
        print("  （反汇编为空）")
        return None
    end = insns[-1].address + insns[-1].size
    print("  所属函数: 0x%08X ~ 0x%08X  (%d 字节, %d 条指令)"
          % (start, end, end - start, len(insns)))

    calls = []
    imms = Counter()
    for ins in insns:
        if ins.mnemonic == "call":
            calls.append(ins)
        for op in ins.operands:
            if op.type == X86_OP_IMM:
                v = op.imm
                imms[v] += 1
                if v > 0xFFFFFFFF00000000:  # 负数补码的 rip 相对量
                    imms[v - (1 << 64)] += 1

    print("  -- call 目标 (%d) --" % len(calls))
    for ins in calls[:24]:
        try:
            t = int(ins.op_str, 0)
            print("     0x%08X  call  0x%08X" % (ins.address, t & 0xFFFFFFFFFFFFFFFF))
        except ValueError:
            print("     0x%08X  call  %s" % (ins.address, ins.op_str))

    hits = []
    for v in sorted(imms):
        if v in FINGERPRINT:
            hits.append((v, imms[v], FINGERPRINT[v]))
    print("  -- 命中存档/加解密指纹常量 --")
    if hits:
        for v, n, d in hits:
            print("     0x%X (%d) x%d   %s" % (v, v, n, d))
    else:
        print("     （无）")

    small = sorted([v for v in imms if 0 <= v <= 1024])
    if small:
        print("  -- 小立即数分布(0~1024) --")
        print("     " + " ".join("%d×%d" % (v, imms[v]) for v in small))

    return {"start": start, "end": end, "imms": imms,
            "calls": [c.op_str for c in calls], "n_ins": len(insns)}


def main():
    if len(sys.argv) < 3:
        print("用法: python exe_dis_callers.py <exe> <call_off_hex> [...]")
        return 1
    path = sys.argv[1]
    offs = [int(a, 0) for a in sys.argv[2:]]
    size = os.path.getsize(path)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    print("目标: %s（%d 字节，只读）" % (path, size))
    print("待分析调用点 %d 个" % len(offs))

    results = []
    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # 先重扫一次得到每个 call 的目标（复用 exe_xref_mt 的逻辑）
            import struct
            for off in offs:
                rel = struct.unpack_from("<i", mm, off + 1)[0]
                tgt = off + 5 + rel
                r = summarize(md, mm, off, tgt)
                if r:
                    r["call_off"] = off
                    r["tgt"] = tgt
                    results.append(r)

    print("=" * 78)
    print("汇总（按是否命中指纹排序）")
    def score(r):
        return sum(1 for v in r["imms"] if v in FINGERPRINT)
    for r in sorted(results, key=score, reverse=True):
        tags = sorted([v for v in r["imms"] if v in FINGERPRINT])
        print("  0x%08X~0x%08X  %5dB  指纹[%s]" % (
            r["start"], r["end"], r["end"] - r["start"],
            ",".join(str(t) for t in tags) if tags else "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
