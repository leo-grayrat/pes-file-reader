#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_struct_fields.py — 从编译器生成的「拷贝赋值代码」里反推 struct 的精确字段图。

原理：
  C++ 里 `*dst = *src;` 若结构体含位域或不可 memcpy 的成员，MSVC 会展开成逐字段搬运：
      mov   eax, [rbx+8]        /  mov [r8+8], eax          → +0x08 是 4 字节字段
      movzx eax, byte  [rbx+16] /  mov [r8+16], al          → +0x10 是 1 字节字段
      mov eax,[rbx+4]; xor eax,[r8+4]; and eax,0x0FFF0000
      xor [r8+4],eax                                        → +0x04 的 bit16..27 是位域
  纯 POD 的连续区段则被降级成 movups 批量搬（SSE 16B 一拍），
  于是「显式字段」+「批量区」拼起来正好等于 sizeof(struct)。

  所以：只要在 exe 里找到某张表的元素拷贝代码，就能把该结构的字段边界、
  位宽、位域 mask 全部读出来——不靠社区 wiki，不靠猜偏移，是编译器亲口说的。

  找拷贝代码的入口通常来自 exe_struct_hooks.py：
  凡是 `imul reg, idx, <步长>` 命中的函数，多半就在搬这张表的元素。

地址口径：flat image（文件偏移即地址）。
只读：仅 mmap 读取，绝不执行/加载目标代码，绝不写入目标文件。

用法：
  python exe_struct_fields.py <start_hex> [end_hex]
  python exe_struct_fields.py 0x131AB90 0x131AD80
  python exe_struct_fields.py 0x131AB90 0x131AD80 --expect 0x254   # 校验总大小
"""
import mmap
import os
import re
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(BASE, "resources", "Patch 1.07.00",
                   "eFootball PES 2021", "PES2021.exe")

# 内存操作数：[reg + 0xNN] / [reg] ，排除带索引寄存器的形式（那是批量循环）
RE_SIMPLE = re.compile(r"^\[(r[a-z0-9]+)(?:\s*\+\s*(0x[0-9a-f]+|\d+))?\]$")
RE_INDEXED = re.compile(r"^\[(r[a-z0-9]+)\s*\+\s*(r[a-z0-9]+)")

SIZE_OF = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16}


def op_size(op_str, piece):
    """从 'byte ptr [rbx + 0x10]' 之类的串里取宽度。"""
    for k, v in SIZE_OF.items():
        if piece.startswith(k + " ptr"):
            return v
    # 无显式宽度标注时按寄存器名猜
    if "xmm" in op_str:
        return 16
    return None


def split_ops(op_str):
    """把 'a, b' 拆成两半（内存操作数里没有顶层逗号）。"""
    depth = 0
    for i, ch in enumerate(op_str):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        elif ch == "," and depth == 0:
            return op_str[:i].strip(), op_str[i + 1:].strip()
    return op_str.strip(), None


def mem_ref(piece):
    """返回 (base, disp, size) 或 None；带索引寄存器的返回 ('INDEXED', None, size)。"""
    if "[" not in piece:
        return None
    inner = piece[piece.index("["):]
    size = op_size(piece, piece)
    m = RE_INDEXED.match(inner)
    if m:
        return ("INDEXED", None, size)
    m = RE_SIMPLE.match(inner)
    if not m:
        return None
    base = m.group(1)
    disp = int(m.group(2), 0) if m.group(2) else 0
    return (base, disp, size)


def analyze(mm, start, end, expect=None):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    fields = {}          # disp -> {"size":n, "read":bool, "write":bool, "masks":[...]}
    batches = []         # (起始 disp 提示, 循环次数, 每轮字节数)
    pending_mask = None  # 最近一次 `and reg, imm` 的立即数
    last_disp = None
    loop_count = None
    # 派生基址：`lea rdx,[rbx+0x14]` 之后 [rdx] 其实是结构的 +0x14。
    # 不跟踪的话子对象成员会被全部错记到 +0x00（实测踩过这个坑）。
    alias = {}

    for ins in md.disasm(mm[start:end], start):
        mn, ops = ins.mnemonic, ins.op_str
        a, b = split_ops(ops)

        # 维护派生基址表
        if mn == "lea" and b:
            ref = mem_ref(b if "[" in b else "")
            if ref and ref[0] not in ("INDEXED", "rsp", "rbp") and ref[1] is not None:
                alias[a] = alias.get(ref[0], 0) + ref[1]
            else:
                alias.pop(a, None)
        elif mn in ("mov", "movzx", "movsx", "movsxd", "add", "sub", "xor",
                    "imul", "pop") and a in alias and "[" not in a:
            alias.pop(a, None)     # 该寄存器被改写，派生关系失效

        # 记 `mov ecx, N`：可能是后面 movups 循环的轮数
        if mn == "mov" and b and b.startswith("0x") and a in ("ecx", "rcx"):
            try:
                loop_count = int(b, 0)
            except ValueError:
                loop_count = None

        # 位域惯用法里的 `and reg, imm`
        if mn == "and" and b and b.startswith("0x"):
            try:
                pending_mask = int(b, 0)
            except ValueError:
                pending_mask = None
            if last_disp is not None and pending_mask is not None:
                fields.setdefault(last_disp, {"size": 4, "read": False,
                                              "write": False, "masks": []})
                if pending_mask not in fields[last_disp]["masks"]:
                    fields[last_disp]["masks"].append(pending_mask)
            continue

        if mn not in ("mov", "movzx", "movsx", "movsxd", "movups",
                      "movaps", "movdqu", "xor"):
            continue

        for piece, is_dst in ((a, True), (b, False)):
            if not piece:
                continue
            ref = mem_ref(piece)
            if ref is None:
                continue
            base, disp, size = ref
            if base == "INDEXED":
                # movups xmm,[rdx+rax] 形式 = 批量拷贝循环体。
                # 循环游标一般由 `lea rax,[dst+0x24]` 初始化，派生基址表里就有起点。
                if mn.startswith("mov") and size == 16 and loop_count:
                    m = RE_INDEXED.match(piece[piece.index("["):])
                    origin = None
                    for r in (m.group(1), m.group(2)) if m else ():
                        if r in alias:
                            origin = alias[r]
                            break
                    batches.append((loop_count, origin))
                    loop_count = None
                continue
            if base in ("rsp", "rbp"):
                continue          # 栈帧保存/恢复，不是结构字段
            if disp is None or size is None:
                continue
            disp += alias.get(base, 0)
            f = fields.setdefault(disp, {"size": size, "read": False,
                                         "write": False, "masks": []})
            f["size"] = max(f["size"], size)
            if is_dst:
                f["write"] = True
            else:
                f["read"] = True
            last_disp = disp

    print("=" * 78)
    print("字段图（源自 0x%08X ~ 0x%08X 的拷贝代码）" % (start, end))
    print("-" * 78)
    print("  偏移      宽度  读/写   位域 mask（若为位域成员）")
    copied = [d for d, f in fields.items() if f["read"] and f["write"]]
    for disp in sorted(fields):
        f = fields[disp]
        rw = ("R" if f["read"] else "-") + ("W" if f["write"] else "-")
        masks = ", ".join("0x%08X(%d bit)" % (m, bin(m).count("1"))
                          for m in f["masks"])
        star = " *" if disp in copied else "  "
        print("  +0x%04X   %2dB   %s%s  %s" % (disp, f["size"], rw, star, masks))
    print("-" * 78)
    print("  标 * = 同一偏移既读又写，是确凿的「拷贝字段」（%d 个）" % len(copied))

    for cnt, origin in batches:
        span = cnt * 32
        if origin is not None:
            print("  批量区: +0x%X ~ +0x%X（movups 循环 %d 轮 × 32 B = %d 字节）"
                  % (origin, origin + span, cnt, span))
        else:
            print("  批量区: movups 循环 %d 轮 × 32 B = %d (0x%X) 字节（起点未定）"
                  % (cnt, span, span))
    if batches:
        print("        该段无逐字段语义 = 编译器判定可 SIMD 直搬，多为 POD 数组")

    if fields:
        cover = max(d + fields[d]["size"] for d in fields)
        print("  字段覆盖终点 = +0x%X (%d)" % (cover, cover))
        if expect:
            ok = "吻合 ✓" if cover == expect else "不吻合 ✗"
            print("  对比期望 sizeof = %d (0x%X) —— %s" % (expect, expect, ok))
    elif expect:
        print("  未提取到字段，无法与期望 sizeof %d 对比" % expect)
    print("=" * 78)


def main():
    argv = list(sys.argv[1:])
    expect = None
    if "--expect" in argv:
        i = argv.index("--expect")
        expect = int(argv[i + 1], 0)
        del argv[i:i + 2]
    if not argv:
        print(__doc__)
        return 1
    start = int(argv[0], 0)
    end = int(argv[1], 0) if len(argv) > 1 else start + 0x200
    if not os.path.exists(EXE):
        print("找不到目标 exe：%s" % EXE)
        return 1
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            analyze(mm, start, end, expect)
    return 0


if __name__ == "__main__":
    sys.exit(main())
