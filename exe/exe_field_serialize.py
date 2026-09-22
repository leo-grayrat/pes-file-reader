#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_field_serialize.py — 枚举 380B→312B 序列化器 0x1F14670 的 switch 全部 case，
提取「字段 ID → 312B 存档记录内位位置」映射，再与字段描述符表合并。

前置（docs ⑫）：
  0x1F14670 = 380B 运行时球员对象 → 312B 存档记录的序列化器，按 r9d(字段 ID) 分派。
  本脚本解析它的 MSVC switch 双表：
    lea r8,[rip-0x1f150ac]                      ; r8 归零
    movzx eax, byte [r8 + rbx + 0x1f15444]      ; 二级索引表：ID -> case 号
    mov   ecx, dword [r8 + rax*4 + 0x1f15410]   ; 跳转表：case 号 -> 代码 RVA
    jmp   rcx
  两张表的 RVA 换算成文件偏移（.data1: RVA = off + 0xA00）得：
    索引表 off = 0x1F14A44（125 项 byte）
    跳转表 off = 0x1F14A10（N 项 dword，值为绝对 RVA 低 32 位）

case 写记录的两种形态：
  A 直接位域写：and dword [rdi+X], ~MASK; shl eax,N; or [rdi+X], eax
                ⇒ 记录字节偏移 X、位偏移 N、位宽 = popcount(MASK)
  B 打包写：    mov r8d, BIT; call 0xc2d180(rcx=记录, rdx=值, r8d=位偏移)
                ⇒ 记录内位偏移 BIT
  C 直拷：      mov [rdi+Y], eax/ax/al  ⇒ 记录字节偏移 Y（整字段，非位域）

用法：
  python exe_field_serialize.py                 # 输出 outputs/serialize_cases.md
  python exe_field_serialize.py --verbose       # 附带每个 case 的反汇编

只读：mmap 读取 exe，绝不执行其代码。
"""
import os
import re
import struct
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "exe"))
import exe_pe_const as P  # noqa: E402

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402

SER_RVA_IDX = 0x1F15444   # 二级索引表 RVA（125 x u8）
SER_RVA_JMP = 0x1F15410   # 跳转表 RVA（N x u32，值 = 目标 RVA）
MAX_ID = 0x7C             # cmp ebx, 0x7c

# 与 exe_field_desc.py 保持一致
ABILITY_BY_ID = {
    0x12: "offensive_awareness", 0x13: "ball_control", 0x14: "tight_possession",
    0x15: "low_pass", 0x16: "lofted_pass", 0x17: "finishing", 0x18: "place_kicking",
    0x19: "curl", 0x1A: "speed", 0x1B: "acceleration", 0x1C: "jump",
    0x1D: "physical_contact", 0x1E: "balance", 0x1F: "stamina", 0x20: "ball_winning",
    0x21: "aggression", 0x22: "gk_awareness", 0x23: "gk_catching", 0x24: "gk_reach",
    0x25: "defensive_awareness", 0x26: "gk_clearing", 0x27: "heading",
    0x28: "dribbling", 0x29: "gk_reflexes", 0x2A: "kicking_power",
}
KNOWN_BY_ID = {
    0x0D: "年龄", 0x10: "身高 cm", 0x11: "体重 kg",
}


def _imm(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def main():
    verbose = "--verbose" in sys.argv
    out = os.path.join(BASE, "outputs", "serialize_cases.md")

    data = open(P.EXE, "rb").read()
    secs = P.load_sections(data)
    idx_off, _ = P.rva_to_off(secs, SER_RVA_IDX)
    jmp_off, _ = P.rva_to_off(secs, SER_RVA_JMP)

    idx_tbl = [data[idx_off + i] for i in range(MAX_ID + 1)]
    ncase = max(idx_tbl) + 1
    jmp_tbl = [struct.unpack_from("<I", data, jmp_off + 4 * i)[0] for i in range(ncase)]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def case_off(cid):
        rva = jmp_tbl[cid]
        off, _ = P.rva_to_off(secs, rva)
        return off

    def analyze(off):
        """反汇编到 ret，提取写记录的模式。返回 (模式, 详情, 反汇编文本)。"""
        ins = []
        for i in md.disasm(data[off : off + 0x120], off):
            ins.append("%s %s" % (i.mnemonic, i.op_str))
            if i.mnemonic == "ret" or len(ins) > 60:
                break
        txt = "; ".join(ins)
        # C 直拷
        m = re.search(r"mov (dword|word|byte) ptr \[rdi \+ (0x[0-9a-f]+|\d+)\]", txt)
        if m and "call" not in txt.split(";")[0]:
            # 确认不是位域写（没有 and/or 同址）
            if not re.search(r"and (dword|word|byte) ptr \[rdi", txt):
                return "C", "rec+0x%02X 直拷" % _imm(m.group(2)), txt
        # A 直接位域写
        a = re.search(r"and (?:dword )?ptr \[rdi \+ (0x[0-9a-f]+|\d+)\], (0x[0-9a-f]+)", txt)
        if a:
            X = _imm(a.group(1))
            sh = re.search(r"shl eax, (0x[0-9a-f]+|\d+)", txt)
            N = _imm(sh.group(1)) if sh else 0
            msk = re.search(r"and eax, (0x[0-9a-f]+|\d+)", txt)
            w = _imm(msk.group(1)).bit_length() if msk else "?"
            return "A", "rec+0x%02X bit%d w=%s" % (X, N, w), txt
        # B 打包写
        b = re.search(r"mov r8d, (0x[0-9a-f]+|\d+)", txt)
        if b and "0xc2d180" in txt:
            return "B", "位偏移 %d（经 0xc2d180 打包）" % _imm(b.group(1)), txt
        if "0xc2d180" in txt:
            return "B", "位偏移 ?（未取到 r8d 立即数）", txt
        return "?", "", txt

    L = []
    L.append("# 380B → 312B 序列化器 case 全表（`0x1F14670`）")
    L.append("")
    L.append("由 `exe/exe_field_serialize.py` 从 exe 静态枚举（只读，不执行其代码）。")
    L.append("")
    L.append("- 分派：`cmp ebx,0x7c` ⇒ 字段 ID `0x00`~`0x7C`，共 %d 项" % (MAX_ID + 1))
    L.append("- 索引表 `RVA 0x%X`（off `0x%X`，125×u8）；跳转表 `RVA 0x%X`（off `0x%X`，%d×u32）"
             % (SER_RVA_IDX, idx_off, SER_RVA_JMP, jmp_off, ncase))
    L.append("- 唯一 case 分支数：**%d**" % ncase)
    L.append("- 记录指针 `rdi`（312B 目标），源对象 `rsi`（380B）")
    L.append("")
    L.append("## 字段 ID → 312B 记录内位置")
    L.append("")
    L.append("| ID | case | 模式 | 记录内位置 | 语义（来自描述符表） |")
    L.append("|---|---|---|---|---|")
    seen = {}
    for fid in range(MAX_ID + 1):
        cid = idx_tbl[fid]
        if cid not in seen:
            off = case_off(cid)
            seen[cid] = analyze(off) if off else ("?", "(越界)", "")
        mode, detail, txt = seen[cid]
        sem = ABILITY_BY_ID.get(fid) or KNOWN_BY_ID.get(fid) or ""
        if fid in ABILITY_BY_ID:
            sem = "**%s**" % ABILITY_BY_ID[fid]
        L.append("| `0x%02X` | %d | %s | %s | %s |" % (fid, cid, mode, detail, sem))

    if verbose:
        L.append("")
        L.append("## 各 case 反汇编")
        L.append("")
        L.append("```")
        for cid in sorted(seen):
            mode, detail, txt = seen[cid]
            L.append("case %d [%s] %s" % (cid, mode, detail))
            L.append("  " + txt[:200])
        L.append("```")

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("written: %s (case=%d)" % (out, ncase))


if __name__ == "__main__":
    sys.exit(main())
