#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_field_setter.py — 批量反汇编字段描述符表里的 setter，提取「写入目标」的位域。

前置（本轮新解，见 docs）：
  0xc2d180(rec, field_id, value) 的完整语义已反汇编确认：
    1. call 0x1407e70           查描述符（rdx=48B 输出缓冲）
    2. r8 = desc+0x10           setter 指针
    3. 用 desc+0x18(min) / desc+0x20(max) 校验 value
    4. call r8                  setter(rcx=记录, rdx=&value)
  ⇒ 传入的 rcx 是**312B 存档记录**（序列化器 0x1F14670 里 rdi=记录），
    故 setter 内的内存偏移即 312B 记录内的位置。

setter 典型形态：
  mov ecx,[rdx]                      ; 取 value
  mov eax,[rcx+X] / movzx eax,...    ; 读目标
  and eax, ~MASK ; shl ecx,N ; or    ; 位域合成
  mov [rcx+X], eax                   ; 写回
⇒ 提取 (记录偏移 X, 位偏移 N, 位宽)

用法：
  python exe_field_setter.py                  # 输出 outputs/setter_layout.md
  python exe_field_setter.py --verbose        # 附带 setter 反汇编

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

T1_RVA = 0x34FACB0
N1, S1 = 122, 0x30

ABILITY_BY_ID = {
    0x12: "offensive_awareness", 0x13: "ball_control", 0x14: "tight_possession",
    0x15: "low_pass", 0x16: "lofted_pass", 0x17: "finishing", 0x18: "place_kicking",
    0x19: "curl", 0x1A: "speed", 0x1B: "acceleration", 0x1C: "jump",
    0x1D: "physical_contact", 0x1E: "balance", 0x1F: "stamina", 0x20: "ball_winning",
    0x21: "aggression", 0x22: "gk_awareness", 0x23: "gk_catching", 0x24: "gk_reach",
    0x25: "defensive_awareness", 0x26: "gk_clearing", 0x27: "heading",
    0x28: "dribbling", 0x29: "gk_reflexes", 0x2A: "kicking_power",
}
KNOWN_BY_ID = {0x0D: "年龄", 0x10: "身高 cm", 0x11: "体重 kg"}


def _imm(s):
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def main():
    verbose = "--verbose" in sys.argv
    out = os.path.join(BASE, "outputs", "setter_layout.md")

    data = open(P.EXE, "rb").read()
    secs = P.load_sections(data)
    t1_off, _ = P.rva_to_off(secs, T1_RVA)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def setter_off(va):
        if va >= P.IMAGE_BASE:
            return P.rva_to_off(secs, va - P.IMAGE_BASE)[0]
        o, _ = P.rva_to_off(secs, va - 0x600 + 0x1000)
        return o if o is not None else P.rva_to_off(secs, va)[0]

    def analyze(off):
        ins = []
        for i in md.disasm(data[off : off + 0x100], off):
            ins.append("%s %s" % (i.mnemonic, i.op_str))
            if i.mnemonic == "ret" or len(ins) > 40:
                break
        txt = "; ".join(ins)
        # 形态1（主要）：xor 三连位域写
        #   mov eax,[rdx]; shl eax,N; xor eax,[rcx+X]; and eax,MASK; xor [rcx+X],eax
        m1 = re.search(
            r"(?:shl eax, (0x[0-9a-f]+|\d+); )?xor eax, dword ptr \[rcx \+ (0x[0-9a-f]+|\d+)\];"
            r" and eax, (0x[0-9a-f]+)", txt)
        if m1:
            # 位偏移 0 时编译器省略 shl
            N = _imm(m1.group(1)) if m1.group(1) else 0
            X = _imm(m1.group(2))
            mask = _imm(m1.group(3))
            return X, N, bin(mask).count("1"), txt
        # 形态2（少数）：and/or 位域写
        w = re.findall(r"mov (?:dword |word |byte )?ptr \[rcx \+ (0x[0-9a-f]+|\d+)\]", txt)
        if not w:
            w = re.findall(r"mov (?:dword |word |byte )?ptr \[rcx\]", txt)
            X = 0 if w else None
        else:
            X = _imm(w[-1])
        if X is None:
            return None, None, None, txt
        sh = re.search(r"shl e[cx]x, (0x[0-9a-f]+|\d+)", txt)
        N = _imm(sh.group(1)) if sh else 0
        msk = re.search(r"and e[ac]x, (0x[0-9a-f]+|\d+)", txt)
        wdt = _imm(msk.group(1)).bit_length() if msk else None
        return X, N, wdt, txt

    rows = []
    for i in range(N1):
        b = data[t1_off + i * S1 : t1_off + (i + 1) * S1]
        fid = struct.unpack_from("<I", b, 0x00)[0]
        sv = struct.unpack_from("<Q", b, 0x10)[0]
        so = setter_off(sv)
        X, N, wdt, txt = analyze(so) if so else (None, None, None, "")
        rows.append((fid, sv, X, N, wdt, txt))

    L = []
    L.append("# 312B 存档记录位布局（由字段 setter 反汇编提取）")
    L.append("")
    L.append("由 `exe/exe_field_setter.py` 从 exe 静态提取（只读，不执行其代码）。")
    L.append("")
    L.append("**链路**：序列化器 `0x1F14670` case → `0xc2d180(记录, 字段ID, 值)`")
    L.append("→ 查描述符表 `0x1407E70` → 调 `desc.setter(记录, &值)`。")
    L.append("传入 setter 的 `rcx` 是 312B 存档记录，故 setter 内的内存偏移 = 记录内位置。")
    L.append("")
    L.append("| ID | setter VA | 记录偏移 | 位偏移 | 位宽 | 语义 |")
    L.append("|---|---|---|---|---|---|")
    for fid, sv, X, N, wdt, txt in rows:
        sem = ABILITY_BY_ID.get(fid) or KNOWN_BY_ID.get(fid) or ""
        if fid in ABILITY_BY_ID:
            sem = "**%s**" % ABILITY_BY_ID[fid]
        if X is None:
            L.append("| `0x%02X` | `0x%X` | — | — | — | %s |" % (fid, sv, sem))
        else:
            L.append("| `0x%02X` | `0x%X` | `+0x%02X` | %d | %s | %s |"
                     % (fid, sv, X, N, wdt if wdt else "?", sem))

    if verbose:
        L.append("")
        L.append("## setter 反汇编")
        L.append("")
        L.append("```")
        for fid, sv, X, N, wdt, txt in rows:
            L.append("ID 0x%02X setter=0x%X  rec+0x%02X bit%s w=%s"
                     % (fid, sv, X if X else 0, N, wdt))
            L.append("  " + txt[:180])
        L.append("```")

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("written: %s" % out)


if __name__ == "__main__":
    sys.exit(main())
