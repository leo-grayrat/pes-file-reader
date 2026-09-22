#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_field_desc.py — 转储 PES2021 exe 的「球员字段描述符表」并解析每个字段的位域。

背景（docs/exe-save-layout.md ⑬）：
  0x1407E70 是按字段 ID 查描述符的分派函数，内含两张静态表：
    - 表1: ID 0x00~0x79（122 项）× 0x30 步长，命中后拷 48B 描述符给调用者
    - 表2: ID 0x7A~0x7C（3 项）× 0x28 步长，命中后拷 40B
  描述符里存的是 getter/setter 的 **VA**（不是 flat 文件偏移），必须经 PE 段换算
  才能反汇编（.data1 的 RVA=0x1000 / filePtr=0x600，Δ=0xA00）。

描述符 48B 布局（实测）：
  +0x00 u32  字段 ID（与数组下标严格一致，0..121）
  +0x08 u64  getter VA   —— 从 380B 运行时对象取值
  +0x10 u64  setter VA   —— 写回 380B 运行时对象
  +0x18 u32  最小值（min）—— 能力类恒 40、身高 100、体重 30、年龄 15
  +0x20 u32  最大值（max）—— 能力类恒 99、身高 250、体重 150、年龄 50
  +0x24 u32  位宽（bit width）—— 能力 7、身高/体重 8、布尔 1、熟练度类 2

getter 形态统一为「从 rcx(380B 对象) 取位域」：
  mov eax,[rcx+X]; shr eax,N; and eax,M; mov [rdx],eax; ret
⇒ (对象内偏移 X, 位偏移 N, 位宽 = bitlen(M))，本脚本自动提取。

用法：
  python exe_field_desc.py                      # 输出 outputs/field_descriptors.md
  python exe_field_desc.py --out <path>         # 指定输出
  python exe_field_desc.py --raw                # 附带每项 48B 原始 hex

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

# 表基址（VA），由 0x1407E76 / 0x1407EC9 的 lea rip 换算得到：
#   lea r9,[rip+0x20F2433] @0x1407E76 -> RVA 0x34FACB0 -> off 0x34F9CB0 (.ecode)
#   lea r9,[rip+0x20F3AC0] @0x1407EC9 -> RVA 0x34FC390 -> off 0x34FB390 (.ecode)
# 这里直接存 RVA，运行时按段表换算成文件偏移，避免硬编码 Δ。
T1_RVA = 0x34FACB0
T2_RVA = 0x34FC390
N1, S1 = 122, 0x30
N2, S2 = 3, 0x28

# ---- 25 项能力：ID -> 名字 ----
# 定序依据：描述符表 ID 0x12~0x2A 的顺序 与 EDIT 位流顺序（core/fit_weights.py
# ABIL_ORDER / build_player_browser.py）逐条吻合，且与 docs ⑫⑬ 已实证的「组偏移」
# 100% 对上（low_pass..place_kicking 同在 +0x10、speed..physical_contact 同在 +0x14、
# stamina..gk_awareness 同在 +0x18、gk_reach..heading 同在 +0x1C、balance/gk_reflexes
# 同在 +0x2C、curl/gk_catching/dribbling 同在 +0x24）。
ABILITY_BY_ID = {
    0x12: "offensive_awareness", 0x13: "ball_control", 0x14: "tight_possession",
    0x15: "low_pass", 0x16: "lofted_pass", 0x17: "finishing", 0x18: "place_kicking",
    0x19: "curl", 0x1A: "speed", 0x1B: "acceleration", 0x1C: "jump",
    0x1D: "physical_contact", 0x1E: "balance", 0x1F: "stamina", 0x20: "ball_winning",
    0x21: "aggression", 0x22: "gk_awareness", 0x23: "gk_catching", 0x24: "gk_reach",
    0x25: "defensive_awareness", 0x26: "gk_clearing", 0x27: "heading",
    0x28: "dribbling", 0x29: "gk_reflexes", 0x2A: "kicking_power",
}

# ---- 其他已由 min/max 量纲唯一确定的字段 ----
KNOWN_BY_ID = {
    0x0D: "年龄（15~50，6bit）",
    0x10: "身高 cm（100~250，8bit）",
    0x11: "体重 kg（30~150，8bit）",
}


def _imm(s):
    """capstone 对 <10 的立即数输出十进制，>=10 输出 0x 十六进制。"""
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def load():
    data = open(P.EXE, "rb").read()
    secs = P.load_sections(data)
    t1_off, _ = P.rva_to_off(secs, T1_RVA)
    t2_off, _ = P.rva_to_off(secs, T2_RVA)
    return data, secs, t1_off, t2_off


def va_to_off(secs, p):
    """描述符里的函数指针 VA -> 文件偏移（.data1: RVA 0x1000 / filePtr 0x600）。"""
    if p >= P.IMAGE_BASE:
        return P.rva_to_off(secs, p - P.IMAGE_BASE)
    off, name = P.rva_to_off(secs, p - 0x600 + 0x1000)
    if off is not None:
        return off, name
    return P.rva_to_off(secs, p)


def parse_getter(data, md, off):
    """反汇编 getter，返回 (对象偏移, 位偏移, 掩码, 摘要)。"""
    if off is None:
        return None
    ins = []
    for i in md.disasm(data[off : off + 0x40], off):
        ins.append("%s %s" % (i.mnemonic, i.op_str))
        if len(ins) >= 4 or i.mnemonic == "ret":
            break
    txt = "; ".join(ins)
    m = re.search(r"\[rcx \+ (0x[0-9a-f]+|\d+)\]", txt)
    if not m:  # [rcx]
        m2 = re.match(r"mov\w* eax, \w+ ptr \[rcx\]", txt)
        if not m2:
            return None
        src = 0
    else:
        src = _imm(m.group(1))
    sh = re.search(r"shr\s+eax,\s+(0x[0-9a-f]+|\d+)", txt)
    an = re.search(r"and\s+eax,\s+(0x[0-9a-f]+|\d+)", txt)
    return {
        "obj_off": src,
        "bit": _imm(sh.group(1)) if sh else 0,
        "mask": _imm(an.group(1)) if an else None,
        "dis": txt,
    }


def main():
    argv = sys.argv[1:]
    out = os.path.join(BASE, "outputs", "field_descriptors.md")
    if "--out" in argv:
        out = argv[argv.index("--out") + 1]
    raw = "--raw" in argv

    data, secs, t1_off, t2_off = load()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    rows1 = []
    for i in range(N1):
        b = data[t1_off + i * S1 : t1_off + (i + 1) * S1]
        fid = struct.unpack_from("<I", b, 0x00)[0]
        g = struct.unpack_from("<Q", b, 0x08)[0]
        s = struct.unpack_from("<Q", b, 0x10)[0]
        mn = struct.unpack_from("<I", b, 0x18)[0]
        mx = struct.unpack_from("<I", b, 0x20)[0]
        w = struct.unpack_from("<I", b, 0x24)[0]
        gi = parse_getter(data, md, va_to_off(secs, g)[0])
        rows1.append((fid, mn, mx, w, gi, g, s, b.hex(" ")))

    rows2 = []
    for i in range(N2):
        b = data[t2_off + i * S2 : t2_off + (i + 1) * S2]
        fid = struct.unpack_from("<I", b, 0x00)[0]
        g = struct.unpack_from("<Q", b, 0x08)[0]
        s = struct.unpack_from("<Q", b, 0x10)[0]
        mn = struct.unpack_from("<I", b, 0x18)[0]
        mx = struct.unpack_from("<I", b, 0x20)[0]
        gi = parse_getter(data, md, va_to_off(secs, g)[0])
        rows2.append((fid, mn, mx, gi, g, s))

    L = []
    L.append("# PES2021 球员字段描述符表（exe 实证，380B 运行时对象）")
    L.append("")
    L.append("由 `exe/exe_field_desc.py` 从 exe 静态转储（只读，不执行其代码）。")
    L.append("")
    L.append("- 查表函数 `0x1407E70`：按 `r8d`(字段 ID) 线性查表，命中后拷描述符给 `rdx`")
    L.append("- 表1 = **122 项 × 0x30**（ID `0x00`~`0x79`）；表2 = **3 项 × 0x28**（ID `0x7A`~`0x7C`）")
    L.append("- 描述符 `+0x18/+0x20/+0x24` = **最小值 / 最大值 / 位宽**（非 312B 记录偏移——")
    L.append("  312B 存档侧位打包由序列化器 `0x1F14670` 独立完成，见 §判定）")
    L.append("- getter 统一形态 `mov eax,[rcx+X]; shr N; and M` ⇒ 从 380B 对象取 `(X, N, 位宽)` 位域")
    L.append("")
    L.append("## 表1：122 字段全表")
    L.append("")
    L.append("| ID | min | max | 位宽 | 对象偏移 | 位偏移 | 语义 | getter 反汇编 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for fid, mn, mx, w, gi, g, s, hx in rows1:
        if gi:
            cell = "`+0x%02X` | %d |" % (gi["obj_off"], gi["bit"])
        else:
            cell = "— | — |"
        sem = ABILITY_BY_ID.get(fid) or KNOWN_BY_ID.get(fid) or ""
        if gi and mn == 40 and mx == 99 and w == 7:
            sem = "**%s**" % (ABILITY_BY_ID.get(fid, "?"))
        dis = gi["dis"][:52] if gi else "(非位域 getter)"
        L.append("| `0x%02X` | %d | %d | %d | %s %s | %s"
                 % (fid, mn, mx, w, cell, sem, dis))
    if raw:
        L.append("")
        L.append("### 原始 48B hex")
        L.append("")
        L.append("```")
        for fid, mn, mx, w, gi, g, s, hx in rows1:
            L.append("id=0x%02X get=0x%X set=0x%X  %s" % (fid, g, s, hx))
        L.append("```")

    L.append("")
    L.append("## 25 项能力（判据：min=40 且 max=99 且 位宽=7）")
    L.append("")
    L.append("| # | ID | 对象偏移 | 位偏移 | 能力名 |")
    L.append("|---|---|---|---|---|")
    n = 0
    for fid, mn, mx, w, gi, g, s, hx in rows1:
        if mn == 40 and mx == 99 and w == 7 and gi:
            n += 1
            L.append("| %d | `0x%02X` | `+0x%02X` | %d | **%s** |"
                     % (n, fid, gi["obj_off"], gi["bit"],
                        ABILITY_BY_ID.get(fid, "?")))
    L.append("")
    L.append("（共 %d 项 —— 与 PES 的 25 项能力一一对应）" % n)
    L.append("")
    L.append("> **定序依据**：本表 ID 0x12~0x2A 的顺序与 EDIT 存档位流顺序")
    L.append("> （`core/fit_weights.py` 的 `ABIL_ORDER`）逐条吻合，且与 docs ⑫⑬ 已实证的")
    L.append("> 「组偏移」100% 对上：low_pass..place_kicking 同在 `+0x10`、")
    L.append("> speed..physical_contact 同在 `+0x14`、stamina..gk_awareness 同在 `+0x18`、")
    L.append("> gk_reach..heading 同在 `+0x1C`、balance/gk_reflexes 同在 `+0x2C`、")
    L.append("> curl/gk_catching/dribbling 同在 `+0x24`。")
    L.append("> 另经已知球员语义校验（莱诺 GK 五项高、非 GK 的 gk_* 恒 40，见 docs ⑪）。")

    L.append("")
    L.append("## 2bit 字段组（疑似 13 位置熟练度，待验证）")
    L.append("")
    L.append("判据 `位宽=2 且 max=2`：与熟练度取值 `0=C/1=B/2=A` 吻合。")
    L.append("社区已知 13 个可踢位置（`core/build_player_browser.py` 的 `PLAYABLE_ORDER`）：")
    L.append("GK, CB, LB, RB, DMF, CMF, LM, RM, AMF, RWF, SS, CF, LWF。")
    L.append("")
    L.append("| # | ID | 对象偏移 | 位偏移 |")
    L.append("|---|---|---|---|")
    k = 0
    for fid, mn, mx, w, gi, g, s, hx in rows1:
        if w == 2 and mx == 2 and gi:
            k += 1
            L.append("| %d | `0x%02X` | `+0x%02X` | %d |" % (k, fid, gi["obj_off"], gi["bit"]))
    L.append("")
    L.append("（共 %d 项，多于 13 —— 哪 13 个对应熟练度需用已知球员的 13 位串反查，" % k)
    L.append("本表只给出候选范围。`+0x28` 的 bit7/9/11/…/29 是 12 个连续 2bit 槽，" )
    L.append("形态上最像一组数组式字段。）")
    L.append("")
    L.append("## 表2：ID 0x7A~0x7C（0x28 步长，非位域直拷）")
    L.append("")
    L.append("| ID | min | max | getter | setter |")
    L.append("|---|---|---|---|---|")
    for fid, mn, mx, gi, g, s in rows2:
        L.append("| `0x%02X` | %d | %d | `0x%X` %s | `0x%X` |"
                 % (fid, mn, mx, g, (gi["dis"][:50] if gi else ""), s))

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    print("written: %s (%d 字段)" % (out, N1 + N2))


if __name__ == "__main__":
    sys.exit(main())
