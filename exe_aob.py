#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_aob.py —— 用社区 Cheat Table 的 AOB 签名在 FL_2023.exe 中定位代码（只读静态）。

原理：Cheat Table 里的 aobscanmodule 签名被作者保证「在目标 exe 中唯一」。
我们手上的 FL_2023.exe（SP Football Life 2023）与 PES2021.exe 代码布局一致
（社区实测 PES2021 / FL2023 / FL2026 三版注入点均为 +EA4C58），故这些签名可
直接在本地 exe 上精确定位，把 CT 表中的「内存偏移」锚定到具体代码位置。

本脚本只以只读方式 mmap 目标二进制，绝不执行其代码，绝不写入或修改目标文件。

签名来源：
  - resources/CT/PES 2021 - v21.1.0 英文版/PES 2021 - v21.1.0.CT
  - resources/CT/PES 2021 - v21.1.0 汉化版/PES2021--汉化.CT
  - resources/CT/SP Football Life 2026 - v21.1.0 - CN.CT
  - github.com/xAranaktu/PES-2021-Cheat-Table（SP Football Life 2023 - v21.1.0.CT）

用法：
  python exe_aob.py            # 扫描全部已知签名，报告命中与预期 RVA 是否吻合
  python exe_aob.py ctx        # 额外输出命中点上下文 hex 转储
  python exe_aob.py imm        # 额外扫描资金偏移常量本身（作为立即数）的出现位置
"""
import os
import sys

import exe_probe

BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EXE = os.path.join(BASE, "game", "FL_2023.exe")

# ---- AOB 签名表（byte 串以空格分隔，便于与 CT 表原文对照）----
# expect_rva：CT 表作者实测的注入点 RVA（PES2021/FL2023/FL2026 三版一致）
AOB_SIGNATURES = [
    {
        "name": "INJECT_ClubBudget",
        "pattern": "8B 87 F4 CB 6E 01 89 45 C4",
        "expect_rva": 0xEA4C58,
        "semantics": "mov eax,[rdi+016ECBF4] ; mov [rbp-3C],eax",
        "meaning": "转会预算读取点（预算结构基址 = rdi）",
        "derived": [
            ("转会预算", "ptrBudget + 0x16ECBF4", "4 字节无符号"),
            ("薪资预算", "ptrBudget + 0x16ECC08", "4 字节无符号"),
        ],
    },
    {
        "name": "INJECT_ptrPlayer",
        "pattern": "CB B8 02 00 00 00 0F 1F 40 00 66 0F 1F 84 00 00 00 00 00 0F 10 02 0F 11 01",
        "expect_rva": 0xC650F0,
        "semantics": "... movups xmm0,[rdx] ; movups [rcx],xmm0",
        "meaning": "球员对象指针捕获（ptrPlayer = rdx）",
        "derived": [
            ("球员年薪", "ptrPlayer + 0x15C", "4 字节有符号"),
            ("球员身价", "ptrPlayer + 0x174", "4 字节有符号"),
        ],
    },
    {
        "name": "INJECT_ptrPlayerTwo",
        "pattern": "48 8B 40 2C 48 89 02",
        "expect_rva": 0x730FFA7,
        "semantics": "mov rax,[rax+2C] ; mov [rdx],rax",
        "meaning": "球员对象指针捕获（第二处，ptrPlayer = rax）",
        "derived": [],
    },
    {
        "name": "INJECT_TrainingOnEnter",
        "pattern": "49 8B 86 90 00 00 00 0F BE",
        "expect_rva": 0xC0FC5B1,
        "semantics": "mov rax,[r14+00000090] ; movsx ...",
        "meaning": "BAL 训练进入（BAL 模式相关）",
        "derived": [],
    },
    {
        "name": "INJECT_TrainingOnChange",
        "pattern": "0F BE 41 0A 2B C2",
        "expect_rva": 0xBB35C1,
        "semantics": "movsx eax,byte ptr [rcx+0A] ; sub eax,edx",
        "meaning": "BAL 训练项变更",
        "derived": [],
    },
    {
        "name": "INJECT_MatchTime",
        "pattern": "8B 44 24 40 89 44 24 40",
        "expect_rva": 0x7ABD593,
        "semantics": "mov eax,[rsp+40] ; mov [rsp+40],eax",
        "meaning": "比赛时间（Gameplay 分组）",
        "derived": [],
    },
]

# ---- 由 CT 表导出的关键内存偏移常量（检查其作为立即数在 exe 中的出现）----
IMM_CONSTANTS = [
    (0x16ECBF4, "<I", "转会预算偏移 ptrBudget+0x16ECBF4"),
    (0x16ECC08, "<I", "薪资预算偏移 ptrBudget+0x16ECC08"),
    (0x15C, "<I", "球员年薪偏移 ptrPlayer+0x15C"),
    (0x174, "<I", "球员身价偏移 ptrPlayer+0x174"),
]


def parse_pattern(text):
    return bytes(int(t, 16) for t in text.split())


def scan_signatures(mm, sections, show_ctx):
    print("=" * 74)
    print("[AOB 签名扫描] 目标：%s" % os.path.basename(DEFAULT_EXE))
    ok_count = 0
    for sig in AOB_SIGNATURES:
        pat = parse_pattern(sig["pattern"])
        hits, overflow = exe_probe.find_all(mm, pat, cap=64)
        n = len(hits)
        tag = "（>cap）" if overflow else ""
        print("\n  ── %s  签名 %d 字节" % (sig["name"], len(pat)))
        print("     语义: %s" % sig["semantics"])
        print("     含义: %s" % sig["meaning"])
        print("     命中 %d 处%s（CT 表预期唯一、RVA=0x%X）" % (n, tag, sig["expect_rva"]))
        matched = False
        for off in hits[:8]:
            rva = exe_probe.off2rva(sections, off)
            hit_rva = (rva is not None and rva == sig["expect_rva"])
            if hit_rva:
                matched = True
            flag = "  ★与预期 RVA 一致" if hit_rva else ""
            rva_s = ("RVA 0x%08X" % rva) if rva is not None else "RVA 未映射"
            print("       文件偏移 0x%08X  %s%s" % (off, rva_s, flag))
        if matched:
            ok_count += 1
            print("     结论：✅ 本地 exe 命中，与社区实测地址一致")
        elif n == 0:
            print("     结论：❌ 未命中——该签名针对 PES2021.exe，FL_2023.exe 可能有差异")
        else:
            print("     结论：⚠️ 有命中但均与预期 RVA 不符（%d 处）" % n)
        for label, expr, vtype in sig["derived"]:
            print("       └ 派生: %-6s %-28s %s" % (label, expr, vtype))
        if show_ctx and hits:
            print("     -- 首个命中点上下文 --")
            print(exe_probe.hexdump(mm, hits[0], radius=24))
    print("\n" + "-" * 74)
    print("  汇总：%d/%d 个签名与社区实测地址一致" % (ok_count, len(AOB_SIGNATURES)))
    return ok_count


def scan_immediates(mm, sections):
    print("=" * 74)
    print("[关键偏移常量扫描] 检查 CT 表导出的偏移是否以立即数形式出现在代码中")
    for value, fmt, desc in IMM_CONSTANTS:
        pat = __import__("struct").pack(fmt, value)
        hits, overflow = exe_probe.find_all(mm, pat, cap=4096)
        tag = "（>cap，属噪声常量）" if overflow else ""
        print("  0x%X (%d) [%s]：命中 %d 处%s" % (value, value, desc, len(hits), tag))
        for off in hits[:6]:
            rva = exe_probe.off2rva(sections, off)
            rva_s = ("RVA 0x%08X" % rva) if rva is not None else "RVA 未映射"
            print("     文件偏移 0x%08X  %s" % (off, rva_s))


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    mode = sys.argv[1] if len(sys.argv) > 1 else "scan"
    exe = DEFAULT_EXE
    if not os.path.isfile(exe):
        print("错误：目标文件不存在：%s" % exe)
        return 1
    f, mm, size = exe_probe.open_target(exe)
    try:
        print("目标文件: %s（%d 字节，只读 mmap，绝不执行）" % (exe, size))
        info = exe_probe.parse_pe(mm)
        sections = info.get("sections", [])
        if mode in ("scan", "ctx"):
            scan_signatures(mm, sections, show_ctx=(mode == "ctx"))
        elif mode == "imm":
            scan_immediates(mm, sections)
        else:
            print("未知子命令：%s（可选 scan / ctx / imm）" % mode)
            return 1
    finally:
        mm.close()
        f.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
