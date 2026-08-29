#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_xref.py —— 对 FL_2023.exe 做字符串→代码引用反查（定位 ML 资金字段的读写例程）。

思路：ML 资金相关类路径字符串（MLBudgetSetting/MLSeasonSalary/MLAccounting* 等）在 .rdata，
结构：找 .text 段里 rip-relative 引用这些字符串 RVA 的指令，反汇编其上下文，
顺藤追到存档写出例程，最终定位资金字段的存档偏移。

用法：
  python exe_xref.py            # 段表 + 目标字符串定位 + xref 扫描（默认）
  python exe_xref.py disasm     # 对命中的 xref 附近做 objdump 反汇编
"""
import os
import struct
import subprocess
import exe_probe

EXE = "game/FL_2023.exe"
TARGETS = [
    "ML/MLBudgetSetting", "ML/MLBudgetReport", "ML/MLSeasonSalary",
    "ML/Accounting/MLAccountingTransferFeeDetail",
    "ML/Accounting/MLAccountingSalaryDetail",
    "Common/CmnFinanceReport", "Common/CmnTransferMarket",
]


def find_xrefs(mm, sections, text_sec, target_rva):
    """扫代码段找 rip-relative 引用 target_rva 的位置（返回文件偏移列表）。

    利用代码段内 off↔rva 线性关系加速，规避逐字节 rva2off 的 O(节数) 开销。
    """
    vaddr = text_sec["vaddr"]
    raddr = text_sec["raddr"]
    base = raddr
    n = text_sec["rsize"] - 4
    xrefs = []
    data = mm
    try:
        import numpy as np
        buf = data[base:base + n]
        arr = np.frombuffer(buf, dtype="<i4")
        idx = np.arange(len(arr), dtype=np.int64)
        pos = base + idx * 4
        need = (target_rva - (vaddr + (pos + 4 - raddr))).astype(np.int32)
        hits = np.nonzero(arr == need)[0]
        return [int(base + int(i) * 4) for i in hits]
    except ImportError:
        pass
    for pos in range(base, base + n):
        disp = struct.unpack_from("<i", data, pos)[0]
        endrva = vaddr + (pos + 4 - raddr)
        if endrva + disp == target_rva:
            xrefs.append(pos)
    return xrefs


def main():
    f, mm, size = exe_probe.open_target(EXE)
    info = exe_probe.parse_pe(mm)
    sections = info["sections"]
    print("image_base = 0x%X, size = %d MB" % (info.get("image_base", 0), size >> 20))
    print("=== sections ===")
    text_sec = None
    for s in sections:
        mark = ""
        if "text" in s["name"].lower() or "trace" in s["name"].lower():
            if text_sec is None or s["vsize"] > text_sec["vsize"]:
                text_sec = s
        if "text" in s["name"].lower() or "trace" in s["name"].lower():
            mark = "  <- code"
        print("  %-8s vaddr=0x%08X vsize=0x%08X raddr=0x%08X rsize=0x%08X%s"
              % (s["name"], s["vaddr"], s["vsize"], s["raddr"], s["rsize"], mark))

    print("\n=== 目标字符串定位 ===")
    located = []
    for t in TARGETS:
        off = mm.find(t.encode())
        if off < 0:
            print("  %-42s 未命中" % t)
            continue
        rva = exe_probe.off2rva(sections, off)
        located.append((t, off, rva))
        print("  %-42s off=0x%08X rva=0x%08X" % (t, off, rva))

    if text_sec is None or "--no-xref" in os.sys.argv:
        return

    print("\n=== xref 扫描（.text 段 rip-relative 引用）===")
    for t, off, rva in located:
        xrefs = find_xrefs(mm, sections, text_sec, rva)
        print("\n  [%s] rva=0x%08X -> %d 处引用" % (t, rva, len(xrefs)))
        for x in xrefs[:8]:
            xrva = exe_probe.off2rva(sections, x)
            print("      xref off=0x%08X rva=0x%08X" % (x, xrva))


if __name__ == "__main__":
    main()