#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
immed_scan.py —— 在 FL_2023.exe 的 .text 段搜索已知 data 偏移的 32 位立即数引用。
目标：事件表偏移 0x12A72FD、注册表锚点 0xde034、+0x598 预算偏移 0x598。
命中后 dump 附近原始字节（供反汇编/人工研判）。
纯静态分析，不运行游戏、不解包 CPK。
"""
import os, struct, sys
import exe_probe

EXE = "game/FL_2023.exe"
TARGETS = [
    ("event_table_0x12A72FD", 0x12A72FD),
    ("reg_anchor_0x0DE034",   0x0DE034),
    ("budget_off_0x598",      0x598),
    ("edit_base_0x7C",        0x7C),
]

def find_imm32(mm, sec, value):
    """在代码段内找 value 的 32 位小端立即数（允许前导 0x00/0xFF 扩展等宽）。"""
    pat = struct.pack("<I", value)
    hits = []
    base, n = sec["raddr"], sec["rsize"]
    # 紧凑匹配
    start = 0
    while True:
        i = mm.find(pat, base + start, base + n)
        if i < 0:
            break
        hits.append(i)
        start = i - base + 1
    return hits

def main():
    f, mm, size = exe_probe.open_target(EXE)
    info = exe_probe.parse_pe(mm)
    text_sec = None
    for s in info["sections"]:
        if "text" in s["name"].lower() or "trace" in s["name"].lower():
            if text_sec is None or s["vsize"] > text_sec["vsize"]:
                text_sec = s
    if text_sec is None:
        print("未找到代码段"); return
    print("代码段: %s vaddr=0x%08X raddr=0x%08X rsize=0x%08X" %
          (text_sec["name"], text_sec["vaddr"], text_sec["raddr"], text_sec["rsize"]))
    for name, val in TARGETS:
        hits = find_imm32(mm, text_sec, val)
        print("\n[%s] 0x%08X -> %d 处命中" % (name, val, len(hits)))
        for h in hits[:12]:
            rva = exe_probe.off2rva(info["sections"], h)
            ctx = mm[h-8:h+16]
            print("  off=0x%08X rva=0x%08X  ctx=%s" % (h, rva, ctx.hex(" ")))

if __name__ == "__main__":
    main()
