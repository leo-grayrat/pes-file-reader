#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_trace_section_digests.py — 追「4 段摘要写进 encHeader[0:256]」的落盘点。

假设(承接 exe_trace_buildsave.py 的发现):
- build_save 内层(0x1412840~0x1412C1A)只有 1 次 SHA-512(0x140E160@0x1412B21, 派生 rolling_key),
  不逐段算摘要 ⇒ 4 段摘要由更外层编排例程算好塞进 encHeader。
- 真正算 SHA-512 压缩的是喂入器 0x1413950, 全 exe 仅 3 调用者 0x14107AE/0x14109EE/0x14118FE
  (浑元4 称其末尾做 std::string 拼装, 但摘要落盘可能在 call 0x1413950 之后、字符串转换之前)。
- build_save 内层把 64B 摘要写出去用的是 0x140FDF0(WRITE64, 0x1412B35)。若逐段例程也调 0x140FDF0
  且目标 = encHeader 摘要槽, 即坐实"逐段例程把 SHA-512 写进 encHeader[0:256]"。

做法(纯静态, 只读 mmap):
1. 全 exe 扫 E8, 列出 0x140FDF0(WRITE64) 的全部调用者。
2. 对 3 个喂入器调用者, 各找 prologue 入口, 反汇编入口~+0x500, 高亮
   call 0x1413950 / call 0x140FDF0 / movaps×4(64B 搬运) / rep movs / 任何 64B 写到缓冲。
"""
import mmap
import os
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = r"D:/File/Git/pes-file-reader/resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe"

FEEDER = 0x1413950          # SHA-512 喂入器 (压缩)
WRITE64 = 0x140FDF0         # 64B 写出 (build_save 内层用它写摘要/密钥)
FEEDER_CALLERS = [0x14107AE, 0x14109EE, 0x14118FE]


def find_callers(mm, tgt):
    out = []
    pos = 0
    while True:
        i = mm.find(b"\xE8", pos)
        if i < 0 or i + 5 > len(mm):
            break
        rel = struct.unpack_from("<i", mm, i + 1)[0]
        t = i + 5 + rel
        if t == tgt:
            out.append(i)
        pos = i + 1
    return out


def find_prologue(mm, off, back=0x2000):
    lo = max(0, off - back)
    seg = mm[lo:off]
    cands = []
    for sig in (b"\xf3\x0f\x1e\xfa", b"\x55\x48\x89\xe5", b"\x40\x55"):
        idx = seg.find(sig)
        while idx != -1:
            cands.append(lo + idx)
            idx = seg.find(sig, idx + 1)
    return max(cands) if cands else off - 0x200


def main():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    size = os.path.getsize(EXE)
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            wc = find_callers(mm, WRITE64)
            print("== 1) 0x140FDF0(WRITE64) 调用者 ==")
            print("  %s" % (["0x%08X" % c for c in wc] or "无"))
            print()

            hl = {FEEDER: "FEED_SHA512", WRITE64: "WRITE64",
                  0x1413DF0: "SHA_COMPRESS", 0x140E160: "SHA_ONESHOT"}
            for cf in FEEDER_CALLERS:
                # 以调用点为中心取宽窗口, 不依赖 prologue 探测(避免命中小 helper)
                start = cf - 0x80
                end = cf + 0x600
                print("== 2) 喂入器调用者 0x%08X (窗口 0x%08X~0x%08X) =="
                      % (cf, start, end))
                print("-" * 70)
                n = 0
                near_feed = False
                for ins in md.disasm(mm[start:end], start):
                    a = ins.address
                    raw = mm[a:a + ins.size].hex()
                    tag = ""
                    if ins.mnemonic == "call" and ins.op_str.startswith("0x"):
                        t = int(ins.op_str, 16)
                        if t in hl:
                            tag = "  <<< %s" % hl[t]
                            if t == FEEDER:
                                near_feed = True
                        elif not ins.op_str.startswith("0x1"):
                            tag += "  (导入调用?)"
                    if ins.mnemonic == "movaps" and "xmmword ptr" in ins.op_str:
                        tag += "  (64B 搬运?)"
                    if ins.mnemonic == "rep" or ins.mnemonic.startswith("movs"):
                        tag += "  (块拷贝?)"
                    if a == cf:
                        tag += "  <<< 本调用点"
                    print("  0x%08X: %-22s %-8s %s%s"
                          % (a, raw, ins.mnemonic, ins.op_str, tag))
                    n += 1
                print("  （%d 条）" % n)
                print()


if __name__ == "__main__":
    sys.exit(main())
