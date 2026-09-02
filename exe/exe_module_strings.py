#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_module_strings.py — 给定一段代码区间，扫出它 rip-relative 引用的全部字符串常量，
                        用「模块自己引用了哪些字符串」来判定模块身份。

为什么需要它：
  受保护 exe 的导入名被剥离、常量池被混淆，但**代码区的 rip-relative 数据引用仍然有效**
  （lea reg,[rip+disp32] 的位移是明文）。于是可以反过来：不去猜某个函数在干什么，
  而是把整个模块引用的字符串全捞出来，让模块自报身份。

  本脚本用于回答 docs/exe-save-layout.md §7 末尾的问题：0x140D000~0x1432000 这一片
  到底是「存档数据反序列化模块」还是别的东西。

地址口径：flat image（文件偏移即地址）。rip-relative 目标 = 指令末偏移 + disp32，
在 flat 模型下同样自洽（同一 image 内的相对位移不受 base 影响）。

只读：仅 mmap 读取，绝不执行/加载目标代码，绝不写入目标文件。

用法：
  python exe_module_strings.py                          # 默认扫存档 I/O 模块区间
  python exe_module_strings.py 0x140D000 0x1432000
  python exe_module_strings.py 0x140D000 0x1432000 --min 6
"""
import mmap
import os
import re
import struct
import sys
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(BASE, "resources", "Patch 1.07.00",
                   "eFootball PES 2021", "PES2021.exe")

# 存档 I/O 模块的经验区间：由 0x1413A20/0x1413B60（该模块专用的 wstring/string
# 模板实例）的 xref 跨度界定，见 exe_caller_dist.py
DEFAULT_RANGE = (0x140D000, 0x1432000)

ASCII_OK = re.compile(rb"[\x20-\x7e]")


def iter_rip_refs(mm, lo, hi):
    """扫区间内的 lea reg,[rip+disp32]，产出 (指令偏移, 目标偏移)。

    只匹配 REX.W + 8D + ModRM(mod=00,rm=101)，即 64 位 lea 取地址——
    这是 MSVC 引用字符串/静态数据的标准形式。
    """
    pos = lo
    while pos < hi - 7:
        b = mm[pos]
        if 0x48 <= b <= 0x4F:                 # REX.W 前缀
            if mm[pos + 1] == 0x8D and (mm[pos + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", mm, pos + 3)[0]
                end = pos + 7                 # REX + 8D + ModRM + disp32
                yield pos, end + disp
        pos += 1


def read_ascii(mm, off, maxlen=96):
    out = bytearray()
    for i in range(maxlen):
        c = mm[off + i]
        if c == 0:
            break
        if not (0x20 <= c <= 0x7E):
            return None
        out.append(c)
    return out.decode("ascii") if out else None


def read_utf16(mm, off, maxlen=96):
    out = []
    for i in range(maxlen):
        lo = mm[off + 2 * i]
        hi = mm[off + 2 * i + 1]
        if lo == 0 and hi == 0:
            break
        ch = lo | (hi << 8)
        # 只接受 BMP 可打印区（含 CJK），排除控制字符与代理区
        if ch < 0x20 or 0xD800 <= ch <= 0xDFFF:
            return None
        out.append(chr(ch))
    return "".join(out) if out else None


def main():
    args = [a for a in sys.argv[1:]]
    minlen = 4
    if "--min" in args:
        i = args.index("--min")
        minlen = int(args[i + 1])
        del args[i:i + 2]
    nums = [int(a, 0) for a in args if not a.startswith("--")]
    lo, hi = (nums[0], nums[1]) if len(nums) >= 2 else DEFAULT_RANGE

    if not os.path.exists(EXE):
        print("找不到目标 exe：%s" % EXE)
        return 1
    size = os.path.getsize(EXE)
    print("目标: %s（%d 字节，只读 mmap）" % (EXE, size))
    print("扫描代码区间 0x%08X ~ 0x%08X（%d 字节），提取 rip-relative 引用的字符串"
          % (lo, hi, hi - lo))
    print("=" * 78)

    found = {}      # 目标偏移 -> (类型, 文本)
    refs = Counter()
    n_ref = 0
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for ins_off, tgt in iter_rip_refs(mm, lo, hi):
                n_ref += 1
                if not (0 <= tgt < size - 8):
                    continue
                refs[tgt] += 1
                if tgt in found:
                    continue
                s = read_ascii(mm, tgt)
                if s and len(s) >= minlen:
                    found[tgt] = ("A", s)
                    continue
                w = read_utf16(mm, tgt)
                if w and len(w) >= minlen:
                    found[tgt] = ("W", w)

    print("共扫到 %d 个 rip-relative lea，其中 %d 个目标是可读字符串（去重后）"
          % (n_ref, len(found)))
    print("-" * 78)
    for tgt in sorted(found):
        kind, text = found[tgt]
        print("  0x%08X [%s×%d] %s" % (tgt, kind, refs[tgt], text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
