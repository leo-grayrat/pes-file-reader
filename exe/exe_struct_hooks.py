#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_struct_hooks.py — 用「已解出的存档结构常量」当鱼钩，在 exe 里定位 data 块的解析代码。

思路（算法常量鱼钩法的翻版）：
  当年用 MT19937 的 LCG 常量（1664525 / 1566083941）在 468 MB 里各只命中 1 次，
  一举锁定加解密区。同一招可以换饵：我们已经用社区 wiki 法解出了 data 块的**步长常量**
  （EDIT 球员条目 312 B、team-player 表 284 B、ML 队块 0x690、赛程条目 0x254）。
  任何遍历这些表的代码都必须把「索引 × 步长」算出来，于是这些数字会以
  `imul reg, reg, imm32` 的乘数形式出现在代码里。

  只搜裸 4 字节立即数噪声太大（468 MB 里任意 4 字节组合都会撞上几十次），
  所以这里只认 imul 指令编码，把噪声压到可人工研判的量级：
    69 /r imm32        imul r32, r/m32, imm32
    48 69 /r imm32     imul r64, r/m64, imm32
    6B /r imm8         imul r32, r/m32, imm8   （只对 <=127 的常量有效）

  局限（如实说明）：MSVC /O2 常把常量乘法降级成 lea+shl 组合（312 = 8×39 可拆成
  lea+lea+shl），这类会漏掉。故「0 命中」不能证明解析器不存在，只能说明没用 imul。

地址口径：flat image（文件偏移即地址）。
只读：仅 mmap 读取，绝不执行/加载目标代码，绝不写入目标文件。

用法：
  python exe_struct_hooks.py                 # 扫全部已知结构常量
  python exe_struct_hooks.py 312 284         # 只扫指定常量（十进制或 0x 前缀）
  python exe_struct_hooks.py --raw 0x12A72FD # 额外搜裸 imm32（用于极特异的大偏移）
  python exe_struct_hooks.py 0x254 --group   # 命中点按「所属函数」归组（推断算法族）
  python exe_struct_hooks.py 0x690 --range 0x1300000 0x1360000  # 只看某代码区间
"""
import mmap
import os
import struct
import sys
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(BASE, "resources", "Patch 1.07.00",
                   "eFootball PES 2021", "PES2021.exe")

# 来自 core/pesfile.py 的已确认结构常量（注释即语义）
HOOKS = [
    (312,     "EDIT 球员条目步长（240 data + 72 appearance）"),
    (284,     "EDIT team-player 表步长"),
    (0x690,   "ML 队块步长（1680）"),
    (0x254,   "ML 赛程条目步长（596）"),
    (240,     "EDIT 球员 data 段长度"),
    (0x24,    "ML 事件表条目步长（36）"),
]

# 存档管理层区间（见 docs/exe-save-layout.md §7.3），用于判断命中是否落在已知模块外
SAVE_MGR = (0x140D000, 0x1432000)


def find_imul(mm, value):
    """找以 value 为立即数乘数的 imul 指令，返回 (偏移, 编码形式) 列表。"""
    hits = []
    imm32 = struct.pack("<i", value) if -(1 << 31) <= value < (1 << 31) else None
    n = len(mm)

    if imm32 is not None:
        # 形式 A: 69 /r imm32  （mod=11 的 reg,reg 形式：modrm 0xC0~0xFF）
        pos = 0
        while True:
            i = mm.find(b"\x69", pos, n - 6)
            if i < 0:
                break
            modrm = mm[i + 1]
            if modrm >= 0xC0 and mm[i + 2:i + 6] == imm32:
                # 排除 REX 前缀已被单独处理的情况由形式 B 覆盖，这里记录裸 69
                prev = mm[i - 1] if i > 0 else 0
                form = "48 69" if 0x40 <= prev <= 0x4F else "69"
                hits.append((i - 1 if form == "48 69" else i, form))
            pos = i + 1

    # 形式 C: 6B /r imm8（仅小常量）
    if -128 <= value <= 127:
        imm8 = struct.pack("<b", value)
        pos = 0
        while True:
            i = mm.find(b"\x6b", pos, n - 3)
            if i < 0:
                break
            modrm = mm[i + 1]
            if modrm >= 0xC0 and mm[i + 2:i + 3] == imm8:
                hits.append((i, "6B"))
            pos = i + 1
    return hits


def find_raw_imm32(mm, value):
    """搜裸 32 位小端立即数（噪声大，只用于极特异的大偏移常量）。"""
    pat = struct.pack("<I", value & 0xFFFFFFFF)
    out = []
    pos = 0
    while True:
        i = mm.find(pat, pos)
        if i < 0:
            break
        out.append(i)
        pos = i + 1
    return out


def func_start_hint(mm, off, back=0x600):
    """向前找 int3(0xCC) 填充，猜函数入口。无符号表时的启发式，可能不准。"""
    lo = max(0, off - back)
    idx = mm.rfind(b"\xcc", lo, off)
    if idx < 0:
        return None
    while idx + 1 < off and mm[idx + 1] == 0xCC:
        idx += 1
    return idx + 1


def group_hits(mm, value, hits):
    """把 imul 命中点按所属函数归组：同一函数里出现多次，说明该函数专职处理这张表。"""
    owners = {}
    for h in hits:
        off = h[0] if isinstance(h, tuple) else h
        st = func_start_hint(mm, off)
        key = st if st is not None else (off & ~0xFFF)
        owners.setdefault(key, []).append(off)
    print("  —— 按所属函数归组：%d 个函数 ——" % len(owners))
    for st in sorted(owners, key=lambda k: (-len(owners[k]), k)):
        pts = owners[st]
        print("    函数 0x%08X  命中 %d 处: %s"
              % (st, len(pts), ", ".join("0x%X" % p for p in pts[:6])
                 + (" ..." if len(pts) > 6 else "")))


def report(value, label, hits, kind="imul"):
    print("=" * 74)
    print("鱼钩 %d (0x%X) —— %s" % (value, value, label))
    print("  %s 命中 %d 处" % (kind, len(hits)))
    if not hits:
        print("  （无命中；注意 MSVC 可能把常量乘法降级为 lea+shl，不能据此断定无解析器）")
        return
    lo, hi = SAVE_MGR
    buckets = Counter((h[0] if isinstance(h, tuple) else h) >> 16 for h in hits)
    shown = 0
    for h in hits:
        off = h[0] if isinstance(h, tuple) else h
        form = h[1] if isinstance(h, tuple) else "-"
        where = "存档管理层内" if lo <= off < hi else ""
        print("    0x%08X  [%s] %s" % (off, form, where))
        shown += 1
        if shown >= 30:
            print("    ...（其余 %d 处略）" % (len(hits) - shown))
            break
    print("  按 64KB 分桶：%d 桶；最热 5 桶 %s"
          % (len(buckets),
             ", ".join("0x%08X:%d" % (b << 16, n) for b, n in buckets.most_common(5))))


def main():
    argv = list(sys.argv[1:])
    raw_mode = "--raw" in argv
    grp_mode = "--group" in argv
    rng = None
    if "--range" in argv:
        i = argv.index("--range")
        rng = (int(argv[i + 1], 0), int(argv[i + 2], 0))
        del argv[i:i + 3]
    args = [a for a in argv if not a.startswith("--")]
    if args:
        hooks = [(int(a, 0), "命令行指定") for a in args]
    else:
        hooks = HOOKS

    if not os.path.exists(EXE):
        print("找不到目标 exe：%s" % EXE)
        return 1
    print("目标: %s（%d 字节，只读 mmap，flat 口径）"
          % (EXE, os.path.getsize(EXE)))
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for value, label in hooks:
                hits = find_imul(mm, value)
                if rng:
                    lo, hi = rng
                    hits = [h for h in hits
                            if lo <= (h[0] if isinstance(h, tuple) else h) < hi]
                    label += "（限 0x%X~0x%X）" % (lo, hi)
                report(value, label, hits)
                if grp_mode:
                    group_hits(mm, value, hits)
                if raw_mode:
                    report(value, label + "（裸 imm32）",
                           find_raw_imm32(mm, value), kind="裸 imm32")
    return 0


if __name__ == "__main__":
    sys.exit(main())
