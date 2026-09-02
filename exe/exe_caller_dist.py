#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_caller_dist.py — 统计某个函数入口的 call rel32 调用者「地址分布」，用来区分
                     「通用库函数」和「某个业务模块的专用函数」。

为什么需要它：
  只数调用者个数会误判。`std::string::assign` 这类 MSVC 内联库函数在整个 exe 里
  有几百个调用点、散布在所有模块；而一个真正的业务专用函数（比如某种存档块的解析器）
  调用者少且地址高度聚集。判据是**分布**，不是**数量**。

  本脚本用于纠正 docs/exe-save-layout.md §7 末尾的一个假结论：曾以「调用 0x1413A20 /
  0x1413B60 的调用者集中在 0x1416xxx-0x1431xxx」为据，推断那一段是存档反序列化模块。
  但这两个函数后来被证明是 std::wstring / std::string 成员方法（见 §7.2），
  是全 exe 通用库函数，其 xref 分布不能证明任何模块归属。

地址口径：flat image（文件偏移即地址），与 exe_dis_func.py / exe_dis_callers.py 一致。

只读：仅 mmap 读取，绝不执行/加载目标代码，绝不写入目标文件。

用法：
  python exe_caller_dist.py <target_hex> [target_hex ...]
  python exe_caller_dist.py 0x1413A20 0x1413B60 0x1413DF0
"""
import mmap
import os
import struct
import sys
from collections import Counter

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(BASE, "resources", "Patch 1.07.00",
                   "eFootball PES 2021", "PES2021.exe")

# §7 末尾那段假结论声称的「反序列化模块」区间，用来量化检验其聚集性主张
CLAIMED_MODULE = (0x1416000, 0x1432000)


def callers_of(mm, target):
    """全文件扫 E8（call rel32），返回目标恰为 target 的调用点文件偏移列表。"""
    out = []
    pos = 0
    limit = len(mm) - 5
    while True:
        idx = mm.find(b"\xe8", pos, limit)
        if idx < 0:
            break
        rel = struct.unpack_from("<i", mm, idx + 1)[0]
        if idx + 5 + rel == target:
            out.append(idx)
        pos = idx + 1
    return out


def func_start_hint(mm, off, back=0x400):
    """向前找 int3(0xCC) 填充，猜函数入口。无符号表时的启发式，可能不准。"""
    lo = max(0, off - back)
    idx = mm.rfind(b"\xcc", lo, off)
    if idx < 0:
        return None
    # 跳过连续的 int3 填充
    while idx + 1 < off and mm[idx + 1] == 0xCC:
        idx += 1
    return idx + 1


def group_callers(mm, targets):
    """把多个目标的调用点按「所属函数入口」归组，输出候选函数清单。"""
    owners = {}
    for t in targets:
        for c in callers_of(mm, t):
            h = func_start_hint(mm, c)
            key = h if h else (c & ~0xFFF)
            owners.setdefault(key, []).append((c, t))
    print("=" * 74)
    print("按所属函数归组：%d 个候选函数（调用了 %s）"
          % (len(owners), " / ".join("0x%08X" % t for t in targets)))
    for fn in sorted(owners):
        hits = sorted(owners[fn])
        tgt_cnt = Counter(t for _, t in hits)
        desc = ", ".join("0x%08X×%d" % (t, n) for t, n in sorted(tgt_cnt.items()))
        print("  函数 0x%08X : %d 个调用点  [%s]" % (fn, len(hits), desc))
    return owners


def report(target, callers):
    print("=" * 74)
    print("target 0x%08X : %d 个直接调用者" % (target, len(callers)))
    if not callers:
        print("  （无直接调用者 —— 经间接分派进入，或为虚函数）")
        return
    print("  调用者地址跨度 0x%08X ~ 0x%08X（跨 %.1f MB）"
          % (min(callers), max(callers), (max(callers) - min(callers)) / 1048576.0))
    buckets = Counter(c >> 16 for c in callers)
    print("  按 64KB 分桶：共 %d 桶，最热 10 桶 ——" % len(buckets))
    for b, n in buckets.most_common(10):
        print("    0x%08X-0x%08X : %3d" % (b << 16, ((b + 1) << 16) - 1, n))
    lo, hi = CLAIMED_MODULE
    inmod = sum(1 for c in callers if lo <= c < hi)
    print("  落在声称的模块区间 0x%08X~0x%08X : %d / %d = %.1f%%"
          % (lo, hi - 1, inmod, len(callers), 100.0 * inmod / len(callers)))
    # 聚集性判据：调用者集中在少数桶里 => 专用函数；铺满几十上百个桶 => 通用库函数
    verdict = "专用（高度聚集）" if len(buckets) <= 4 else (
        "偏聚集" if len(buckets) <= 12 else "通用库函数（分布弥散）")
    print("  聚集性判定：%s" % verdict)


def main():
    args = [a for a in sys.argv[1:]]
    do_group = "--group" in args
    args = [a for a in args if not a.startswith("--")]
    targets = [int(a, 0) for a in args]
    if not targets:
        targets = [0x1413A20, 0x1413B60]
    if not os.path.exists(EXE):
        print("找不到目标 exe：%s" % EXE)
        return 1
    print("目标: %s（%d 字节，只读 mmap）" % (EXE, os.path.getsize(EXE)))
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            if do_group:
                group_callers(mm, targets)
            else:
                for t in targets:
                    report(t, callers_of(mm, t))
    return 0


if __name__ == "__main__":
    sys.exit(main())
