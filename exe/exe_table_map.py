#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_table_map.py — 从「批量表处理函数」里抽出游戏内部的数据表清单。

背景：
  0x13FE480 这类函数会一张表接一张表地跑循环，每张表的循环都长这样：

      cmp  edi, 0x7531            ; ① 硬编码容量上限（越界就换哨兵对象）
      lea  rdx, [rbx + 0xadf4bc]  ; ② 表基址（相对某全局单例 rbx）
      imul rcx, rax, 0x17c        ; ③ 元素大小（索引 × 步长）
      call 0xaf6290               ; ④ 每元素的处理函数
      cmp  edi, dword [rbx+0xd0bce8]  ; ⑤ 实际元素个数所在的变量
      jb   循环头

  编译器做了强度削减的循环则把 ③ 换成 `add rbp, 0x208`（指针每轮加步长），
  语义等价。于是把这些立即数按出现顺序收集起来，就是一张
  「元素大小 × 容量上限 × 表基址 × 计数变量」的清单——
  这是 exe 亲口报出的内部数据模型，可用来反向校验我们对存档 data 块的切分。

判读须知（工具只做提取，不替你下结论）：
  * 一个循环里常有两个 cmp 立即数：循环体内那个是**容量上限**（配 cmovae/jb 选哨兵），
    循环末尾那个是**本次实际轮数**。工具按出现顺序列出，不猜哪个是哪个。
  * `imul` 与 `add` 二者出现其一即可确定步长；都没有则该表步长未定。
  * 基址取最近一次 `lea rdx,[rbx+disp]`；同一循环里可能先出现哨兵基址再出现真表基址。

地址口径：flat image（文件偏移即地址）。
只读：仅 mmap 读取，绝不执行/加载目标代码，绝不写入目标文件。

用法：
  python exe_table_map.py 0x13FE480
  python exe_table_map.py 0x13FE480 0x13FDBE0 0x13FD530 0x13FCF70 0x13FCD30
  python exe_table_map.py 0x13FE480 --limit 0x1200      # 手动放宽扫描长度
"""
import mmap
import os
import re
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(BASE, "resources", "Patch 1.07.00",
                   "eFootball PES 2021", "PES2021.exe")

# 只把「像结构大小」的立即数当步长候选：太小的是标志位掩码，太大的是全局偏移
STRIDE_LO, STRIDE_HI = 0x10, 0x4000
# 容量上限候选范围（球员 30001、赛程 13000、联赛 100 …）
CAP_LO, CAP_HI = 8, 0x100000

RE_IMUL = re.compile(r"^(r[a-z0-9]+), (r[a-z0-9]+), (0x[0-9a-f]+)$")
RE_ADD_IMM = re.compile(r"^(r[a-z0-9]+), (0x[0-9a-f]+)$")
RE_CMP_IMM = re.compile(r"^([a-z0-9]+), (0x[0-9a-f]+|\d+)$")
RE_CMP_MEM = re.compile(r"^dword ptr \[(r[a-z0-9]+) \+ (0x[0-9a-f]+)\], ([a-z0-9]+)$")
RE_CMP_MEM2 = re.compile(r"^([a-z0-9]+), dword ptr \[(r[a-z0-9]+) \+ (0x[0-9a-f]+)\]$")
RE_LEA_BASE = re.compile(r"^(r[a-z0-9]+), \[(r[a-z0-9]+) \+ (0x[0-9a-f]+)\]$")


def scan(mm, start, limit):
    """扫到第一个 ret（含跨过 int3 对齐的情况）为止，返回记录列表。"""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    rows = []
    cur = {"caps": [], "stride": None, "bases": [], "counts": [], "iters": None}
    end_at = None
    last_cmp = None      # 最近一个 cmp 的立即数，用于识别循环末尾的轮数比较

    for ins in md.disasm(mm[start:start + limit], start):
        mn, ops = ins.mnemonic, ins.op_str
        if mn == "ret":
            end_at = ins.address
            break

        if mn == "imul":
            m = RE_IMUL.match(ops)
            if m:
                v = int(m.group(3), 0)
                if STRIDE_LO <= v <= STRIDE_HI:
                    cur["stride"] = v
        elif mn == "add":
            m = RE_ADD_IMM.match(ops)
            if m:
                v = int(m.group(2), 0)
                if STRIDE_LO <= v <= STRIDE_HI:
                    # 强度削减的循环把「索引×步长」换成「指针每轮加步长」，
                    # 这条 add 位于 call 之后，步长属于刚结算的那张表而非下一张。
                    if cur["stride"] is None and rows and rows[-1]["stride"] is None:
                        rows[-1]["stride"] = v
                    elif cur["stride"] is None:
                        cur["stride"] = v
        elif mn in ("jb", "jae", "jne", "jl", "jbe", "jle"):
            # 回跳 = 循环末尾，那么最近这个 cmp 立即数是「本次轮数」，
            # 应归给刚结算的表，而不是当成下一张表的容量上限。
            try:
                tgt = int(ops, 0)
            except ValueError:
                tgt = None
            if tgt is not None and tgt < ins.address and last_cmp is not None:
                if rows and rows[-1]["iters"] is None:
                    rows[-1]["iters"] = last_cmp
                if last_cmp in cur["caps"]:
                    cur["caps"].remove(last_cmp)
                last_cmp = None
        elif mn == "cmp":
            m = RE_CMP_IMM.match(ops)
            if m:
                v = int(m.group(2), 0)
                if CAP_LO <= v <= CAP_HI:
                    cur["caps"].append(v)
                    last_cmp = v
            else:
                m = RE_CMP_MEM.match(ops) or RE_CMP_MEM2.match(ops)
                if m:
                    g = m.groups()
                    off = int(g[1], 0) if g[1].startswith("0x") else int(g[2], 0)
                    if off not in cur["counts"]:
                        cur["counts"].append(off)
        elif mn == "lea":
            m = RE_LEA_BASE.match(ops)
            if m and m.group(1) in ("rdx", "rcx", "rax", "r8"):
                off = int(m.group(3), 0)
                if off > 0x1000:            # 表基址都是大偏移，滤掉栈/小结构
                    cur["bases"].append(off)
        elif mn == "call" and ops.startswith("0x"):
            # 一轮循环收尾：把攒到的参数结成一条记录
            if cur["stride"] or cur["caps"]:
                cur["handler"] = int(ops, 0)
                cur["at"] = ins.address
                rows.append(cur)
                cur = {"caps": [], "stride": None, "bases": [],
                       "counts": [], "iters": None}
            # 结算后清游标：否则循环末尾若用「cmp 索引, 计数变量」终止，
            # 回跳检测会把循环体内的容量上限误抄成轮数（实测踩过）。
            last_cmp = None

    return rows, end_at


def report(start, rows, end_at):
    print("=" * 96)
    print("批量表处理函数 0x%08X%s" % (start,
          ("  (函数体到 0x%08X 的 ret)" % end_at) if end_at else "  (未在扫描窗口内遇到 ret)"))
    print("-" * 96)
    if not rows:
        print("  未提取到表参数——该函数可能不是批量表循环，或用了本工具未覆盖的寻址形式。")
        return
    print("  %-12s %-16s %-12s %-20s %-20s %s"
          % ("元素大小", "容量上限", "本次轮数", "表基址(rbx+)",
             "计数变量(rbx+)", "每元素处理函数"))
    for r in rows:
        stride = ("%d (0x%X)" % (r["stride"], r["stride"])) if r["stride"] else "—"
        caps = ", ".join("%d (0x%X)" % (c, c) for c in r["caps"]) or "—"
        iters = ("%d (0x%X)" % (r["iters"], r["iters"])) if r["iters"] else "—"
        bases = ", ".join("0x%X" % b for b in r["bases"][-2:]) or "—"
        counts = ", ".join("0x%X" % c for c in r["counts"]) or "—"
        print("  %-12s %-16s %-12s %-20s %-20s 0x%08X"
              % (stride, caps, iters, bases, counts, r["handler"]))
    print("-" * 96)
    print("  共 %d 条。容量上限 = 循环体内的越界检查（超了就用哨兵对象）；" % len(rows))
    print("  本次轮数 = 循环末尾回跳前的比较值。表基址列可能同时含哨兵基址与真表基址。")


def main():
    argv = list(sys.argv[1:])
    limit = 0x1000
    if "--limit" in argv:
        i = argv.index("--limit")
        limit = int(argv[i + 1], 0)
        del argv[i:i + 2]
    if not argv:
        print(__doc__)
        return 1
    if not os.path.exists(EXE):
        print("找不到目标 exe：%s" % EXE)
        return 1
    with open(EXE, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            for a in argv:
                start = int(a, 0)
                rows, end_at = scan(mm, start, limit)
                report(start, rows, end_at)
    return 0


if __name__ == "__main__":
    sys.exit(main())
