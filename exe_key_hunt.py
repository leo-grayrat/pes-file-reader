#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_key_hunt.py — MASTERKEY_PES21「拆分内联」定向搜索（纯标准库，只读 mmap）。

背景：exe_probe.py 的 cmd_key 只搜【64 字节连续】的变体，以及 16 字节分段。
它从未测试"密钥被拆成 8 字节 / 4 字节立即数散落内联在代码里"这一假设。
本脚本补上这一层：
  - 8 字节(qword)块：468MB 内期望误报 ~2.5e-11，命中即强信号
  - 4 字节(dword)块：期望误报 ~109，靠"多个不同 dword 在相近地址聚集"筛选
并输出命中处的十六进制上下文，便于判断是否真是指令立即数。

严格只读：仅 mmap 读取目标二进制，绝不执行/加载其代码，绝不写入目标文件。
用法：
  python exe_key_hunt.py "resources/Patch 1.07.00/eFootball PES 2021/PES2021.exe"
"""
import mmap
import os
import sys

# ---- PES2021 主密钥（与 pes_decrypt.py / exe_probe.py 的 MASTERKEY_PES21 一致，64 字节）----
MASTERKEY_PES21 = bytes([
    0x90, 0x61, 0xD8, 0x66, 0x43, 0x77, 0x24, 0xF8,
    0x92, 0xBA, 0xB8, 0x71, 0x21, 0xC7, 0x60, 0x63,
    0xF0, 0x91, 0x9A, 0x7D, 0xED, 0x47, 0x80, 0xDE,
    0x51, 0xF5, 0xDD, 0xD1, 0x08, 0xFE, 0x32, 0x84,
    0xF5, 0x09, 0x92, 0x00, 0xB2, 0x3E, 0x88, 0x9F,
    0xEB, 0x24, 0x43, 0x05, 0x58, 0x76, 0x00, 0x22,
    0x9B, 0xFE, 0xEC, 0xF6, 0x50, 0x00, 0x29, 0xD3,
    0x42, 0x75, 0x50, 0xB9, 0xEC, 0xD2, 0xF6, 0x75,
])

CAP = 32          # 每个模式最多记录多少命中
CTX_BYTES = 48    # 命中前后各取多少字节做上下文
CLUSTER_WIN = 0x1000  # 4 字节命中聚集判定窗口（同 4KB 内算聚集）


def find_all(mm, pat, cap=CAP):
    """返回 pat 在 mm 中的全部偏移（最多 cap 个）。"""
    hits = []
    start = 0
    while True:
        i = mm.find(pat, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
        if len(hits) >= cap:
            break
    return hits


def hex_ctx(mm, off, span=CTX_BYTES):
    """命中处前后的 hex + 可打印 ASCII，用于人工判断是否指令立即数。"""
    lo = max(0, off - span)
    hi = min(len(mm), off + span)
    raw = mm[lo:hi]
    out = []
    for base in range(0, len(raw), 16):
        chunk = raw[base:base + 16]
        hexs = " ".join("%02X" % b for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        mark = "  <<<" if lo + base <= off < lo + base + 16 else ""
        out.append("    %08X  %-47s  %s%s" % (lo + base, hexs, ascii_, mark))
    return "\n".join(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path or not os.path.isfile(path):
        print("用法: python exe_key_hunt.py <exe 路径>")
        return 1
    size = os.path.getsize(path)
    print("目标: %s（%d 字节，只读 mmap，绝不执行）" % (path, size))

    key = MASTERKEY_PES21
    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # ---------- 第一层：8 字节(qword)块 ----------
            print("=" * 74)
            print("[第一层] 8 字节(qword)分段搜索 —— 命中即强信号")
            print("  （64 字节 = 8 个 qword；每块正反两种字节序分别搜）")
            qword_hits = {}   # block_index -> [(off, label)]
            total_q = 0
            for i in range(0, 64, 8):
                blk = key[i:i + 8]
                for label, pat in (("正序", blk), ("反序", blk[::-1])):
                    hits = find_all(mm, pat)
                    if hits:
                        qword_hits.setdefault(i // 8, []).extend(
                            (o, label) for o in hits)
                        total_q += len(hits)
                        print("  qword[%d] key[%02d:%02d] %s %s -> %d 处: %s"
                              % (i // 8, i, i + 8, label, pat.hex(), len(hits),
                                 ", ".join("0x%08X" % o for o in hits[:6])))
                        for o in hits[:2]:
                            print(hex_ctx(mm, o))
            if not total_q:
                print("  未命中任何 8 字节块。")

            # ---------- 第二层：4 字节(dword)块 ----------
            print("=" * 74)
            print("[第二层] 4 字节(dword)分段搜索 —— 有噪声，靠聚集筛选")
            print("  （64 字节 = 16 个 dword；x86 立即数最常见的内联粒度）")
            dword_hits = {}   # dword_index -> [off]
            for i in range(0, 64, 4):
                blk = key[i:i + 4]
                for label, pat in (("正序", blk), ("反序", blk[::-1])):
                    hits = find_all(mm, pat, cap=256)
                    if hits:
                        dword_hits.setdefault(i // 4, []).extend(hits)
                        print("  dword[%02d] key[%02d:%02d] %s %s -> %d 处"
                              % (i // 4, i, i + 4, label, pat.hex(), len(hits)))
            if not dword_hits:
                print("  未命中任何 4 字节块。")

            # ---------- 聚集分析 ----------
            if dword_hits:
                print("=" * 74)
                print("[聚集分析] 不同 dword 是否落在相近地址（同 0x%X 窗口）" % CLUSTER_WIN)
                flat = []
                for idx, offs in dword_hits.items():
                    for o in offs:
                        flat.append((o, idx))
                flat.sort()
                clusters = []
                cur = [flat[0]]
                for o, idx in flat[1:]:
                    if o - cur[-1][0] <= CLUSTER_WIN:
                        cur.append((o, idx))
                    else:
                        clusters.append(cur)
                        cur = [(o, idx)]
                clusters.append(cur)
                scored = []
                for c in clusters:
                    idxs = set(i for _, i in c)
                    scored.append((len(idxs), c[0][0], c[-1][0], sorted(idxs)))
                scored.sort(reverse=True)
                shown = 0
                for nuniq, lo, hi, idxs in scored:
                    if nuniq < 3:      # 少于 3 个不同 dword 视为噪声
                        continue
                    print("  ★ 窗口 0x%08X~0x%08X：%d 个不同 dword（索引 %s）"
                          % (lo, hi, nuniq, idxs))
                    print(hex_ctx(mm, lo, span=32))
                    shown += 1
                    if shown >= 5:
                        break
                if not shown:
                    print("  未发现 >=3 个不同 dword 的聚集（密钥大概率不是 dword 立即数内联）。")

            # ---------- 结论 ----------
            print("=" * 74)
            if total_q:
                print("结论：8 字节块有命中 —— 密钥很可能以 qword 立即数/数据块形式内联，")
                print("      用 exe_probe.py ctx 对命中偏移深挖周边函数。")
            elif dword_hits:
                print("结论：8 字节块 0 命中，4 字节块有命中但无强聚集。")
                print("      密钥既非整段连续、也非 qword 立即数内联；")
                print("      更可能是运行时构造（由种子/算法生成）或经过变换后存储。")
            else:
                print("结论：8 字节与 4 字节分段均 0 命中。")
                print("      密钥不以任何原始字节片段形式出现在 exe 中 ——")
                print("      「拆分内联」假设被证伪，应转向「运行时构造/派生」。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
