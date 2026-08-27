#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_probe.py — PES2021(mod) 游戏 exe 的【只读静态】探测工具（纯标准库）。

严格约束：本脚本只以只读方式 mmap 目标二进制，绝不执行/加载其代码，
绝不写入或修改目标文件；所有输出仅打印到 stdout。

子命令：
  pe      PE 概览（节表、导入表、文件 I/O 相关函数）
  key     主密钥锚点搜索（MASTERKEY_PES21 原始字节及变体）
  consts  已知结构常数搜索（步长/条数/文件大小）+ 关键字符串锚点
  strings 全量字符串普查（ASCII + UTF-16LE），按主题过滤
  ctx     对指定文件偏移输出 hex 转储与周边字符串（用于深挖锚点）
  all     依次执行以上全部

用法：
  python exe_probe.py all
  python exe_probe.py key --exe game\\FL_2023.exe

结论可复现：同一二进制上重复运行输出一致（不含时间戳/随机因素）。
"""
import argparse
import mmap
import os
import re
import struct
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_EXE = os.path.join(BASE, "game", "FL_2023.exe")

# ---- PES2021 主密钥（与 pes_decrypt.py 的 MASTERKEY_PES21 一致，64 字节）----
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

# ---- 已知结构常数（来自 docs/bl_ml_structure.md、docs/replay_structure.md）----
# (值, struct 格式, 说明)
STRUCT_CONSTS = [
    (5383087, "<I", "回放文件总大小 (0x5223AF)"),
    (5368928, "<I", "回放数据块大小 (0x51EC60)"),
    (5368848, "<I", "回放负载长度 0x51EC10（data-0x50）"),
    (13157,   "<I", "回放 logo 块大小"),
    (1680,    "<I", "球队记录步长 0x690"),
    (1680,    "<H", "球队记录步长 0x690 (16位)"),
    (788,     "<I", "赛事表记录步长 0x314"),
    (788,     "<H", "赛事表记录步长 0x314 (16位)"),
    (160,     "<I", "回放名单步长 0xA0"),
    (700,     "<I", "球队数"),
    (76,      "<I", "赛事条数"),
    (320,     "<I", "加密头尺寸 ENCRYPTION_HEADER_SIZE"),
    (208,     "<I", "文件头尺寸 FILE_HEADER_SIZE"),
    (0x11F2C0, "<I", "球队数组尾偏移 0x100+700*0x690"),
    (0x1F1E30, "<I", "赛事表基址候选"),
    # —— 数据侧新增：比赛日记录与赛季 ——
    (596,      "<I", "比赛日记录步长 0x254"),
    (596,      "<H", "比赛日记录步长 0x254 (16位)"),
    (713,      "<I", "比赛日记录数（进度相关）"),
    (1473,     "<I", "比赛日记录数（进度相关）"),
    (0x345408, "<I", "比赛日数组基址（存档内偏移）"),
    (0x3299B0, "<I", "比赛日数组基址候选（存档内偏移）"),
    (2020,     "<I", "赛季起始年"),
    (2021,     "<I", "赛季起始年"),
]

# 关键字符串锚点（ASCII 与 UTF-16LE 双编码搜索）
ANCHOR_STRINGS = [
    "REPLAY", "REPLAY00000000", "REPLAY%08d", "REPLAY%08X",
    "ML00000000", "BL00000000", "EDIT",
    "Master League", "MasterLeague", "Become a Legend", "BecomeALegend",
    "Option File", "OptionFile", "SaveData", "SAVE DATA",
    # —— 外部球员数据库 / 资金动态余额 相关 ——
    "Pesdb", "pesdb", "PESDB", "PlayerDB", "player_db", "MasterDB",
    "PlayerData", "player_data", "PLAYER.bin", "player.bin",
    "balance", "Balance", "BALANCE", "clubMoney", "fundBalance",
]

# 字符串普查的主题过滤器（全部小写比对）
STRING_GROUPS = {
    "存档/读写/路径": [
        "save", "load", ".bin", ".dat", "optionfile", "option file",
        "userdata", "user data", "slot", "storage", "write data", "read data",
    ],
    "资金/转会": [
        "budget", "fund", "money", "transfer", "salary", "fee",
        "finance", "cash", "income", "expense", "balance",
    ],
    "赛程/赛事": [
        "schedule", "fixture", "calendar", "competition", "tournament",
        "league", "cup", "season", "matchday", "round",
    ],
    "球员/球队": [
        "player", "squad", "roster", "team", "club", "position",
        "rating", "ability", "condition",
    ],
    "战术": [
        "tactic", "formation", "strategy", "instruction", "playstyle",
        "pressing", "defensive", "attacking",
    ],
    "回放": ["replay", "highlight", "goal cam", "instant replay"],
    "模式名": [
        "master league", "become a legend", "myclub", "my club",
        "exhibition", "training", "edit mode",
    ],
}

MAX_LIST = 24          # 每类命中最多列出的条数
COUNT_CAP = 1000000    # 计数上限（超过记为 >cap，避免噪声常数耗时）
CTX_WINDOW = 512       # 命中点上下文窗口（字节）

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


# ---------------- PE 解析（只读、标准库实现） ----------------

def parse_pe(mm):
    """解析 PE 头、节表、导入表，返回 dict。"""
    info = {"error": None}
    try:
        if mm[:2] != b"MZ":
            info["error"] = "缺少 MZ 魔数"
            return info
        e_lfanew = struct.unpack_from("<I", mm, 0x3C)[0]
        if mm[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            info["error"] = "缺少 PE 签名"
            return info
        coff = e_lfanew + 4
        machine, nsec, timestamp, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", mm, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", mm, opt)[0]
        info["machine"] = {0x8664: "x86-64", 0x14C: "x86"}.get(machine, hex(machine))
        info["timestamp"] = timestamp
        info["pe32plus"] = (magic == 0x20B)
        if magic == 0x20B:
            info["image_base"] = struct.unpack_from("<Q", mm, opt + 24)[0]
            dd_off = opt + 112
        else:
            info["image_base"] = struct.unpack_from("<I", mm, opt + 28)[0]
            dd_off = opt + 96
        sections = []
        sec_off = opt + opt_size
        for i in range(nsec):
            o = sec_off + i * 40
            name = mm[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", mm, o + 8)
            sections.append({"name": name, "vsize": vsize, "vaddr": vaddr,
                             "rsize": rsize, "raddr": raddr})
        info["sections"] = sections
        # 数据目录：第 1 项为导入表
        n_dd = struct.unpack_from("<I", mm, dd_off - 4)[0]
        info["imports"] = []
        if n_dd > 1:
            imp_rva, imp_size = struct.unpack_from("<II", mm, dd_off + 8)
            if imp_rva:
                info["imports"] = parse_imports(mm, sections, imp_rva)
    except Exception as e:  # noqa: BLE001 —— 静态探测需容忍畸形数据
        info["error"] = repr(e)
    return info


def rva2off(sections, rva):
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            return s["raddr"] + (rva - s["vaddr"])
    return None


def off2rva(sections, off):
    for s in sections:
        if s["raddr"] <= off < s["raddr"] + s["rsize"]:
            return s["vaddr"] + (off - s["raddr"])
    return None


def read_cstr(mm, off, limit=256):
    end = mm.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return mm[off:end].decode("ascii", "replace")


def parse_imports(mm, sections, imp_rva):
    """解析导入表：返回 [{dll, funcs:[...]}]。"""
    off = rva2off(sections, imp_rva)
    result = []
    if off is None:
        return result
    entry_size = 8 if True else 0  # PE32+ thunk 为 8 字节；此处按 8 字节处理
    for i in range(512):  # 防畸形：上限 512 个 DLL
        desc = off + i * 20
        oft, ts, fwd, name_rva, ft = struct.unpack_from("<IIIII", mm, desc)
        if oft == 0 and name_rva == 0:
            break
        n_off = rva2off(sections, name_rva)
        dll = read_cstr(mm, n_off) if n_off is not None else "?"
        funcs = []
        thunk_rva = oft or ft
        t_off = rva2off(sections, thunk_rva)
        if t_off is not None:
            for j in range(8192):  # 防畸形：单 DLL 函数数上限
                val = struct.unpack_from("<Q", mm, t_off + j * entry_size)[0]
                if val == 0:
                    break
                if val >> 63:  # 按序号导入
                    funcs.append("#%d" % (val & 0xFFFF))
                else:
                    h_off = rva2off(sections, val & 0x7FFFFFFF)
                    if h_off is not None:
                        funcs.append(read_cstr(mm, h_off + 2, 128))
        result.append({"dll": dll, "funcs": funcs})
    return result


FILE_IO_PAT = re.compile(
    r"(CreateFile|ReadFile|WriteFile|SetFilePointer|FlushFile|GetFileSize|"
    r"DeleteFile|FindFirstFile|FindNextFile|CloseHandle|MapViewOf|CreateMapping|"
    r"SetEndOfFile|LockFile|GetTempPath|GetFullPath|fopen|fread|fwrite|fclose)",
    re.I)


# ---------------- 通用工具 ----------------

def find_all(mm, pat, cap=COUNT_CAP):
    """生成所有命中偏移；超过 cap 时停止并返回 (offsets, overflow)。"""
    offsets = []
    pos = 0
    while len(offsets) <= cap:
        pos = mm.find(pat, pos)
        if pos < 0:
            return offsets, False
        offsets.append(pos)
        pos += 1
        if len(offsets) > cap:
            return offsets, True
    return offsets, False


def nearby_ascii(mm, off, window=CTX_WINDOW, minlen=5):
    """提取命中点附近窗口内的可打印 ASCII 串（去重、保序）。"""
    lo, hi = max(0, off - window), min(len(mm), off + window)
    out, seen = [], set()
    for m in ASCII_RE.finditer(mm[lo:hi]):
        s = m.group().decode("ascii")
        if len(s) >= minlen and s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) >= 6:
            break
    return out


def full_string_at(mm, off, enc="ascii"):
    """取命中点所在的完整串（向前回溯到非可打印边界）。"""
    step = 1 if enc == "ascii" else 2
    start = off
    ok = set(range(0x20, 0x7F))
    while start >= step:
        if enc == "ascii":
            if mm[start - 1] in ok:
                start -= 1
                continue
        else:
            if mm[start - 2] in ok and mm[start - 1] == 0:
                start -= 2
                continue
        break
    end = off
    while end < len(mm) - step:
        if enc == "ascii":
            if mm[end] in ok:
                end += 1
                continue
        else:
            if mm[end] in ok and mm[end + 1] == 0:
                end += 2
                continue
        break
    try:
        return mm[start:end].decode(enc)
    except Exception:  # noqa: BLE001
        return mm[start:end].decode(enc, "replace")


def hexdump(mm, off, radius=32):
    """以 off 为中心的 hex 转储（含偏移标注）。"""
    lo = max(0, off - radius)
    hi = min(len(mm), off + radius + 8)
    lines = []
    for row in range(lo, hi, 16):
        chunk = mm[row:row + 16]
        hx = " ".join("%02X" % b for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        mark = " <--" if row <= off < row + 16 else ""
        lines.append("    0x%08X  %-47s  %s%s" % (row, hx, asc, mark))
    return "\n".join(lines)


def fmt_hit(sections, off):
    rva = off2rva(sections, off)
    if rva is None:
        return "文件偏移 0x%08X（RVA: 节外/覆盖区）" % off
    return "文件偏移 0x%08X  RVA 0x%08X" % (off, rva)


def open_target(path):
    size = os.path.getsize(path)
    f = open(path, "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    return f, mm, size


# ---------------- 子命令实现 ----------------

def cmd_pe(mm, sections_holder, args):
    print("=" * 72)
    print("[PE 概览]")
    info = parse_pe(mm)
    sections_holder.update(info)
    if info.get("error"):
        print("  解析失败:", info["error"])
        return
    print("  架构: %s | ImageBase: 0x%X | TimeDateStamp: 0x%08X" %
          (info["machine"], info["image_base"], info["timestamp"]))
    print("  节表:")
    print("    %-8s %10s %12s %12s %12s" % ("名称", "VirtAddr", "VirtSize", "RawAddr", "RawSize"))
    for s in info["sections"]:
        print("    %-8s 0x%08X 0x%08X   0x%08X 0x%08X" %
              (s["name"], s["vaddr"], s["vsize"], s["raddr"], s["rsize"]))
    print("  导入表（%d 个 DLL）:" % len(info["imports"]))
    for d in info["imports"]:
        io_funcs = [fn for fn in d["funcs"] if FILE_IO_PAT.search(fn)]
        print("    - %s（%d 个函数）" % (d["dll"], len(d["funcs"])))
        if io_funcs:
            print("      文件 I/O 相关: %s" % ", ".join(io_funcs[:40]))


def cmd_key(mm, sections, args):
    print("=" * 72)
    print("[主密钥锚点搜索] MASTERKEY_PES21（64 字节）")
    key = MASTERKEY_PES21
    variants = [
        ("完整 64 字节原始序列", key),
        ("前 32 字节", key[:32]),
        ("后 32 字节", key[32:]),
        ("按 4 字节反转（字节序变体）", b"".join(key[i:i + 4][::-1] for i in range(0, 64, 4))),
        ("按 8 字节反转（字节序变体）", b"".join(key[i:i + 8][::-1] for i in range(0, 64, 8))),
    ]
    # 追加：16 字节分段（含反序），用于密钥被拆分存储/部分内联的情形
    total_hits = 0
    for name, pat in variants:
        hits, overflow = find_all(mm, pat, cap=256)
        shown = hits[:MAX_LIST]
        total_hits += len(shown)
        tag = "（>cap）" if overflow else ""
        print("  [%s] 命中 %d 处%s" % (name, len(hits), tag))
        for off in shown:
            print("    %s" % fmt_hit(sections, off))
            ctx = nearby_ascii(mm, off)
            if ctx:
                print("      附近字符串: %s" % " | ".join(ctx))
            else:
                print("      附近字符串: （窗口内无可打印串）")
    print("  ── 16 字节分段命中统计（低置信度，仅计数）：")
    seg_hits = 0
    for i in range(0, 64, 16):
        seg = key[i:i + 16]
        for label, p in (("正序", seg), ("反序", seg[::-1])):
            hits, _ = find_all(mm, p, cap=16)
            if hits:
                seg_hits += len(hits)
                print("    key[%d:%d] %s 命中 %d 处: %s" %
                      (i, i + 16, label, len(hits),
                       ", ".join("0x%08X" % o for o in hits[:8])))
    if seg_hits == 0:
        print("    无任何 16 字节分段命中")
    if total_hits == 0:
        print("  结论：未在任何变体下命中，密钥可能以展开常量/指令立即数形式存在，或已被 mod 移除。")


def cmd_consts(mm, sections, args):
    print("=" * 72)
    print("[已知结构常数搜索]")
    for value, fmt, desc in STRUCT_CONSTS:
        pat = struct.pack(fmt, value)
        hits, overflow = find_all(mm, pat, cap=COUNT_CAP)
        n = len(hits)
        tag = "（>cap，噪声常数）" if overflow else ""
        # 噪声常数（命中过多）只抽样列出带上下文的少量命中
        shown = hits[:MAX_LIST]
        print("  常数 %d (0x%X, %s) [%s]：命中 %d 处%s" %
              (value, value, desc, fmt, n, tag))
        for off in shown:
            ctx = nearby_ascii(mm, off, window=256)
            ctx_s = (" | ".join(ctx)) if ctx else "-"
            print("    %s  ctx: %s" % (fmt_hit(sections, off), ctx_s))
        if 0 < n <= 16:  # 低命中高价值常数：附 hex 转储供人工判读指令形态
            print("    -- hex 转储（命中点 ±32 字节）--")
            for off in shown[:8]:
                print(hexdump(mm, off))
    print("-" * 72)
    print("[关键字符串锚点]")
    for s in ANCHOR_STRINGS:
        for enc, label in (("ascii", "ASCII"), ("utf-16-le", "UTF16")):
            pat = s.encode(enc)
            hits, overflow = find_all(mm, pat, cap=512)
            if not hits:
                continue
            tag = "（>cap）" if overflow else ""
            print('  "%s" [%s] 命中 %d 处%s' % (s, label, len(hits), tag))
            for off in hits[:12]:
                full = full_string_at(mm, off, enc)
                print("    %s  完整串: %r" % (fmt_hit(sections, off), full[:80]))


def cmd_strings(mm, sections, args):
    print("=" * 72)
    print("[字符串普查] 全文件提取后按主题过滤（仅列出代表性命中）")
    hits_by_group = {g: [] for g in STRING_GROUPS}
    counts_by_group = {g: 0 for g in STRING_GROUPS}
    n_ascii = n_utf16 = 0

    def test(text, off, enc_label):
        low = text.lower()
        for g, kws in STRING_GROUPS.items():
            if any(k in low for k in kws):
                counts_by_group[g] += 1
                if len(hits_by_group[g]) < MAX_LIST * 3:
                    hits_by_group[g].append((off, enc_label, text))

    for m in ASCII_RE.finditer(mm):
        n_ascii += 1
        test(m.group().decode("ascii"), m.start(), "A")
    for m in UTF16_RE.finditer(mm):
        n_utf16 += 1
        test(m.group().decode("utf-16-le"), m.start(), "W")

    print("  ASCII 串总数: %d，UTF-16LE 串总数: %d" % (n_ascii, n_utf16))
    for g in STRING_GROUPS:
        print("  ── 主题【%s】匹配 %d 条，列出前 %d 条：" %
              (g, counts_by_group[g], min(len(hits_by_group[g]), MAX_LIST)))
        for off, enc_label, text in hits_by_group[g][:MAX_LIST]:
            print("    [%s] %s  %r" % (enc_label, fmt_hit(sections, off), text[:96]))


def cmd_ctx(mm, sections, args):
    print("=" * 72)
    offs = [int(x, 0) for x in args.off]
    if not offs:
        print("  未指定偏移（--off 0x1FB6358 ...）")
        return
    for off in offs:
        if not (0 <= off < len(mm)):
            print("  偏移 0x%X 越界" % off)
            continue
        print("[锚点深挖] %s" % fmt_hit(sections, off))
        print(hexdump(mm, off, radius=args.radius))
        ctx = nearby_ascii(mm, off, window=args.radius * 4, minlen=4)
        print("    周边字符串: %s" % (" | ".join(ctx) if ctx else "-"))


def main():
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser(description="PES2021 exe 只读静态探测")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("pe", "key", "consts", "strings", "ctx", "all"):
        p = sub.add_parser(name, help="%s 子命令" % name)
        p.add_argument("--exe", default=DEFAULT_EXE, help="目标二进制路径")
        if name == "ctx":
            p.add_argument("--off", nargs="+", required=True,
                           help="一个或多个文件偏移（支持 0x 十六进制）")
            p.add_argument("--radius", type=int, default=64, help="转储半径（字节）")
    args = ap.parse_args()

    exe = args.exe if os.path.isabs(args.exe) else os.path.join(BASE, args.exe)
    if not os.path.isfile(exe):
        print("错误：目标文件不存在：%s" % exe)
        return 1

    f, mm, size = open_target(exe)
    try:
        print("目标文件: %s（%d 字节，只读 mmap，绝不执行）" % (exe, size))
        holder = {}
        if args.cmd in ("pe", "all"):
            cmd_pe(mm, holder, args)
        info = holder or parse_pe(mm)
        sections = info.get("sections", [])
        if args.cmd in ("key", "all"):
            cmd_key(mm, sections, args)
        if args.cmd in ("consts", "all"):
            cmd_consts(mm, sections, args)
        if args.cmd in ("strings", "all"):
            cmd_strings(mm, sections, args)
        if args.cmd == "ctx":
            cmd_ctx(mm, sections, args)
    finally:
        mm.close()
        f.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
