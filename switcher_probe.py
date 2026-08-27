#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FL23 switcher.exe 深度静态逆向探针（纯标准库、全程只读、不执行目标程序）。

任务 #15：判定程序类型（安装器/切换器）、提取内嵌结构（PE 资源/覆盖数据/
zlib 载荷/内嵌 CPK）、还原切换机制（文件清单/路径/URL/校验逻辑）。

用法:
  python switcher_probe.py pe       # PE 概览 + 覆盖数据(overlay) + 导入表
  python switcher_probe.py sig      # 安装器类型签名扫描
  python switcher_probe.py strings  # 全文件字符串普查 (ASCII + UTF-16LE)
  python switcher_probe.py zlib     # 全部 zlib 流定位与内容摘要
  python switcher_probe.py script   # 安装脚本文本全量提取 (UTF-16 + ASCII)
  python switcher_probe.py records  # 文件安装记录 (目标路径/尺寸) + 载荷鉴别
  python switcher_probe.py cpk      # 内嵌 CPK/@UTF 表解析 (文件清单)
  python switcher_probe.py overlay  # overlay 包装层结构 (载荷边界)
  python switcher_probe.py urls     # URL / 文件路径 / 注册表键普查
  python switcher_probe.py all      # 全部
"""
import os
import re
import sys
import zlib
import struct

BASE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(BASE, "game", "FL23 switcher.exe")


def load():
    with open(TARGET, "rb") as f:   # 只读打开
        return f.read()


def banner(t):
    print("\n" + "=" * 74)
    print(t)
    print("=" * 74)


# ---------------------------------------------------------- PE 解析
def rva_to_off(sections, rva):
    for vs, vsize, raw, rsize in sections:
        if vs <= rva < vs + max(vsize, rsize):
            return rva - vs + raw
    return None


def cmd_pe(b):
    banner("PE 概览 + 节表 + 覆盖数据 + 导入表")
    e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
    print(f"DOS e_lfanew=0x{e_lfanew:X}  PE签名={b[e_lfanew:e_lfanew+4]!r}")
    coff = e_lfanew + 4
    machine, nsec, ts, _, _, optsize, _ = struct.unpack_from("<HHIIIHH", b, coff)
    print(f"machine=0x{machine:04X}  节数={nsec}  时间戳={ts} (0x{ts:X})  "
          f"optsize=0x{optsize:X}")
    opt = coff + 20
    magic = struct.unpack_from("<H", b, opt)[0]
    pe32p = (magic == 0x20B)
    print(f"Optional magic=0x{magic:X} ({'PE32+' if pe32p else 'PE32'})")
    if pe32p:
        entry, imgbase = struct.unpack_from("<IQ", b, opt + 16)
        dd_off = opt + 112
    else:
        entry, imgbase = struct.unpack_from("<II", b, opt + 16)
        dd_off = opt + 96
    ndd = struct.unpack_from("<I", b, dd_off - 4)[0]
    print(f"入口 RVA=0x{entry:X}  ImageBase=0x{imgbase:X}  数据目录数={ndd}")
    secs = []
    sec_off = opt + optsize
    print("\n节表:")
    for i in range(nsec):
        o = sec_off + i * 40
        name = b[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vs, rsize, raw = struct.unpack_from("<IIII", b, o + 8)
        ch = struct.unpack_from("<I", b, o + 36)[0]
        secs.append((vs, vsize, raw, rsize))
        print(f"  {name:<8} VA=0x{vs:08X} vsize=0x{vsize:08X} "
              f"raw=0x{raw:08X} rsize=0x{rsize:08X} ch=0x{ch:08X}")
    body_end = max(raw + rsize for _, _, raw, rsize in secs)
    overlay = len(b) - body_end
    print(f"\n节数据结束=0x{body_end:X}, 文件总长=0x{len(b):X}, "
          f"覆盖数据(overlay)=0x{overlay:X} ({overlay} 字节, "
          f"{100.0 * overlay / len(b):.1f}%)")
    print(f"overlay 头 64B: {b[body_end:body_end + 64].hex(' ').upper()}")
    # 导入表
    imp_rva, imp_size = struct.unpack_from("<II", b, dd_off + 8)  # 第 2 个目录项
    print(f"\n导入目录 RVA=0x{imp_rva:X} size=0x{imp_size:X}")
    o = rva_to_off(secs, imp_rva)
    if o:
        while True:
            ilt, ts2, _, name_rva, _ = struct.unpack_from("<IIIII", b, o)
            if name_rva == 0 and ilt == 0:
                break
            no = rva_to_off(secs, name_rva)
            nm = b[no:no + 40].split(b"\x00")[0].decode("ascii", "replace") \
                if no else "?"
            funcs = []
            lo = rva_to_off(secs, ilt) if ilt else None
            if lo:
                while True:
                    th = struct.unpack_from("<Q" if pe32p else "<I", b, lo)[0]
                    if th == 0:
                        break
                    if not (th >> (63 if pe32p else 31)) & 1:
                        fo = rva_to_off(secs, th & 0x7FFFFFFF)
                        if fo:
                            fn = b[fo + 2:fo + 42].split(b"\x00")[0]
                            funcs.append(fn.decode("ascii", "replace"))
                    lo += 8 if pe32p else 4
                    if len(funcs) > 200:
                        break
            print(f"  {nm}: {funcs}")
            o += 20


# ---------------------------------------------------------- 类型签名
INSTALLER_SIGS = [
    (b"Inno Setup Setup Data", "Inno Setup"),
    (b"zlb\x1a", "Inno Setup zlb 块"),
    (b"NullsoftInst", "NSIS"),
    (b"\x37\x7A\xBC\xAF\x27\x1C", "7-Zip 归档"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip 归档(ASCII变体)"),
    (b"MSCF", "CAB 归档"),
    (b"PK\x03\x04", "ZIP 归档"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2/MSI"),
    (b"InstItClass", "InstalIt 系自研安装器类名"),
    (b"InstallSuccess", "InstalIt 系标记"),
    (b"#InstallDir#", "InstalIt 脚本占位符"),
    (b"_inst%d.exe", "自释放临时安装器模式"),
    (b"CPK ", "CRI CPK 容器"),
    (b"\xff\xfe<\x00", "UTF-16 XML/manifest"),
]


def cmd_sig(b):
    banner("安装器/容器类型签名扫描（全文件）")
    for sig, name in INSTALLER_SIGS:
        i = b.find(sig)
        cnt = b.count(sig)
        if i >= 0:
            print(f"  [命中] {name:<28} sig={sig[:16]!r} 首现@0x{i:X} 共{cnt}次")
        else:
            print(f"  [未中] {name:<28} sig={sig[:16]!r}")
    # MZ 嵌套（自释放/多段 PE）
    mz = []
    i = 0
    while True:
        i = b.find(b"MZ", i)
        if i < 0 or len(mz) > 20:
            break
        if i + 0x3C < len(b):
            try:
                elf = struct.unpack_from("<I", b, i + 0x3C)[0]
                if 0 < elf < 0x400 and b[i + elf:i + elf + 2] == b"PE":
                    mz.append(i)
            except struct.error:
                pass
        i += 2
    print(f"\n嵌套完整 PE (MZ+PE 头): {['0x%X' % x for x in mz]}")


# ---------------------------------------------------------- 字符串
def ascii_strings(b, minlen=5):
    return [(m.start(), m.group().decode("ascii"))
            for m in re.finditer(rb"[ -~]{%d,}" % minlen, b)]


def utf16_strings(b, minlen=4):
    out = []
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, b):
        out.append((m.start(), m.group().decode("utf-16-le")))
    return out


def cmd_strings(b, limit=None):
    banner("全文件字符串普查")
    asc = ascii_strings(b)
    u16 = utf16_strings(b)
    print(f"ASCII {len(asc)} 条, UTF-16LE {len(u16)} 条")
    print("-- UTF-16LE 全部 --")
    for o, s in u16[: (limit or len(u16))]:
        print(f"  0x{o:06X}  {s!r}")
    print("-- ASCII（过滤 API/节名噪声后, 全量）--")
    noise = re.compile(r"^(Get|Set|Reg|Create|Delete|Load|Free|Draw|Select|"
                       r"Bit|Ext|Fill|Combine|Offset|Intersect|Union|"
                       r"IsBad|Multi|Text|Wide|Char|lstr|wsprintf|wvsprintf|"
                       r"Dispatch|Translate|Send|Post|Peek|Wait|Msg|End|Show|"
                       r"Enable|Check|Send|Is|InflateTree|InflateCodes|"
                       r"[A-Z][A-Za-z]*[AW]$)")
    for o, s in asc:
        if noise.match(s):
            continue
        print(f"  0x{o:06X}  {s[:120]!r}")


# ---------------------------------------------------------- zlib 流
def zlib_streams(b):
    out = []
    i = 0
    while i < len(b) - 2:
        cands = [x for x in (b.find(b"\x78\x9c", i), b.find(b"\x78\xda", i),
                             b.find(b"\x78\x01", i)) if x >= 0]
        if not cands:
            break
        p = min(cands)
        try:
            d = zlib.decompressobj()
            out.append((p, d.decompress(b[p:min(p + 8 * 1048576, len(b))])))
            i = p + 2
        except zlib.error:
            i = p + 1
    return out


def _content_tag(data):
    tags = []
    if data[:4] == b"CPK ":
        tags.append("CPK容器")
    if b"@UTF" in data[:512] or b"CpkTocInfo" in data:
        tags.append("CPK/UTF表")
    if re.search(rb"(?:[\x20-\x7e]\x00){8,}", data):
        tags.append("含UTF-16文本")
    if b"Welcome" in data or b"License" in data:
        tags.append("安装向导脚本")
    if b"\x89PNG" in data:
        tags.append("PNG图")
    if b"BM" == data[:2]:
        tags.append("BMP图")
    return "/".join(tags) or "二进制"


def cmd_zlib(b):
    banner("zlib 压缩流全量定位与内容摘要")
    for p, data in zlib_streams(b):
        asc = ascii_strings(data, 5)
        sample = " | ".join(dict.fromkeys(s for _, s in asc[:30]))[:150]
        print(f"  @0x{p:06X} 解压后 {len(data):8d}B  [{_content_tag(data)}]")
        if asc:
            print(f"      串例: {sample}")


# ---------------------------------------------------------- 脚本文本
def cmd_script(b):
    banner("安装脚本/配置文本全量提取（各 zlib 流的 ASCII + UTF-16 串）")
    for p, data in zlib_streams(b):
        asc = ascii_strings(data, 4)
        u16 = utf16_strings(data, 3)
        if not asc and not u16:
            continue
        print(f"\n##### zlib @0x{p:06X} ({len(data)}B) "
              f"ASCII {len(asc)} 条 / UTF-16 {len(u16)} 条 #####")
        for o, s in asc:
            print(f"  A+{o:06X}  {s}")
        for o, s in u16:
            print(f"  U+{o:06X}  {s}")


# ---------------------------------------------------------- CPK/@UTF
def cmd_cpk(b):
    """内嵌 CPK 的 @UTF 表：解表头 + 提取字符串表（含文件名/列名）。"""
    banner("内嵌 CPK / @UTF 表解析（来自 zlib 解压流）")
    for p, data in zlib_streams(b):
        if b"@UTF" not in data:
            continue
        print(f"\n##### zlib @0x{p:06X} ({len(data)}B) #####")
        if data[:4] == b"CPK ":
            print("  外层为标准 CPK 封装 (CPK 头 + @UTF 表)")
        i = data.find(b"@UTF")
        n = 0
        while i >= 0 and n < 16:
            n += 1
            try:
                tsize = struct.unpack_from(">I", data, i + 4)[0]
                (rows_off, strs_off, data_off, tname,
                 ncol, rwidth, nrows) = struct.unpack_from(
                    ">IIIIHHI", data, i + 8)
                # 表名字符串 (位于字符串表, 以 0 字节开头)
                tn = b""
                k = i + strs_off + 1
                while k < len(data) and data[k] != 0:
                    tn += bytes([data[k]])
                    k += 1
                print(f"\n  @UTF表 +0x{i:X}: tsize=0x{tsize:X} "
                      f"表名={tn.decode('ascii', 'replace')!r} "
                      f"{ncol}列×{nrows}行 行宽={rwidth}")
                # 字符串表区 [strs_off, data_off)
                sreg = data[i + strs_off:i + data_off]
                strs = [m.group().decode("utf-8", "replace")
                        for m in re.finditer(rb"[\x20-\x7e\xc0-\xff]{2,}",
                                             sreg)]
                strs = list(dict.fromkeys(strs))
                print(f"  字符串表 {len(sreg)}B, 串 {len(strs)} 条:")
                for s in strs[:200]:
                    print(f"    {s}")
                # 列名即字符串表前几项；行数即文件条目数 (CpkTocInfo)
            except struct.error:
                pass
            i = data.find(b"@UTF", i + 4)


# ---------------------------------------------------------- 安装记录
def cmd_records(b):
    """解析 overlay 内文件安装记录 (目标路径/尺寸) 并鉴别各数据载荷。"""
    banner("文件安装记录与载荷鉴别")
    print("目标路径来自 98/106B 安装记录条目（压缩流解压后检出）; "
          "载荷为各大数据流的解压产物。")
    rec_re = re.compile(rb"\x01\x00\x00\x00[\x5e\x66]\x00[\x00\x01]\x00")
    found = False
    for src, data in zlib_streams(b):
        for m in rec_re.finditer(data):
            found = True
            o = m.start()
            chunk = data[o:o + 120]
            # 目标路径在记录尾部 (NUL 结尾)
            pm = re.search(rb"([A-Za-z][\w\\ ]{3,40}\.[a-z]{2,4})\x00", chunk)
            size = struct.unpack_from("<I", chunk, 22)[0]
            typ = struct.unpack_from("<H", chunk, 4)[0]
            flag = struct.unpack_from("<H", chunk, 6)[0]
            print(f"\n记录 (流@0x{src:05X}+0x{o:X}): "
                  f"目标={pm.group(1).decode() if pm else '?'}")
            print(f"  类型=0x{typ:X} 标志=0x{flag:X} "
                  f"载荷解压尺寸(+22)=0x{size:X} ({size})")
    if not found:
        print("  (未检出记录模式)")
    print("\n--- 数据载荷鉴别 (全部 >=3KB 的解压流) ---")
    for p, data in zlib_streams(b):
        if len(data) < 3000:
            continue
        tag = []
        if data[:4] == b"CPK ":
            tag.append("CRI CPK")
            names = sorted(set(m.group().decode() for m in re.finditer(
                rb"[A-Za-z0-9_\-./ ]{4,45}\.(?:bin|o|txt)", data)))
            tag.append(f"内含 {len(names)} 个 .bin/.o/.txt 文件名")
            print(f"  @0x{p:06X} {len(data):8d}B [{'/'.join(tag)}]")
            print(f"      文件例: {names[:8]}")
            continue
        inner = []
        for magic in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
            q = data.find(magic, 64)
            if q > 0:
                try:
                    dd = zlib.decompressobj()
                    o2 = dd.decompress(data[q:q + 4000000])
                    inner.append((q, len(o2)))
                except zlib.error:
                    pass
        ss = [m.group().decode("ascii", "replace")
              for m in re.finditer(rb"[A-Za-z]{5,}", data[:4000])]
        guess = "高熵二进制 (疑加密/打包块, 含 WESYS 风格标记)"
        if inner:
            guess = f"含嵌套 zlib {inner[:3]}"
        print(f"  @0x{p:06X} {len(data):8d}B [{guess}] 串例: {ss[:6]}")


# ---------------------------------------------------------- overlay 结构
def section_end(b):
    """节数据结束偏移（动态解析）。"""
    e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
    coff = e_lfanew + 4
    nsec, = struct.unpack_from("<H", b, coff + 2)
    optsize, = struct.unpack_from("<H", b, coff + 16)
    sec_off = coff + 20 + optsize
    end = 0
    for i in range(nsec):
        o = sec_off + i * 40
        rsize, raw = struct.unpack_from("<II", b, o + 16)
        end = max(end, raw + rsize)
    return end


def cmd_overlay(b):
    banner("overlay 包装层结构（文件条目表/载荷边界）")
    secs_end = section_end(b)
    ov = b[secs_end:]
    print(f"overlay 长 0x{len(ov):X}")
    print("头 32B :", ov[:32].hex(" ").upper())
    u32s = struct.unpack_from("<8I", ov, 0)
    print("头 u32 :", [f"0x{x:X}" for x in u32s])
    # 扫描 overlay 内的 zlib 流边界（定位包装层条目头）
    zs = []
    i = 0
    while i < len(ov) - 2:
        cands = [x for x in (ov.find(b"\x78\x9c", i), ov.find(b"\x78\xda", i),
                             ov.find(b"\x78\x01", i)) if x >= 0]
        if not cands:
            break
        p = min(cands)
        try:
            d = zlib.decompressobj()
            out = d.decompress(ov[p:min(p + 8 * 1048576, len(ov))])
            used = (len(ov) - p) - len(d.unused_data)
            zs.append((p, len(out), used))
            i = p + used
        except zlib.error:
            i = p + 1
    print(f"\nzlib 流 {len(zs)} 条（相对 overlay 起点）:")
    for p, dl, used in zs:
        pre = ov[max(0, p - 24):p].hex(" ").upper()
        print(f"  +0x{p:06X} 解压 {dl:8d}B  压缩占用 {used:8d}B  前24B: {pre}")


# ---------------------------------------------------------- URL/路径
def cmd_urls(b):
    banner("URL / 文件路径 / 注册表键 普查（原文 + 全部解压流）")
    blobs = [(0, b)] + [(p, d) for p, d in zlib_streams(b)]
    url_re = re.compile(rb"(?:https?://|www\.)[A-Za-z0-9./_%~?&=#\-]+")
    path_re = re.compile(rb"[A-Za-z]:\\[^\x00-\x1f\x22<>|]{3,120}")
    key_re = re.compile(rb"Software\\[^\x00\x22]{5,120}")
    cpk_re = re.compile(rb"[A-Za-z0-9_\-./\\]{1,60}\.(?:cpk|bin|dat|pak|dpk)",
                        re.I)
    seen = set()
    for src, data in blobs:
        for pat, label in ((url_re, "URL"), (path_re, "盘符路径"),
                           (key_re, "注册表"), (cpk_re, "数据文件名")):
            for m in pat.finditer(data):
                s = m.group().decode("ascii", "replace")
                k = (label, s)
                if k not in seen:
                    seen.add(k)
                    print(f"  [{label}] (src@0x{src:X}) {s}")


SECTIONS = {"pe": None, "sig": None, "strings": None, "zlib": None,
            "script": None, "records": None, "cpk": None,
            "overlay": None, "urls": None}


def main():
    try:
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    b = load()
    print(f"目标: {TARGET}\n大小: {len(b)} 字节 (0x{len(b):X})")
    picks = [a for a in sys.argv[1:] if a.lower() in SECTIONS] or ["all"]
    if "all" in picks:
        picks = list(SECTIONS)
    for p in picks:
        {"pe": cmd_pe, "sig": cmd_sig, "strings": cmd_strings,
         "zlib": cmd_zlib, "script": cmd_script, "records": cmd_records,
         "cpk": cmd_cpk, "overlay": cmd_overlay, "urls": cmd_urls}[p](b)
    print("\n完成。")


if __name__ == "__main__":
    main()
