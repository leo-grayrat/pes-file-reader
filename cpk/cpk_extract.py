"""
cpk_extract.py —— 基于项目内生 CriWare CPK 库 (tools/CirPakGUI/LibCPK.dll) 的无界面解包器。

用法:
  python cpk_extract.py <cpk路径> [--out DIR] [--filter 子串] [--dry]

- 默认仅提取到 outputs/cpk_extract/（不改动源文件）。
- --dry 只列出文件清单（路径/大小/偏移），不写出。
- --filter 仅提取文件名包含该子串的文件（如 "team" / "transfer"）。

依赖: pythonnet + 同目录的 LibCPK.dll / CriPakGUI.exe（已随项目提供）。
"""

import sys
import os
import argparse

DLL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "tools", "CirPakGUI", "LibCPK.dll")

def load_cpk(cpk_path):
    import clr
    clr.AddReference(DLL)
    from LibCPK import CPK
    import System
    cpk = CPK()
    enc = System.Text.Encoding.UTF8
    ok = cpk.ReadCPK(cpk_path, enc)
    if not ok:
        raise RuntimeError("ReadCPK 返回 False，无法读取该 CPK（可能加密或非 CPK）")
    return cpk

def get_entries(cpk):
    """优先用 fileTable（FileEntry 列表）；退化时用 files(UTF) 反射读取。"""
    # fileTable 字段（List<FileEntry>）
    try:
        tbl = cpk.fileTable
        if tbl is not None and len(tbl) > 0:
            return list(tbl), "fileTable"
    except Exception:
        pass
    # 退化：files 是 UTF 表，逐行读取（需列名）
    raise RuntimeError("未找到 fileTable，请报告（files UTF 路径未实现）")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cpk")
    ap.add_argument("--out", default="outputs/cpk_extract")
    ap.add_argument("--filter", nargs="+", default=[])
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    cpk = load_cpk(args.cpk)
    entries, src = get_entries(cpk)
    print(f"CPK 读取成功（条目来源: {src}），共 {len(entries)} 个文件")

    out_root = args.out
    os.makedirs(out_root, exist_ok=True)
    written = 0
    for e in entries:
        # 跳过 CPK 内部元数据虚拟条目（CPK_HDR/CONTENT_OFFSET/TOC_HDR/ETOC_HDR 等，FileType 非 FILE）
        ftype = e.FileType
        if ftype is not None and str(ftype) != "FILE":
            continue
        name = str(e.FileName)
        dirn = str(e.LocalDir) if e.LocalDir else ""
        rel = os.path.join(dirn, name) if dirn else name
        rel = rel.replace("\\", "/")
        if args.filter and not any(f in rel for f in args.filter):
            continue
        try:
            size = int(e.FileSize)
            exsize = int(e.ExtractSize)
            off = int(e.FileOffset)
        except Exception as ex:
            print(f"  ! 跳过 {rel}: 字段解析失败 {ex}")
            continue
        if args.dry:
            print(f"  {rel}  off={off:#x}  filesize={size:,}  extractsize={exsize:,}  type={e.FileType}")
            continue
        # 从 CPK 读取原始数据
        with open(args.cpk, "rb") as f:
            f.seek(off)
            raw = f.read(size)
        if exsize != size:
            try:
                raw = cpk.DecompressCRILAYLA(raw, exsize)
            except Exception as ex:
                print(f"  ! 解压失败 {rel}: {ex}")
                continue
        dst = os.path.join(out_root, rel)
        os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
        with open(dst, "wb") as f:
            f.write(raw)
        written += 1
    if not args.dry:
        print(f"已写出 {written} 个文件到 {out_root}")

if __name__ == "__main__":
    main()
