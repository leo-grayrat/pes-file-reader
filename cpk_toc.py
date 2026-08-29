#!/usr/bin/env python3
"""Count files in a CRI CPK by reading its TOC (File table) only — no extraction.
Strategy: locate the TOC UTF table (the one whose string area contains the
schema names CpkTocInfo/FileName), then count file-entry strings that look
like filenames. Validated against dt00_4K_x64.cpk (known 9 files)."""
import struct, re, sys, os

def find_toc(b):
    """Return (toc_start_off, table_size) for the file-table UTF."""
    # The real TOC contains schema names "CpkTocInfo" and "FileName"
    i = b.find(b"CpkTocInfo")
    if i < 0:
        i = b.find(b"FileName")
    if i < 0:
        return None, None
    # back up to the enclosing @UTF
    j = b.rfind(b"@UTF", 0, i)
    if j < 0:
        return None, None
    if b[j:j+4] != b"@UTF":
        return None, None
    size = struct.unpack_from("<I", b, j+4)[0]
    return j, size

def extract_names(tbl):
    """From a TOC UTF table, pull every NUL-terminated string in the table."""
    names = []
    i = 0
    n = len(tbl)
    while i < n:
        c = tbl[i]
        if 32 <= c < 127:
            s = i
            while i < n and 33 <= tbl[i] < 127:
                i += 1
            if i - s >= 3:
                names.append(tbl[s:i].decode("latin1"))
            i += 1  # skip the NUL
        else:
            i += 1
    return names

def is_filename(s):
    return ("/" in s or "\\" in s or "." in s) and len(s) < 200

def main():
    path = sys.argv[1]
    fsize = os.path.getsize(path)
    with open(path, "rb") as f:
        # read first 200 MB (TOC sits near end for CPK); also read tail
        head = f.read(200 << 20)
    toc, size = find_toc(head)
    if toc is None:
        print("no TOC found in first 200MB")
        return
    tbl = head[toc:toc+size] if size and size < len(head) else head[toc:toc+ (size or 2000)]
    names = extract_names(tbl)
    files = [x for x in names if is_filename(x)]
    # drop the schema column names (they also contain letters/dots sometimes)
    schema_terms = {"CpkTocInfo","DirName","FileName","FileSize","ExtractSize",
                    "FileOffset","ID","UserString","common/menu/font"}
    files = [x for x in files if x not in schema_terms]
    print("file:", os.path.basename(path))
    print("size on disk:", fsize)
    print("toc @", hex(toc), "table_size", size)
    print("total filename-like strings:", len(files))
    print("--- first 20 entries ---")
    for x in files[:20]:
        print("  ", x)
    print("--- last 10 entries ---")
    for x in files[-10:]:
        print("  ", x)

if __name__ == "__main__":
    main()
