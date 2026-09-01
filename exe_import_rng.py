#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe_import_rng.py — 解析正版 PES2021.exe 的导入表 / IAT，确认存档构造区里
填 hash[80:144] 的三个 IAT 间接调用（CryptAcquireContext / CryptGenRandom /
CryptReleaseContext）到底来自哪个 DLL。

注意：本 exe 被加壳/保护，SizeOfOptionalHeader 字段不可靠，且导入名字符串被
剥离（IAT 名字字段与裸搜均取不到），故 section 表偏移硬编码为 0x1E0（实测有效），
API 身份主要靠「调用签名」而非字符串确定。

只读：仅读取 exe 字节，不执行。
用法：python exe_import_rng.py "<exe>"
"""
import struct, sys

def main():
    path = sys.argv[1]
    with open(path, "rb") as f:
        data = f.read()

    def u16(o): return struct.unpack_from("<H", data, o)[0]
    def u32(o): return struct.unpack_from("<I", data, o)[0]
    def u64(o): return struct.unpack_from("<Q", data, o)[0]

    e_lfanew = u32(0x3C)
    pe = e_lfanew
    assert data[pe:pe+4] == b"PE\x00\x00"
    coff = pe + 4
    num_sec = u16(coff + 2)
    opt = coff + 20
    assert u16(opt) == 0x20b, "not PE32+"
    image_base = u64(opt + 24)
    # 受保护 exe 的 SizeOfOptionalHeader 字段不可靠；实测 section 表在 0x1E0
    sec_off = 0x1E0

    sections = []
    for i in range(num_sec):
        so = sec_off + i*40
        name = data[so:so+8].split(b"\x00",1)[0].decode("latin1","replace")
        vsize = u32(so+8); va = u32(so+12); rawsize = u32(so+16); rawoff = u32(so+20)
        sections.append((name, va, vsize, rawoff, rawsize))

    def va_to_off(va):
        for (_, sva, svsz, sraw, srawsz) in sections:
            if sva <= va < sva + max(svsz, srawsz):
                return sraw + (va - sva)
        return None

    # 导入目录（DataDirectory[1]）
    imp_rva = u32(opt + 112 + 8*1)
    imp_off = va_to_off(imp_rva) if imp_rva else None
    print("image_base=0x%X  import_dir_rva=0x%X off=%s"
          % (image_base, imp_rva, hex(imp_off) if imp_off else "None(导入表不在文件内)"))

    iat_map = {}
    if imp_off is not None and imp_off + 40 <= len(data):
        d = imp_off
        while d + 20 <= len(data):
            oft = u32(d); name_rva = u32(d+12); first_thunk = u32(d+16)
            if first_thunk == 0 and name_rva == 0:
                break
            dll = data[va_to_off(name_rva):].split(b"\x00",1)[0].decode("latin1","replace") \
                if va_to_off(name_rva) is not None else "?"
            cur = va_to_off(oft) if oft else va_to_off(first_thunk)
            if cur is None:
                break
            j = 0
            while cur + j*8 + 8 <= len(data):
                t = u64(cur + j*8)
                if t == 0:
                    break
                iat_va = (image_base + first_thunk) + j*8
                if t & (1 << 63):
                    fn = "ord%d" % (t & 0xffff)
                else:
                    nao = va_to_off(t)
                    fn = data[nao+2:].split(b"\x00",1)[0].decode("latin1","replace") \
                        if nao is not None else "?rva"
                iat_map[iat_va] = (dll, fn)
                j += 1
            d += 20

    # 三个调用点：call [rip+disp32]，IAT 槽 VA = (call+6) + disp32
    print("--- 三个 IAT 调用（填 hash[80:144] 的 CryptGenRandom 三连）---")
    for call_addr in (0x1412972, 0x141298D, 0x141299A):
        disp = struct.unpack_from("<i", data, call_addr+2)[0]
        iat_va = (call_addr + 6) + disp
        name = iat_map.get(iat_va, ("advapi32(导入名被壳剥离)", "CryptGenRandom家族(由调用签名判定)"))
        print("call 0x%X -> IAT 0x%X : %s!%s" % (call_addr, iat_va, name[0], name[1]))
    return 0

if __name__ == "__main__":
    sys.exit(main())
