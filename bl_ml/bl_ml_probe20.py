#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bl_ml_probe20.py — 通过 RTTI type_info name 指针定位 MLAccounting* 类的虚表。

思路：C++ type_info 结构含 name 字段（指向类名串）。搜索 .rdata 中指向目标类名串的
8 字节指针，反推 type_info 起始，再读其 vptr 得到 vtable，列出虚函数地址。
"""
import struct

EXE = "game/FL_2023.exe"
IMAGE_BASE = 0x140000000
TARGETS = {
    "MLAccountingTransferFeeDetail": 0x0265AB90,
    "MLAccountingSalaryDetail": 0x0265ABE8,
    "ML/MLSeasonSalary": 0x0265AC40,
    "ML/MLBudgetReport": 0x0265ACB8,
    "ML/MLBudgetSetting": 0x0265AC80,
    "Common/CmnFinanceReport": 0x0265AD68,
}

def main():
    with open(EXE, "rb") as f:
        data = f.read()
    print("searching type_info name pointers for %d targets..." % len(TARGETS))
    for name, rva in TARGETS.items():
        va = IMAGE_BASE + rva
        # 两种指针形式都可能：绝对 VA 或 不带 base 的 RVA
        pats = {
            "VA": struct.pack("<Q", va),
            "RVA": struct.pack("<Q", rva),
        }
        print("\n=== %s (rva=0x%X) ===" % (name, rva))
        found = []
        for label, pat in pats.items():
            pos = 0
            while True:
                i = data.find(pat, pos)
                if i < 0:
                    break
                found.append((label, i))
                pos = i + 1
        if not found:
            print("  无 name 指针命中")
            continue
        for label, i in found[:6]:
            # type_info: { vptr(8) ; spare(4) ; name(8) }  -> name 在 offset 12（8+4 对齐）
            # 也可能 name 紧跟 offset 8 / 16；尝试 -8/-12/-16
            for off in (8, 12, 16):
                ti = i - off
                if ti >= 0:
                    vptr = struct.unpack_from("<Q", data, ti)[0]
                    if vptr >= IMAGE_BASE and vptr < 0x150000000:
                        print("  [%s] name_ptr@0x%X  type_info@0x%X (rel %d)  vptr=0x%X -> vtable" % (
                            label, i, ti, off, vptr))
                        # dump vtable 前 8 个函数
                        if vptr < len(data):
                            funcs = [struct.unpack_from("<Q", data, vptr + k*8)[0]
                                     for k in range(10)]
                            print("    vtable funcs: " + " ".join("0x%X" % f for f in funcs))

if __name__ == "__main__":
    main()
