#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ct_fieldmap.py —— 从社区 Cheat Table（PES 2021 v21.1.0）导出游戏内对象字段布局。
CT 表把社区逆向成果（字段名 + 偏移 + 类型）明文保存，是"免费的字段字典"。
导出 outputs/pes_player_fieldmap.md 供存档/EDIT 字段解读对照。
"""
import os, re
from collections import defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CT = os.path.join(BASE, "resources", "CT", "PES 2021 - v21.1.0 英文版",
                  "PES 2021 - v21.1.0.CT")

def parse_entries(path):
    raw = open(path, "rb").read().decode("utf-8", errors="replace")
    pat = re.compile(r"<Description>(.*?)</Description>(.*?)(?=<Description>|$)", re.S)
    out = defaultdict(list)
    for d, rest in pat.findall(raw):
        desc = d.strip().strip('"')
        am = re.search(r"<Address>(.*?)</Address>", rest, re.S)
        addr = am.group(1).strip() if am else ""
        om = re.search(r"<Offsets>(.*?)</Offsets>", rest, re.S)
        off = ""
        if om:
            oo = re.findall(r"<Offset>(.*?)</Offset>", om.group(1), re.S)
            off = oo[0].strip() if oo else ""
        vm = re.search(r"<VariableType>(.*?)</VariableType>", rest, re.S)
        vtype = vm.group(1).strip() if vm else ""
        if addr and off:
            try:
                ov = int(off, 16)
            except ValueError:
                continue
            out[addr].append((ov, off, vtype, desc))
    return out, raw

def main():
    groups, raw = parse_entries(CT)
    L = []
    L.append("# PES 2021 游戏内对象字段布局（源自社区 Cheat Table）\n")
    L.append(f"- 来源：`resources/CT/PES 2021 - v21.1.0 英文版/PES 2021 - v21.1.0.CT`")
    L.append("- 用途：CT 表是社区逆向的**字段字典**（名称+偏移+类型），可用于反解存档/EDIT 记录。")
    L.append("- 注意：这是**运行时对象**布局，与存档/EDIT 的紧凑序列化**不一一对应**，")
    L.append("  但字段语义与相对顺序可作为解读线索（已成功定位 EDIT 的身高/体重，见 §对照）。\n")

    for base in sorted(groups):
        items = sorted(groups[base], key=lambda x: x[0])
        L.append(f"\n## 基址 `{base}`（{len(items)} 字段）\n")
        L.append("| 偏移 | 类型 | 字段名 |")
        L.append("|---|---|---|")
        seen = set()
        for ov, off, vtype, desc in items:
            key = (off, desc)
            if key in seen:
                continue
            seen.add(key)
            L.append(f"| `+{off}` | {vtype} | {desc} |")

    # AOB 签名清单
    L.append("\n\n## AOB 签名（aobscanmodule）\n")
    L.append("| 签名名 |")
    L.append("|---|")
    for m in re.findall(r"aobscanmodule\(\s*([A-Za-z0-9_]+)\s*,", raw):
        L.append(f"| `{m}` |")

    outp = os.path.join(BASE, "outputs", "pes_player_fieldmap.md")
    open(outp, "w", encoding="utf-8").write("\n".join(L) + "\n")
    print(f"导出 -> {outp}")
    for base in sorted(groups):
        print(f"  {base}: {len(groups[base])} 字段")

if __name__ == "__main__":
    main()
