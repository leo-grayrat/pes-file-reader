"""
cpk_scan_all.py —— 批量只读 TOC 扫描 D:/Games/SP Football Life/Data 下所有 CPK。
不展开任何数据体，仅解析目录表，定位目标文件（Player.bin / Team.bin / transfer / economy 等）。
输出到 outputs/cpk_scan.txt。
"""
import clr, os, sys, traceback
clr.AddReference(r"D:/File/Git/pes-file-reader/tools/CirPakGUI/LibCPK.dll")
from LibCPK import CPK
import System

DATA = r"D:/Games/SP Football Life/Data"
enc = System.Text.Encoding.UTF8
KEYWORDS = ["Player.bin", "Team.bin", "Transfer", "Economy", "Eco", "Budget", "Salary", "League"]

buf = []
def log(s):
    buf.append(s)
    print(s)

files = sorted(f for f in os.listdir(DATA) if f.lower().endswith(".cpk"))
log(f"# 共发现 {len(files)} 个 CPK（仅解析 TOC，不展开数据）")
log("")

player_bins = []
team_bins = []
match_all = []

for fn in files:
    path = os.path.join(DATA, fn)
    try:
        cpk = CPK()
        ok = cpk.ReadCPK(path, enc)
        if not ok:
            log(f"## {fn}: ReadCPK=False (跳过)")
            continue
        entries = list(cpk.fileTable)
        real = []
        for e in entries:
            try:
                ftype = str(e.FileType)
            except Exception:
                ftype = ""
            if ftype != "FILE":
                continue
            nm = str(e.FileName) if e.FileName else ""
            dirn = str(e.LocalDir) if e.LocalDir else ""
            rel = (dirn + "/" + nm) if dirn else nm
            rel = rel.replace("\\", "/")
            real.append(rel)
        log(f"## {fn}: {len(real)} 个 FILE 条目")
        for rel in real:
            base = os.path.basename(rel)
            if base == "Player.bin":
                player_bins.append((fn, rel))
            if base == "Team.bin":
                team_bins.append((fn, rel))
            rl = rel.lower()
            for kw in KEYWORDS:
                if kw.lower() in rl:
                    match_all.append((fn, rel))
    except Exception as ex:
        log(f"## {fn}: ERROR {ex}")
        traceback.print_exc()

log("")
log("# === Player.bin 精确命中 ===")
if not player_bins:
    log("  (无)")
for fn, rel in player_bins:
    log(f"  {fn} :: {rel}")
log("")
log("# === Team.bin 精确命中 ===")
if not team_bins:
    log("  (无)")
for fn, rel in team_bins:
    log(f"  {fn} :: {rel}")
log("")
log("# === 关键字命中(去重) ===")
seen = set()
for fn, rel in match_all:
    key = (fn, rel)
    if key in seen:
        continue
    seen.add(key)
    log(f"  {fn} :: {rel}")

out = r"D:/File/Git/pes-file-reader/outputs/cpk_scan.txt"
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    f.write("\n".join(buf))
log(f"\n# 写入 {out}")
