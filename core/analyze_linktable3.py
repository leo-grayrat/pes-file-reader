#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选项 C 聚焦分析 v3 —— 核心假设: h3/h4 = 队/赛事分组键。
把每条真实记录的 entry-a(EDIT球员) 与该队阵容 CSV 做归属比对:
若同一 h3 组内的 a 高度集中于某一队 -> h3=队id, 记录=该队球员分组(注册/租借/青训)。
同时统计 c 分布与 v 与队规模的关系。"""
import os, struct, csv
from collections import Counter, defaultdict

DEC="decoded"; OUT="outputs"; TAG="ML00000000"
def u32(b,o): return struct.unpack_from("<I",b,o)[0]

def load_squad():
    """返回 player_id -> set(ml_idx), 以及 ml_idx -> name"""
    p2t=defaultdict(set); t2n={}
    p=os.path.join(OUT,f"parsed_ml_team_squads_{TAG}.csv")
    with open(p,encoding="utf-8") as f:
        for r in csv.DictReader(f):
            pid=int(r["player_id"]); idx=int(r["ml_idx"]); nm=r["name_cn"]
            p2t[pid].add(idx); t2n[idx]=nm
    return p2t, t2n

def load_edit_ids():
    s=set()
    p=os.path.join(OUT,"parsed_edit_players_EDIT00000000.csv")
    if os.path.exists(p):
        with open(p,encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try: s.add(int(r["player_id"]))
                except (ValueError,KeyError): pass
    return s

def main():
    b=open(os.path.join(DEC,TAG+".data"),"rb").read()
    ids=load_edit_ids()
    p2t,t2n=load_squad()
    print(f"[*] edit_ids={len(ids)}  squad players(mapped)={len(p2t)}  teams={len(t2n)}")

    tags=[i for i in range(len(b)-1) if b[i]==0xE5 and b[i+1]==0x07]
    recs=[]
    for i in range(len(tags)-1):
        if tags[i+1]-tags[i]==596:
            o=tags[i]; hdr=[u32(b,o+j*4) for j in range(8)]
            if 11<=hdr[2]<=30:
                recs.append((o,hdr))
    print(f"[*] 真实关联记录: {len(recs)}")

    # 按 h3 分组, 收集 entry-a(仅 edit id) -> 其所属队
    h3_to_teams=defaultdict(Counter)   # h3 -> Counter(team_idx)
    h3_to_players=defaultdict(list)
    c_dist=Counter(); v_in_team=Counter()
    for o,hdr in recs:
        h3=hdr[3]; cnt=hdr[2]; base=o+32
        for k in range(cnt):
            a=u32(b,base+k*16); z=u32(b,base+k*16+4)
            c=u32(b,base+k*16+8); v=u32(b,base+k*16+12)
            if z!=0: continue
            if a in ids:
                h3_to_players[h3].append(a)
                for t in p2t.get(a,()):
                    h3_to_teams[h3][t]+=1
                c_dist[c]+=1

    print(f"\n=== c 分布 (216 类, 取前 15) ===")
    print("  ", c_dist.most_common(15))

    # 对每个 h3 组, 看其 a 球员是否集中到单一队
    print(f"\n=== h3 分组 -> 队归属集中度 (取记录最多的 12 个 h3) ===")
    for h3,_ in Counter({h:sum(h3_to_teams[h].values()) for h in h3_to_teams}).most_common(12):
        tc=h3_to_teams[h3]
        top=tc.most_common(3)
        tot=sum(tc.values())
        topstr="; ".join(f"队#{t}({t2n.get(t,'?')}):{n}" for t,n in top)
        print(f"  h3={h3:>11}: 球员-队归属 {tot} 次, Top3 -> {topstr}")

    # 量化: 同一 h3 组内, 最大队占比 (若>70% 则 h3≈队id)
    ratios=[]
    for h3,tc in h3_to_teams.items():
        if not tc: continue
        tot=sum(tc.values()); mx=max(tc.values())
        ratios.append(mx/tot)
    import statistics
    print(f"\n=== 集中度统计: 最大队占该 h3 组比例 ===")
    print(f"  中位数={statistics.median(ratios):.2f} 均值={statistics.mean(ratios):.2f} "
          f"≥0.7 的组占比={sum(1 for r in ratios if r>=0.7)/len(ratios):.2f} 组数={len(ratios)}")

    # 也测 h4 分组
    h4_to_teams=defaultdict(Counter)
    for o,hdr in recs:
        h4=hdr[4]; cnt=hdr[2]; base=o+32
        for k in range(cnt):
            a=u32(b,base+k*16); z=u32(b,base+k*16+4)
            if z!=0: continue
            a=u32(b,base+k*16)
            if a in ids:
                for t in p2t.get(a,()): h4_to_teams[h4][t]+=1
    r4=[max(tc.values())/sum(tc.values()) for tc in h4_to_teams.values() if tc]
    print(f"  [对照] h4 分组最大队占比 中位数={statistics.median(r4):.2f} ≥0.7占比={sum(1 for r in r4 if r>=0.7)/len(r4):.2f}")

if __name__=="__main__":
    main()
