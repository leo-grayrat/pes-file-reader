#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选项 C 收尾判别:
(1) h4 取值是否全部 ∈ h3 集合 (确认 h4 也是队 id)
(2) 记录(h3=A,h4=B)列出的球员 a 归 A / 归 B / 共有?
(3) 每个 h3 的"对手 h4 数"与"子表数"关系
"""
import os, struct, csv
from collections import Counter, defaultdict
DEC="decoded"; OUT="outputs"; TAG="ML00000000"
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def load_squad():
    p2t=defaultdict(set)
    with open(os.path.join(OUT,f"parsed_ml_team_squads_{TAG}.csv"),encoding="utf-8") as f:
        for r in csv.DictReader(f):
            p2t[int(r["player_id"])].add(int(r["ml_idx"]))
    return p2t

def main():
    b=open(os.path.join(DEC,TAG+".data"),"rb").read()
    p2t=load_squad()
    tags=[i for i in range(len(b)-1) if b[i]==0xE5 and b[i+1]==0x07]
    recs=[]
    for i in range(len(tags)-1):
        if tags[i+1]-tags[i]==596:
            o=tags[i]; hdr=[u32(b,o+j*4) for j in range(8)]
            if 11<=hdr[2]<=30:
                cnt=hdr[2]; base=o+32; ents=[]
                for k in range(cnt):
                    a=u32(b,base+k*16); z=u32(b,base+k*16+4)
                    c=u32(b,base+k*16+8); v=u32(b,base+k*16+12)
                    if z==0: ents.append((a,c,v))
                recs.append((hdr,ents))
    h3set=set(h[3] for h,_ in recs)
    h4set=set(h[4] for h,_ in recs)
    print(f"[*] 真实记录={len(recs)}  h3 去重={len(h3set)}  h4 去重={len(h4set)}")
    print(f"[*] h4 ⊆ h3 ?  {len(h4set & h3set)}/{len(h4set)}  ({100*len(h4set&h3set)/max(1,len(h4set)):.1f}%)")

    # 每记录: 球员 a 归 A(h3) / 归 B(h4) / 共有
    own=0; opp=0; both=0; neither=0; tot=0
    per_team_opp=defaultdict(set); per_team_sub=defaultdict(int)
    for h,ents in recs:
        A=h[3]; B=h[4]; per_team_opp[A].add(B); per_team_sub[A]+=1
        for a,c,v in ents:
            if a not in p2t: continue
            teams=p2t[a]
            inA=A in teams; inB=B in teams
            tot+=1
            if inA and inB: both+=1
            elif inA: own+=1
            elif inB: opp+=1
            else: neither+=1
    print(f"\n=== 列出球员 a 的归属 (对上阵容CSV的 {tot} 条) ===")
    print(f"  仅归本队A(h3): {own} ({100*own/max(1,tot):.1f}%)")
    print(f"  仅归对手B(h4): {opp} ({100*opp/max(1,tot):.1f}%)")
    print(f"  A与B共有:      {both} ({100*both/max(1,tot):.1f}%)")
    print(f"  都不归(其它队): {neither} ({100*neither/max(1,tot):.1f}%)")

    # 每队对手数 vs 子表数
    import statistics
    oppn=[len(v) for v in per_team_opp.values()]
    subn=list(per_team_sub.values())
    print(f"\n=== 每队: 对手h4数 中位数={statistics.median(oppn):.0f} 均值={statistics.mean(oppn):.1f}; 子表数 中位数={statistics.median(subn):.0f} 均值={statistics.mean(subn):.1f} ===")
    # 子表数 ≈ 对手数?
    same=sum(1 for A in per_team_opp if per_team_sub[A]==len(per_team_opp[A]))
    print(f"  子表数==对手数 的队占比: {same}/{len(per_team_opp)}")

if __name__=="__main__":
    main()
