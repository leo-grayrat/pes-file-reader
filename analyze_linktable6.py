#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选项 C 语义终判: 单队各子表(h4)的球员集合重叠度。
高重叠=>同一阵容按对手切分; 低重叠=>每对手不同球员(如转会/球探目标)。
同时用 v3 方法把 h3 解析到主导 ml_idx 队名。"""
import os, struct, csv
from collections import defaultdict, Counter
DEC="decoded"; OUT="outputs"; TAG="ML00000000"
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def load_squad():
    p2t=defaultdict(set); t2n={}
    with open(os.path.join(OUT,f"parsed_ml_team_squads_{TAG}.csv"),encoding="utf-8") as f:
        for r in csv.DictReader(f):
            p2t[int(r["player_id"])].add(int(r["ml_idx"])); t2n[int(r["ml_idx"])]=r["name_cn"]
    return p2t,t2n
def load_edit_ids():
    s=set()
    with open(os.path.join(OUT,"parsed_edit_players_EDIT00000000.csv"),encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try: s.add(int(r["player_id"]))
            except (ValueError,KeyError): pass
    return s

def main():
    b=open(os.path.join(DEC,TAG+".data"),"rb").read()
    p2t,t2n=load_squad(); ids=load_edit_ids()
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
                    if z==0: ents.append(a)
                recs.append((hdr,ents))
    # 按 h3 聚合
    by_h3=defaultdict(list)
    for hdr,ents in recs:
        by_h3[hdr[3]].append((hdr,ents))
    # 取几个队, 解析主导队, 算子表间重叠
    pick=sorted(by_h3.items(), key=lambda kv:-len(kv[1]))[:4]
    for h3,lst in pick:
        # 主导队
        tc=Counter()
        for hdr,ents in lst:
            for a in ents:
                if a in ids:
                    for t in p2t.get(a,()): tc[t]+=1
        dom=tc.most_common(1)[0] if tc else (None,0)
        domname=t2n.get(dom[0],'?') if dom[0] is not None else '?'
        # 子表球员集合(仅 edit id)
        sets=[set(a for a in ents if a in ids) for hdr,ents in lst]
        union=set().union(*sets) if sets else set()
        inter=set.intersection(*sets) if sets else set()
        # 平均 pairwise Jaccard
        import itertools,statistics
        jac=[]
        for s1,s2 in itertools.combinations(sets,2):
            if s1|s2: jac.append(len(s1&s2)/len(s1|s2))
        print(f"\nh3={h3} 主导队=队#{dom[0]}({domname}) 子表数={len(lst)} 唯一球员={len(union)}")
        print(f"  所有子表交集大小={len(inter)}  平均 pairwise Jaccard={statistics.mean(jac):.2f} (1=完全相同,0=互不相交)")
        print(f"  各子表球员数: {[len(s) for s in sets[:12]]}")

if __name__=="__main__":
    main()
