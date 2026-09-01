#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选项 C 收尾: 单队内子表结构 + v 随 c 的规律。
取 3 个代表队(h3), dump 其全部记录: h4 取值、entry(a,c,v)、同球员是否跨记录重复。"""
import os, struct, csv
from collections import Counter, defaultdict
DEC="decoded"; OUT="outputs"; TAG="ML00000000"
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def load_edit_names():
    d={}
    p=os.path.join(OUT,"parsed_edit_players_EDIT00000000.csv")
    if os.path.exists(p):
        with open(p,encoding="utf-8") as f:
            for r in csv.DictReader(f):
                try: d[int(r["player_id"])]=r.get("name","?")
                except (ValueError,KeyError): pass
    return d
def load_squad():
    p2t=defaultdict(set); t2n={}
    with open(os.path.join(OUT,f"parsed_ml_team_squads_{TAG}.csv"),encoding="utf-8") as f:
        for r in csv.DictReader(f):
            p2t[int(r["player_id"])].add(int(r["ml_idx"])); t2n[int(r["ml_idx"])]=r["name_cn"]
    return p2t,t2n

def main():
    b=open(os.path.join(DEC,TAG+".data"),"rb").read()
    p2t,t2n=load_squad(); enames=load_edit_names()
    tags=[i for i in range(len(b)-1) if b[i]==0xE5 and b[i+1]==0x07]
    recs=[]
    for i in range(len(tags)-1):
        if tags[i+1]-tags[i]==596:
            o=tags[i]; hdr=[u32(b,o+j*4) for j in range(8)]
            if 11<=hdr[2]<=30: recs.append((o,hdr))
    # 按 h3 聚合
    by_h3=defaultdict(list)
    for o,hdr in recs:
        cnt=hdr[2]; base=o+32; ents=[]
        for k in range(cnt):
            a=u32(b,base+k*16); z=u32(b,base+k*16+4)
            c=u32(b,base+k*16+8); v=u32(b,base+k*16+12)
            if z==0: ents.append((a,c,v))
        by_h3[hdr[3]].append((hdr,ents))

    # 选 3 个代表队(记录数多)
    pick=sorted(by_h3.items(), key=lambda kv:-len(kv[1]))[:3]
    for h3,lst in pick:
        # 该队主导队
        tc=Counter()
        for hdr,ents in lst:
            for a,c,v in ents:
                if a in p2t:
                    for t in p2t[a]: tc[t]+=1
        dom=tc.most_common(1)[0]
        print(f"\n########## h3={h3}  子表数={len(lst)}  主导队=队#{dom[0]}({t2n.get(dom[0],'?')}) 占{dom[1]} ##########")
        # h4 取值集合
        h4s=set(hdr[4] for hdr,_ in lst)
        print(f"  h4 取值({len(h4s)}种): {sorted(h4s)[:12]}")
        # 球员跨子表重复情况
        play2recs=defaultdict(int)
        for _,ents in lst:
            seen=set()
            for a,c,v in ents:
                if a in p2t: seen.add(a)
            for a in seen: play2recs[a]+=1
        repeat=sum(1 for a,n in play2recs.items() if n>1)
        print(f"  该队唯一球员(在squad中)={len(play2recs)}  跨>=2子表重复的={repeat}")
        # 展示前 2 条子表
        for ri,(hdr,ents) in enumerate(lst[:2]):
            print(f"  -- 子表[{ri}] h4={hdr[4]} h5={hdr[5]} h6={hdr[6]} h7={hdr[7]} count={hdr[2]} --")
            for a,c,v in ents[:6]:
                nm=enames.get(a, f"id{a}")
                print(f"       a={a}({nm[:12]}) c={c} v={v}")

    # v 随 c 的规律: 取 top5 c, 看其 v 分布
    print("\n=== v 随 c(链接类型) 的取值规律 (top6 c) ===")
    c2v=defaultdict(list)
    for o,hdr in recs:
        cnt=hdr[2]; base=o+32
        for k in range(cnt):
            a=u32(b,base+k*16); z=u32(b,base+k*16+4)
            c=u32(b,base+k*16+8); v=u32(b,base+k*16+12)
            if z==0: c2v[c].append(v)
    for c,_ in Counter({c:len(v) for c,v in c2v.items()}).most_common(6):
        vs=c2v[c]
        small=sum(1 for x in vs if x<=100); ffff=sum(1 for x in vs if x==65535)
        print(f"  c={c}: n={len(vs)} v==0xFFFF:{ffff} v<=100:{small} 其他样例={sorted(set(vs))[:6]}")

if __name__=="__main__":
    main()
