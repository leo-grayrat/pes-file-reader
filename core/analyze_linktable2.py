#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""选项 C 聚焦分析 v2：
- 过滤真实关联记录(count∈[11,30])
- h3/h4 是否 = 某个 entry 的 a(源球员=图中节点) 或 c
- c 是否指向文件偏移(解引用)
- v 是枚举/指针/打包值
- 同一 a 是否恒定映射到同一 c(规范化 id)
- 收集全局 a/c 命名空间，与 h3/h4 比对
"""
import os, struct, csv
from collections import Counter

DEC = "decoded"; OUT = "outputs"; TAG = "ML00000000"
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
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
    tags=[i for i in range(len(b)-1) if b[i]==0xE5 and b[i+1]==0x07]
    recs=[]
    for i in range(len(tags)-1):
        if tags[i+1]-tags[i]==596:
            o=tags[i]; hdr=[u32(b,o+j*4) for j in range(8)]
            if 11<=hdr[2]<=30:   # 过滤真实关联记录
                recs.append((o,hdr))
    print(f"[*] 真实关联记录(11<=count<=30): {len(recs)}")

    # 收集所有 entry 的 a 与 c (16B 布局)
    all_a=set(); all_c=set(); a_to_c={}; val_dist=Counter()
    src_recs=[]  # (h3,h4)
    for o,hdr in recs:
        h3,h4,h5,h6,h7=hdr[3],hdr[4],hdr[5],hdr[6],hdr[7]
        src_recs.append((h3,h4,h5,h6,h7))
        cnt=hdr[2]; base=o+32
        for k in range(cnt):
            a=u32(b,base+k*16); z=u32(b,base+k*16+4)
            c=u32(b,base+k*16+8); v=u32(b,base+k*16+12)
            if z!=0: continue
            all_a.add(a); all_c.add(c); a_to_c.setdefault(a,set()).add(c)
            val_dist[v]+=1
    print(f"[*] 全局 entry a 去重={len(all_a)}  c 去重={len(all_c)}")

    # h3/h4 是否在 a/c 命名空间
    h3s={r[0] for r in src_recs}; h4s={r[1] for r in src_recs}
    print(f"\n=== h3/h4 命名空间比对 ===")
    print(f"  h3 命中 entry-a 集合: {len(h3s & all_a)}/{len(h3s)}")
    print(f"  h3 命中 entry-c 集合: {len(h3s & all_c)}/{len(h3s)}")
    print(f"  h4 命中 entry-a 集合: {len(h4s & all_a)}/{len(h4s)}")
    print(f"  h4 命中 entry-c 集合: {len(h4s & all_c)}/{len(h4s)}")

    # 收集全部 h3/h4 各自取值范围
    print(f"  h3 范围 [{min(h3s)},{max(h3s)}] distinct={len(h3s)}  h4 范围 [{min(h4s)},{max(h4s)}] distinct={len(h4s)}")
    print(f"  h5 distinct={len({r[2] for r in src_recs})}  h6 distinct={len({r[3] for r in src_recs})}  h7 distinct={len({r[4] for r in src_recs})}")

    # c 是否像文件偏移? 取前若干 c 解引用看是否像 id
    print(f"\n=== c 字段是否文件偏移(解引用) ===")
    sample_c=list(all_c)[:8]
    for c in sample_c:
        if 0<c<len(b)-4:
            dv=u32(b,c)
            print(f"    c={c:#x}({c}): @offset->u32={dv:#x} 似editid={dv in ids}")
        else:
            print(f"    c={c:#x}({c}): 越界(不像偏移)")

    # 同一 a 是否恒定映射到同一 c
    multi=sum(1 for a,s in a_to_c.items() if len(s)>1)
    print(f"\n=== a→c 规范化 ===")
    print(f"  a 出现记录数(去重 c>1 的)={multi}/{len(a_to_c)}  -> {'恒定映射' if multi==0 else '部分 a 映射到多个 c(动态/不唯一)'}")

    # v 值分布: 小枚举 vs 大值
    print(f"\n=== entry v 值语义 ===")
    small=sum(n for v,n in val_dist.items() if v<=7)
    mid=sum(n for v,n in val_dist.items() if 8<=v<=100)
    big=sum(n for v,n in val_dist.items() if v>100)
    print(f"  v∈[0,7]={small}  v∈[8,100]={mid}  v>100={big}  总={sum(val_dist.values())}")
    print(f"  v 最常见 10 个: {val_dist.most_common(10)}")
    # v 高位分析: 是否按位打包
    hi=sum(1 for v in val_dist if v & 0xFFFF0000)
    print(f"  v 高16位非0 的占比: {hi}/{len(val_dist)}")

    # h3/h4 是否像 '源球员在 entry-a 里出现' -> 图结构
    # 即: 某个 h3 是否也作为某条记录的 entry-a 出现
    print(f"\n=== 图结构测试 ===")
    h3_in_a=len(h3s & all_a); h4_in_a=len(h4s & all_a)
    print(f"  h3 中有 {h3_in_a} 个也作为某 entry 的 a 出现过 (图节点复用)")
    print(f"  h4 中有 {h4_in_a} 个也作为某 entry 的 a 出现过")

if __name__=="__main__":
    main()
