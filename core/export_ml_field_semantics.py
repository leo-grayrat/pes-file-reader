#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""export_ml_field_semantics.py -- 导出 ML 动态字段语义总表 CSV（Phase 1.4）。

把 docs/exe-save-layout.md §7.9.3 ⑲/㉓ 的字段语义表程序化导出为
outputs/ml_field_semantics.csv，供脚本/app 消费。

列：scale(尺度), location(位置), offset, func(关键函数), semantics(语义),
    evidence(证据 §), known(社区已知/此前未知)
"""
import csv
import os
import sys

sys.stdout.reconfigure(encoding="utf-8")
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "outputs")


ROWS = [
    # (scale, location, offset, func, semantics, evidence, known)
    ("每周", "380B 球员对象", "+0x2D", "0x12dcfb0/0x15347c0", "跨赛季递增的周/赛季计数（365 天日期累计）", "⑬⑯", "此前未知"),
    ("每周", "打包槽 [base+pid*4]", "bit0~8", "0x12dcfb0", "9bit 比值（训练因子）", "⑫⑭⑮", "此前未知"),
    ("每周", "打包槽 [base+pid*4]", "bit9~15", "0x12dcfb0", "7bit 分量", "⑫⑭⑮", "此前未知"),
    ("每周", "打包槽 [base+pid*4]", "bit24~27", "0x12dcfb0", "模式位（默认15，备选2）", "⑳", "此前未知"),
    ("每周", "82×192B 周记录数组 [base+0x72b24]", "rec+9/+0x62", "0x1537a80/0x15347c0", "每球员周快照字段", "⑥", "此前未知"),
    ("训练", "焦点对象 [global+0x16ECBE0]", "+0x00~0x07", "0xBBEB10/0xBBEC80", "8 分类训练焦点桶", "⑪", "此前未知"),
    ("训练", "焦点对象 [global+0x16ECBE0]", "+0x0A", "0xBBEB10", "剩余训练点（上限 0x15=21，每周重置）", "⑪", "此前未知"),
    ("训练", "成长系数表 0x1453766", "槽首字节=属性偏移", "0x1533230", "每属性 26 项成长系数（+1500→-1800）", "⑯㉒", "此前未知"),
    ("赛季", "380B 球员对象", "+0x13C&0xF", "0x12e3820", "状态位：3=位图路径、5/6=跳过", "⑳", "此前未知"),
    ("赛季", "每球员槽 [base+pid*8+0x186A4]", "位图", "0x15358e0/0x12de960", "属性位图（0x22222222 标记）", "⑧⑰", "此前未知"),
    ("赛季", "队块", "+0x648", "pesfile.py", "静态俱乐部预算（4 样本同）", "§7.9.1", "社区已知"),
    ("结算", "380B 位打包区", "clamp(旧+Δ,下限,99)", "0x12de6a0/0x1533230", "成长公式：Δ=(槽9bit/100)×开发×衰减×0.5+随机", "⑮", "此前未知"),
    ("注册", "5628B 注册表 [base+0x1049b3c]", "+0x08", "0xB63B00", "激活标志（0x0421413F/0xFFFFFFFF）", "㉓", "此前未知"),
    ("注册", "5628B 注册表", "+0x18", "-", "注册/合同年份（2020/2021）", "㉓", "此前未知"),
    ("注册", "5628B 注册表", "+0x2C/+0x3C", "-", "小计数（状态/档位候选）", "㉓", "此前未知"),
    ("加密", "encHeader", "[0:256]", "0x1413A20 系", "四段 SHA-512 摘要（desc/logo/data/serial）", "§8", "此前未知"),
    ("加密", "encHeader", "[256:320]", "-", "salt=header_key 源", "§8", "此前未知"),
    ("外壳", "FileHeader", "+76 serial", "-", "serial=Windows SID（绑定创建账户）", "§5", "此前未知"),
    # ---- Phase 2/3 新增 ----
    ("成长", "系数索引 edi", "clamp(+0x2D−模式位,0,25)", "0x1533230", "横轴=赛季/年龄进度（+0x2D 逐年+1）", "㉕", "此前未知"),
    ("成长", "系数表 tag 0x0F", "0x0F", "-", "控球 ball_control（EDIT 位打包）", "㉖", "此前未知"),
    ("成长", "系数表 tag 0x13", "0x13", "-", "长传 lofted_pass / 射门 finishing 区段", "㉖", "此前未知"),
    ("成长", "系数表 tag 0x1E", "0x1E", "-", "GK 接球 gk_catching（EDIT 位打包）", "㉖", "此前未知"),
    ("状态", "380B +0x13C&0xF", "值 1..6", "0x12e3820 等", "1/2/3=位图活跃路径、5/6=跳过、4=独立", "㉗", "此前未知"),
    ("状态", "球员 +0x144", "位 0x800000", "0x132b120", "挂牌/状态标志（ML 阵容刷新清除）", "㉙", "此前未知"),
    ("装载", "类型 9（ML）", "0x132b120", "0x132b020/0x22b*", "ML 阵容刷新 + 赛季表推进 + 专属对象族", "㉙", "此前未知"),
    ("装载", "类型 7（BL）", "容器+0x50", "0x13fe100", "球员 380B×2400 直存（与 ML 队块结构不同）", "㉚", "此前未知"),
]


def main():
    path = os.path.join(OUT, "ml_field_semantics.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["scale", "location", "offset", "func", "semantics", "evidence", "known"])
        w.writerows(ROWS)
    print("已导出:", path, f"({len(ROWS)} 行)")


if __name__ == "__main__":
    main()
