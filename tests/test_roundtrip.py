#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
解密→加密 roundtrip 回归测试。

对 examples/ 下各类型样本（BL / ML / rep/REPLAY 各一个）执行：
  1. decrypt → 断言文件头字段合理（fileTypeString 匹配类型、
     320 + 208 + descSize + logoSize + dataSize + serialLength*2 与文件总长吻合）；
  2. encrypt → 断言输出与原文件逐字节一致。

样本缺失时跳过（@skipIf）而非报错。纯标准库，可在仓库根目录直接运行：
  python -m unittest discover tests
  python tests/test_roundtrip.py
"""
import os
import sys
import unittest

# 路径一律由 __file__ 推导，兼容任意工作目录
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
EX_DIR = os.path.join(ROOT, "examples")

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pes_decrypt as p  # noqa: E402

# (相对 examples/ 的样本路径, 期望的 fileTypeString)
SAMPLES = {
    "BL": os.path.join("BL00000000"),
    "ML": os.path.join("ML00000000"),
    "REPLAY": os.path.join("rep", "REPLAY00000000"),
}


def sample_path(expected_type):
    return os.path.join(EX_DIR, SAMPLES[expected_type])


def have_sample(expected_type):
    return os.path.isfile(sample_path(expected_type))


def _cstr(buf):
    """取 NUL 填充定长串的有效部分（返回 str）。"""
    return buf.split(b"\x00")[0].decode("ascii", errors="replace")


class RoundtripTest(unittest.TestCase):
    """decrypt → encrypt roundtrip，输出须与原文件逐字节一致。"""

    def _roundtrip(self, expected_type):
        path = sample_path(expected_type)
        with open(path, "rb") as f:
            blob = f.read()

        r = p.decrypt(blob)
        re_blob = p.encrypt(r)
        self.assertEqual(
            re_blob, blob,
            msg=f"{expected_type}: encrypt(decrypt(x)) 与原文件不一致",
        )

    @unittest.skipIf(not have_sample("BL"), "缺少样本 examples/BL00000000")
    def test_roundtrip_bl(self):
        self._roundtrip("BL")

    @unittest.skipIf(not have_sample("ML"), "缺少样本 examples/ML00000000")
    def test_roundtrip_ml(self):
        self._roundtrip("ML")

    @unittest.skipIf(not have_sample("REPLAY"), "缺少样本 examples/rep/REPLAY00000000")
    def test_roundtrip_replay(self):
        self._roundtrip("REPLAY")


class FileHeaderTest(unittest.TestCase):
    """解密后文件头字段合理性检查。"""

    def _check_header(self, expected_type):
        path = sample_path(expected_type)
        with open(path, "rb") as f:
            blob = f.read()

        r = p.decrypt(blob)
        h = r["hdr"]

        # fileTypeString 与文件类型匹配
        self.assertEqual(_cstr(h["fileTypeString"]), expected_type)

        # gameVersionString 应为 PES2021
        self.assertIn("PES 2021", _cstr(h["gameVersionString"]))

        # 各块长度非负（无符号，天然成立）且 data 块长度与头声明一致
        self.assertEqual(len(r["description"]), h["descSize"])
        self.assertEqual(len(r["logo"]), h["logoSize"])
        self.assertEqual(len(r["data"]), h["dataSize"])
        self.assertEqual(len(r["serial"]), h["serialLength"] * 2)

        # 320 + 208 + descSize + logoSize + dataSize + serialLength*2 与文件总长吻合
        total = (p.ENCRYPTION_HEADER_SIZE + p.FILE_HEADER_SIZE
                 + h["descSize"] + h["logoSize"] + h["dataSize"]
                 + h["serialLength"] * 2)
        self.assertEqual(total, len(blob))
        self.assertEqual(r["consumed"], len(blob))

    @unittest.skipIf(not have_sample("BL"), "缺少样本 examples/BL00000000")
    def test_header_bl(self):
        self._check_header("BL")

    @unittest.skipIf(not have_sample("ML"), "缺少样本 examples/ML00000000")
    def test_header_ml(self):
        self._check_header("ML")

    @unittest.skipIf(not have_sample("REPLAY"), "缺少样本 examples/rep/REPLAY00000000")
    def test_header_replay(self):
        self._check_header("REPLAY")


if __name__ == "__main__":
    unittest.main(verbosity=2)
