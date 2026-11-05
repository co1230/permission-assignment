"""
给 V1 灌入演示数据（开发/演示前用）：
用小孔账号把 test_files/ 里的素材逐个上传，服务端会自动加密并入库。

运行：python tests/seed_v1.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e_v1 import BASE, ROOT, login, upload  # noqa: E402


def main() -> None:
    token = login("xiaokong", "xiaokong123")
    files = sorted(p for p in (ROOT / "test_files").iterdir() if p.suffix != ".json")
    for path in files:
        data, raw = upload(token, path)
        print(f"  {path.name:18s} → {data['category']}  {data['cipher_size_text']}")
    print(f"\n共 {len(files)} 个文件已上传，服务地址 {BASE}")


if __name__ == "__main__":
    main()
