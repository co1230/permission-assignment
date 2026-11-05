"""重建交付压缩包。

只打包项目交付所需内容，排除以下三类：
  1. 隐藏目录（版本控制、编辑器与本地工具配置）与打包产物 release
  2. 运行时数据（数据库 / 密文 / 密钥包 / 会话令牌）
  3. 编译缓存 __pycache__ 与 .pyc

用法：python tools/build_release.py
"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE_DIR = ROOT / "release"
ZIP_NAME = "文件加密与权限隔离-双版本演示.zip"
STAGING = RELEASE_DIR / "_staging"

# 顶层整目录排除（以 . 开头的隐藏目录一律跳过，无需逐个列举）
EXCLUDE_DIRS = {"release"}
# 任意层级排除的目录名
EXCLUDE_ANY_DIR = {"__pycache__", "data"}
# 任意层级排除的文件名 / 后缀
EXCLUDE_SUFFIX = {".pyc", ".key.json", ".envelope.json", ".tokens.json"}


def keep(path: Path) -> bool:
    if any(part.startswith(".") for part in path.parts):
        return False
    if path.name in EXCLUDE_SUFFIX or path.name.endswith(".pyc"):
        return False
    if any(part in EXCLUDE_ANY_DIR for part in path.parts):
        return False
    return True


def build() -> Path:
    if STAGING.exists():
        shutil.rmtree(STAGING)
    STAGING.mkdir(parents=True)

    for item in ROOT.iterdir():
        if item.name in EXCLUDE_DIRS or item.name.startswith("."):
            continue
        dest = STAGING / item.name
        if item.is_dir():
            shutil.copytree(
                item,
                dest,
                ignore=shutil.ignore_patterns(*EXCLUDE_ANY_DIR, "__pycache__", "*.pyc"),
            )
        else:
            shutil.copy2(item, dest)

    zip_path = RELEASE_DIR / ZIP_NAME
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for p in sorted(STAGING.rglob("*")):
            if p.is_file() and keep(p.relative_to(STAGING)):
                zf.write(p, p.relative_to(STAGING))
    shutil.rmtree(STAGING)
    return zip_path


def audit(zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
    leaks = [
        n for n in names
        if n.startswith(".") or "__pycache__" in n or n.endswith((".pyc", ".key.json", ".envelope.json"))
    ]
    print(f"压缩包：{zip_path}")
    print(f"文件数：{len(names)}  大小：{zip_path.stat().st_size / 1024 / 1024:.2f} MB")
    print(f"敏感 / 缓存条目：{'无' if not leaks else leaks}")


if __name__ == "__main__":
    audit(build())
