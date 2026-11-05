"""
V1 验收脚本：把 test_files/ 里所有格式逐个走一遍"上传 → 服务端解密 → SHA-256 比对"，
再检查权限隔离与"搭建者读库解密"。

前置：V1 服务已启动（默认 http://127.0.0.1:8001）
运行：python tests/acceptance_v1.py
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from e2e_v1 import BASE, ROOT, login, request, upload, check  # noqa: E402

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

DB_PATH = ROOT / "v1_server_key" / "data" / "v1.db"
BLOBS = ROOT / "v1_server_key" / "data" / "blobs"


def size_text(n: int) -> str:
    return f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} B"


def main() -> None:
    print("\n=== V1 全格式验收 ===")
    print(f"服务：{BASE}\n")
    admin = login("xiaozhang", "xiaozhang123")
    user = login("xiaokong", "xiaokong123")

    files = sorted(p for p in (ROOT / "test_files").iterdir() if p.suffix != ".json")
    print(f"{'文件':<20}{'类型':<7}{'原始':>10}{'密文':>10}   解密还原")
    print("-" * 66)

    first: tuple[Path, dict, bytes] | None = None
    for path in files:
        raw = path.read_bytes()
        info, _ = upload(user, path)
        status, plain, _ = request(f"/api/files/{info['id']}/decrypt", token=admin, raw=True)
        same = status == 200 and hashlib.sha256(plain).hexdigest() == hashlib.sha256(raw).hexdigest()
        print(f"{path.name:<20}{info['category']:<7}{size_text(len(raw)):>10}{size_text(info['cipher_size']):>10}"
              f"   {'一致' if same else '不一致'}")
        check(f"{path.name} 加解密往返一致", same)
        if first is None:
            first = (path, info, raw)

    assert first is not None
    path, info, raw = first

    print("\n权限隔离")
    status, data, _ = request(f"/api/files/{info['id']}/decrypt", token=user)
    check("小孔调用解密接口被拒（403）", status == 403, data.get("detail", ""))
    status, _, _ = request("/api/admin/vault", token=user)
    check("小孔读取密钥库被拒（403）", status == 403)

    print("\n搭建者视角（不登录，直接读数据库）")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM files WHERE id = ?", (info["id"],)).fetchone()
        key_b64, nonce_b64, name = row["key_b64"], row["nonce_b64"], row["filename"]
    blob = (BLOBS / f"{info['id']}.enc").read_bytes()
    plain = AESGCM(base64.b64decode(key_b64)).decrypt(
        base64.b64decode(nonce_b64), blob, f"v1|{info['id']}|{name}".encode()
    )
    check("用库里的 key_b64 离线解开密文（V1 缺陷）", plain == raw, f"{name} → {len(plain)}B 明文")

    print(f"\n{len(files)} 种格式 + 权限 + 搭建者视角，全部符合预期。\n")


if __name__ == "__main__":
    sys.exit(main())
