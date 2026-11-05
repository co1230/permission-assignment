"""
V1 端到端测试：验证"服务端持钥"的常规做法，以及它的固有缺陷。

覆盖：
  1. 小孔上传 → 只能看密文，调用解密接口被 403
  2. 小张解密 → 与原始文件逐字节一致（文本 / 二进制都测）
  3. 搭建者视角：直接从 SQLite 读 key_b64，离线解密成功 ← V1 的核心问题
  4. 密文下载回来本身不可读

运行：python tests/e2e_v1.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import mimetypes
import sqlite3
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
BASE = "http://127.0.0.1:8001"
DB_PATH = ROOT / "v1_server_key" / "data" / "v1.db"

PASSED: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        print(f"  FAIL  {name} {detail}")
        raise SystemExit(1)
    PASSED.append(name)
    print(f"  PASS  {name}" + (f"\n        → {detail}" if detail else ""))


def request(path: str, *, method: str = "GET", token: str | None = None,
            payload: dict | None = None, raw: bool = False):
    url = BASE + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            body = res.read()
            return res.status, (body if raw else json.loads(body.decode() or "{}")), dict(res.headers)
    except urllib.error.HTTPError as err:
        body = err.read()
        try:
            parsed = json.loads(body.decode() or "{}")
        except json.JSONDecodeError:
            parsed = {"raw": body[:200]}
        return err.code, parsed, dict(err.headers)


def upload(token: str, path: Path, category: str = "auto"):
    boundary = "----demo" + uuid.uuid4().hex
    filename = path.name
    content = path.read_bytes()
    ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"

    parts: list[bytes] = []
    for name, value in (("category", category),):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
        )
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        f"Content-Type: {ctype}\r\n\r\n".encode()
        + content
        + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)

    req = urllib.request.Request(BASE + "/api/files", data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=60) as res:
        return json.loads(res.read().decode()), content


def login(username: str, password: str) -> str:
    status, data, _ = request("/api/login", method="POST", payload={"username": username, "password": password})
    assert status == 200, data
    return data["token"]


def main() -> None:
    print("\n=== V1 端到端测试 (http://127.0.0.1:8001) ===\n")
    admin = login("xiaozhang", "xiaozhang123")
    user = login("xiaokong", "xiaokong123")

    md = ROOT / "test_files" / "项目说明.md"
    mp4 = ROOT / "test_files" / "演示视频.mp4"

    print("1) 小孔上传并加密")
    info_md, raw_md = upload(user, md)
    check("Markdown 上传成功，类型自动识别为文档", info_md["category"] == "文档", f"ID {info_md['id']}")

    info_mp4, raw_mp4 = upload(user, mp4, category="auto")
    check("MP4 上传成功，类型自动识别为视频", info_mp4["category"] == "视频",
          f"原文 {len(raw_mp4) / 1024 / 1024:.1f} MB → 密文 {info_mp4['cipher_size'] / 1024 / 1024:.1f} MB")

    print("\n2) 小孔没有解密权限")
    status, data, _ = request(f"/api/files/{info_md['id']}/decrypt", token=user)
    check("小孔调用解密接口被拒绝", status == 403, data.get("detail", ""))
    status, data, _ = request("/api/admin/vault", token=user)
    check("小孔读取密钥库被拒绝", status == 403)

    print("\n3) 小张可以解密")
    status, body, headers = request(f"/api/files/{info_md['id']}/decrypt", token=admin, raw=True)
    check("小张解密 Markdown 成功", status == 200 and body == raw_md,
          f"{len(body)} 字节，SHA-256 {hashlib.sha256(body).hexdigest()[:16]}…")

    status, body, _ = request(f"/api/files/{info_mp4['id']}/decrypt", token=admin, raw=True)
    check("小张解密 MP4 成功，二进制逐字节一致", status == 200 and hashlib.sha256(body).digest() == hashlib.sha256(raw_mp4).digest(),
          f"{len(body) / 1024 / 1024:.1f} MB 还原")

    print("\n4) 搭建者视角：不需要登录，直接读数据库就能解密")
    if not DB_PATH.exists():
        check("找到 V1 数据库", False, str(DB_PATH))
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM files WHERE id = ?", (info_md["id"],)).fetchone()
        key_b64 = row["key_b64"]
        nonce_b64 = row["nonce_b64"]
        filename = row["filename"]

    blob = (ROOT / "v1_server_key" / "data" / "blobs" / f"{info_md['id']}.enc").read_bytes()
    plain = AESGCM(base64.b64decode(key_b64)).decrypt(
        base64.b64decode(nonce_b64),
        blob,
        f"v1|{info_md['id']}|{filename}".encode(),
    )
    check("搭建者用库里的密钥离线解开了密文（V1 的缺陷）", plain == raw_md,
          f"读取 files.key_b64 → 解出 {len(plain)} 字节明文，无需任何登录")

    status, data, _ = request("/api/admin/vault", token=admin)
    matched = next((k for k in data.get("keys", []) if k["id"] == info_md["id"]), None)
    check("密钥库接口确认密钥是明文存储", bool(matched) and matched["key_b64"] == key_b64,
          data.get("storage", ""))

    print("\n5) 下载回来的密文本身不可读")
    status, cipher, _ = request(f"/api/files/{info_md['id']}/ciphertext", token=user, raw=True)
    check("拿到密文也无法直接读出原文", b"\xe5\xaf\x86\xe7\xa0\x81" not in cipher and len(cipher) > 100,
          f"密文前 16 字节 {cipher[:16].hex()}")

    print(f"\n全部 {len(PASSED)} 项通过\n")


if __name__ == "__main__":
    sys.exit(main())
