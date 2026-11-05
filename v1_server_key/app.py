"""
V1 · 对照版（常规加解密服务）：密钥由服务端生成并入库

角色：
  - 小孔（xiaokong / user） ：只能加密、上传、下载密文，不能解密
  - 小张（xiaozhang / admin）：拥有解密权限，可让服务端解密并下载明文
  - 搭建者（部署这个服务的人）：能读数据库 → 能拿到密钥 → 能解密（本版本的核心缺陷）

这一版故意保留"服务端持钥"的设计，用来和 V2 做对照。
"""

from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BLOB_DIR = DATA_DIR / "blobs"
STATIC_DIR = BASE_DIR / "static"
DATA_DIR.mkdir(parents=True, exist_ok=True)
BLOB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "v1.db"

MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200MB
PBKDF2_ROUNDS = 120_000
SESSION_TTL = 8 * 3600

USERS = [
    ("xiaokong", "xiaokong123", "user", "小孔", "普通用户 · 只能加密"),
    ("xiaozhang", "xiaozhang123", "admin", "小张", "领导 · 拥有解密权限"),
]

CATEGORY_BY_EXT = {
    "文档": {".txt", ".md", ".markdown", ".pdf", ".doc", ".docx", ".rtf", ".csv"},
    "表格": {".xls", ".xlsx", ".ods"},
    "代码": {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".c", ".h", ".cpp",
             ".cs", ".php", ".rb", ".sh", ".sql", ".html", ".css", ".json", ".yaml", ".yml", ".toml"},
    "音频": {".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"},
    "视频": {".mp4", ".mov", ".mkv", ".avi", ".webm", ".flv"},
    "图片": {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"},
    "压缩包": {".zip", ".rar", ".7z", ".tar", ".gz"},
}

# token -> session（单进程内存即可，重启后需重新登录）
SESSIONS: dict[str, dict] = {}

app = FastAPI(title="V1 对照版 · 服务端持钥", docs_url="/api/docs", redoc_url=None)


# --------------------------------------------------------------------------- #
# 数据库
# --------------------------------------------------------------------------- #
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, rounds, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
    return secrets.compare_digest(digest.hex(), digest_hex)


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL,          -- user / admin
                display_name  TEXT NOT NULL,
                title         TEXT NOT NULL
            );

            -- 注意这里的 key_b64：V1 的密钥明文存在服务端数据库里，
            -- 任何能读数据库的人（包括搭建者）都能解密。这正是 V2 要解决的问题。
            CREATE TABLE IF NOT EXISTS files (
                id           TEXT PRIMARY KEY,
                filename     TEXT NOT NULL,
                category     TEXT NOT NULL,
                orig_size    INTEGER NOT NULL,
                cipher_size  INTEGER NOT NULL,
                nonce_b64    TEXT NOT NULL,
                key_b64      TEXT NOT NULL,
                alg          TEXT NOT NULL,
                sha256_plain TEXT NOT NULL,
                owner        TEXT NOT NULL,
                created_at   REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        REAL NOT NULL,
                username  TEXT NOT NULL,
                action    TEXT NOT NULL,
                detail    TEXT NOT NULL,
                result    TEXT NOT NULL
            );
            """
        )
        for username, password, role, display_name, title in USERS:
            row = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO users (username, password_hash, role, display_name, title) VALUES (?,?,?,?,?)",
                    (username, hash_password(password), role, display_name, title),
                )


def audit(username: str, action: str, detail: str, result: str = "ok") -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO audit (ts, username, action, detail, result) VALUES (?,?,?,?,?)",
            (time.time(), username, action, detail, result),
        )


# --------------------------------------------------------------------------- #
# 鉴权
# --------------------------------------------------------------------------- #
def current_user(authorization: str | None = Header(default=None)) -> dict:
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    session = SESSIONS.get(token)
    if not session or session["expires_at"] < time.time():
        raise HTTPException(status_code=401, detail="未登录或登录已过期，请重新登录")
    return session


def require_admin(session: dict = Depends(current_user)) -> dict:
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="当前账号没有解密权限：只有小张（管理员）可以解密")
    return session


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def guess_category(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    for category, exts in CATEGORY_BY_EXT.items():
        if ext in exts:
            return category
    return "其他"


def human_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def aad_for(file_id: str, filename: str) -> bytes:
    """把文件 ID 与文件名作为附加认证数据，防止密文被替换 / 改名。"""
    return f"v1|{file_id}|{filename}".encode()


# --------------------------------------------------------------------------- #
# 接口
# --------------------------------------------------------------------------- #
@app.post("/api/login")
def login(payload: dict):
    username = str(payload.get("username", "")).strip().lower()
    password = str(payload.get("password", ""))
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        audit(username or "-", "login", "登录失败", "deny")
        raise HTTPException(status_code=401, detail="账号或密码错误")

    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {
        "username": row["username"],
        "role": row["role"],
        "display_name": row["display_name"],
        "title": row["title"],
        "expires_at": time.time() + SESSION_TTL,
    }
    audit(row["username"], "login", "登录成功")
    return {"token": token, "user": public_user(SESSIONS[token])}


@app.post("/api/logout")
def logout(authorization: str | None = Header(default=None)):
    if authorization and authorization.lower().startswith("bearer "):
        SESSIONS.pop(authorization[7:].strip(), None)
    return {"ok": True}


def public_user(session: dict) -> dict:
    return {
        "username": session["username"],
        "role": session["role"],
        "display_name": session["display_name"],
        "title": session["title"],
        "can_decrypt": session["role"] == "admin",
    }


@app.get("/api/me")
def me(session: dict = Depends(current_user)):
    return {"user": public_user(session)}


@app.get("/api/files")
def list_files(session: dict = Depends(current_user)):
    with db() as conn:
        rows = conn.execute("SELECT * FROM files ORDER BY created_at DESC").fetchall()
    files = []
    for row in rows:
        item = {
            "id": row["id"],
            "filename": row["filename"],
            "category": row["category"],
            "orig_size": row["orig_size"],
            "cipher_size": row["cipher_size"],
            "orig_size_text": human_size(row["orig_size"]),
            "cipher_size_text": human_size(row["cipher_size"]),
            "alg": row["alg"],
            "owner": row["owner"],
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["created_at"])),
            "sha256_plain": row["sha256_plain"][:16],
        }
        if session["role"] == "admin":
            # 小张能看到密钥——因为密钥就在服务端数据库里，这也说明搭建者同样能看到
            item["key_b64"] = row["key_b64"]
            item["nonce_b64"] = row["nonce_b64"]
        files.append(item)
    return {
        "files": files,
        "server_holds_keys": True,
        "note": "V1：密钥保存在服务端数据库 files.key_b64 字段，服务端可解密。",
    }


@app.post("/api/files")
async def upload_file(
    file: UploadFile = File(...),
    category: str = Form("auto"),
    session: dict = Depends(current_user),
):
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="文件为空")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="文件超过 200MB 限制")

    filename = Path(file.filename or "unnamed").name
    resolved_category = guess_category(filename) if category in ("", "auto") else category
    file_id = secrets.token_hex(8)
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    cipher = AESGCM(key).encrypt(nonce, raw, aad_for(file_id, filename))

    (BLOB_DIR / f"{file_id}.enc").write_bytes(cipher)

    with db() as conn:
        conn.execute(
            "INSERT INTO files (id, filename, category, orig_size, cipher_size, nonce_b64, key_b64,"
            " alg, sha256_plain, owner, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                file_id,
                filename,
                resolved_category,
                len(raw),
                len(cipher),
                base64.b64encode(nonce).decode(),
                base64.b64encode(key).decode(),  # ← 密钥入库：V1 的关键缺陷
                "AES-256-GCM",
                hashlib.sha256(raw).hexdigest(),
                session["username"],
                time.time(),
            ),
        )

    audit(session["username"], "upload", f"{filename} ({resolved_category}, {human_size(len(raw))})")
    return {
        "ok": True,
        "id": file_id,
        "category": resolved_category,
        "cipher_size": len(cipher),
        "cipher_size_text": human_size(len(cipher)),
    }


@app.get("/api/files/{file_id}/ciphertext")
def download_ciphertext(file_id: str, session: dict = Depends(current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="文件不存在")
    path = BLOB_DIR / f"{file_id}.enc"
    if not path.exists():
        raise HTTPException(status_code=410, detail="密文已丢失")
    audit(session["username"], "download_ciphertext", row["filename"])
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=f"{row['filename']}.enc",
    )


@app.get("/api/files/{file_id}/decrypt")
def decrypt_file(file_id: str, session: dict = Depends(require_admin)):
    """只有小张能调用：服务端取出密钥 → 解密 → 返回明文。"""
    with db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="文件不存在")

    cipher = (BLOB_DIR / f"{file_id}.enc").read_bytes()
    key = base64.b64decode(row["key_b64"])
    nonce = base64.b64decode(row["nonce_b64"])
    try:
        plain = AESGCM(key).decrypt(nonce, cipher, aad_for(row["id"], row["filename"]))
    except Exception:
        raise HTTPException(status_code=500, detail="解密失败：密文或密钥已损坏")

    audit(session["username"], "decrypt", row["filename"])
    media_type = mimetypes.guess_type(row["filename"])[0] or "application/octet-stream"
    return Response(
        content=plain,
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(row['filename'])}",
            "X-Original-Size": str(len(plain)),
        },
    )


@app.delete("/api/files/{file_id}")
def delete_file(file_id: str, session: dict = Depends(require_admin)):
    with db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="文件不存在")
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
    (BLOB_DIR / f"{file_id}.enc").unlink(missing_ok=True)
    audit(session["username"], "delete", row["filename"])
    return {"ok": True}


@app.get("/api/admin/vault")
def key_vault(session: dict = Depends(require_admin)):
    """展示服务端数据库里的密钥：证明"能读库的人就能解密"。"""
    with db() as conn:
        rows = conn.execute(
            "SELECT id, filename, key_b64, nonce_b64, owner, created_at FROM files ORDER BY created_at DESC"
        ).fetchall()
    return {
        "storage": "SQLite 表 files，字段 key_b64（Base64 编码的 AES-256 密钥）",
        "db_path": str(DB_PATH.relative_to(BASE_DIR)),
        "keys": [
            {
                "id": row["id"],
                "filename": row["filename"],
                "key_b64": row["key_b64"],
                "nonce_b64": row["nonce_b64"],
                "owner": row["owner"],
            }
            for row in rows
        ],
        "warning": "这些密钥明文存在库里。搭建者、运维、任何拿到数据库文件的人，都能离线解开所有密文。",
    }


@app.get("/api/audit")
def get_audit(limit: int = 50, session: dict = Depends(require_admin)):
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(limit, 200)),)
        ).fetchall()
    return {
        "logs": [
            {
                "ts": time.strftime("%H:%M:%S", time.localtime(row["ts"])),
                "username": row["username"],
                "action": row["action"],
                "detail": row["detail"],
                "result": row["result"],
            }
            for row in rows
        ]
    }


@app.get("/api/health")
def health():
    return {"ok": True, "version": "v1", "mode": "server-side-key"}


init_db()
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
