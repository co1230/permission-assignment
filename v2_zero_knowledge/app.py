"""
V2 · 目标版（零知识 / 搭建者无法解密）：服务端不持有任何解密材料

和 V1 的本质区别：
  V1：服务端生成 AES 密钥 → 明文入库 → 服务端能解密
  V2：浏览器生成 AES 数据密钥 → 用"小张的 RSA 公钥"把数据密钥封装 → 只上传密文 + 封装后的密钥
      服务端只有公钥，没有私钥，永远解不开；小张的私钥只存在他自己的电脑上（用口令加密保存）

角色：
  - 小孔：可加密上传、可看文件列表、不能解密（也没有私钥）
  - 小张：拥有密钥对；私钥在浏览器本地生成并下载，服务端只保存公钥
  - 搭建者：能读全部数据库与磁盘 → 只能看到密文、nonce、被公钥封装的数据密钥 → 无法解密

本文件刻意没有任何"私钥"或"明文数据密钥"字段，可用 /api/proof/schema 自证。
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
BLOB_DIR = DATA_DIR / "blobs"
STATIC_DIR = BASE_DIR / "static"
DATA_DIR.mkdir(parents=True, exist_ok=True)
BLOB_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "v2.db"

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
PBKDF2_ROUNDS = 120_000
SESSION_TTL = 8 * 3600

USERS = [
    ("xiaokong", "xiaokong123", "user", "小孔", "普通用户 · 只能加密"),
    ("xiaozhang", "xiaozhang123", "admin", "小张", "领导 · 持有私钥，可解密"),
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

SESSIONS: dict[str, dict] = {}

app = FastAPI(title="V2 零知识版 · 服务端无法解密", docs_url="/api/docs", redoc_url=None)


# --------------------------------------------------------------------------- #
# 数据库：注意 files 表没有 key 字段，只有"被公钥封装的数据密钥"
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
                role          TEXT NOT NULL,
                display_name  TEXT NOT NULL,
                title         TEXT NOT NULL
            );

            -- 关键：这里只有 wrapped_key_b64（RSA-OAEP 用公钥封装过的 AES 数据密钥）。
            -- 没有私钥就无法解封，服务端 / 搭建者拿到这一行也解不开。
            CREATE TABLE IF NOT EXISTS files (
                id            TEXT PRIMARY KEY,
                filename      TEXT NOT NULL,
                category      TEXT NOT NULL,
                orig_size     INTEGER NOT NULL,
                cipher_size   INTEGER NOT NULL,
                nonce_b64     TEXT NOT NULL,        -- GCM nonce 是公开参数
                wrapped_key_b64 TEXT NOT NULL,       -- 被小张公钥封装的 AES 数据密钥
                alg           TEXT NOT NULL,
                sha256_cipher TEXT NOT NULL,
                owner         TEXT NOT NULL,
                created_at    REAL NOT NULL
            );

            -- 只保存公钥（公开信息，泄露无风险）
            CREATE TABLE IF NOT EXISTS admin_public_key (
                id             INTEGER PRIMARY KEY CHECK (id = 1),
                public_key_b64 TEXT NOT NULL,
                fingerprint    TEXT NOT NULL,
                owner          TEXT NOT NULL,
                created_at     REAL NOT NULL
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
        raise HTTPException(status_code=403, detail="当前账号没有解密权限：只有小张（管理员）持有私钥")
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
    value = float(size)
    for unit in ["B", "KB", "MB", "GB"]:
        if value < 1024 or unit == "GB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def public_user(session: dict) -> dict:
    return {
        "username": session["username"],
        "role": session["role"],
        "display_name": session["display_name"],
        "title": session["title"],
        "can_decrypt": session["role"] == "admin",
    }


# --------------------------------------------------------------------------- #
# 接口：登录
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


@app.get("/api/me")
def me(session: dict = Depends(current_user)):
    return {"user": public_user(session)}


# --------------------------------------------------------------------------- #
# 接口：公钥（公开信息，允许所有登录用户读取，因为加密需要它）
# --------------------------------------------------------------------------- #
@app.get("/api/keys/public")
def get_public_key(session: dict = Depends(current_user)):
    with db() as conn:
        row = conn.execute("SELECT * FROM admin_public_key WHERE id = 1").fetchone()
    if not row:
        return {"public_key_b64": None, "fingerprint": None, "owner": None}
    return {
        "public_key_b64": row["public_key_b64"],
        "fingerprint": row["fingerprint"],
        "owner": row["owner"],
        "created_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(row["created_at"])),
        "alg": "RSA-OAEP-2048 (SHA-256)",
    }


@app.post("/api/keys/public")
def set_public_key(payload: dict, session: dict = Depends(require_admin)):
    public_key_b64 = str(payload.get("public_key_b64", "")).strip()
    if not public_key_b64:
        raise HTTPException(status_code=400, detail="缺少公钥")
    try:
        raw = base64.b64decode(public_key_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="公钥不是合法的 Base64")
    if len(raw) < 200:
        raise HTTPException(status_code=400, detail="公钥格式不正确（应为 SPKI / Base64）")
    fingerprint = hashlib.sha256(raw).hexdigest()
    with db() as conn:
        conn.execute(
            "INSERT INTO admin_public_key (id, public_key_b64, fingerprint, owner, created_at)"
            " VALUES (1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET"
            " public_key_b64=excluded.public_key_b64, fingerprint=excluded.fingerprint,"
            " owner=excluded.owner, created_at=excluded.created_at",
            (public_key_b64, fingerprint, session["username"], time.time()),
        )
    audit(session["username"], "publish_public_key", f"指纹 {fingerprint[:16]}")
    return {"ok": True, "fingerprint": fingerprint}


# --------------------------------------------------------------------------- #
# 接口：文件
# --------------------------------------------------------------------------- #
@app.get("/api/files")
def list_files(session: dict = Depends(current_user)):
    with db() as conn:
        rows = conn.execute("SELECT * FROM files ORDER BY created_at DESC").fetchall()
    return {
        "files": [
            {
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
                "sha256_cipher": row["sha256_cipher"][:16],
                "wrapped_key_preview": row["wrapped_key_b64"][:24] + "…",
            }
            for row in rows
        ],
        "server_knows_key": False,
        "note": "V2：服务端只有被公钥封装的密钥（wrapped_key_b64），没有私钥，无法解密。",
    }


@app.post("/api/files")
async def upload_ciphertext(
    ciphertext: UploadFile = File(...),
    filename: str = Form(...),
    category: str = Form("auto"),
    orig_size: int = Form(0),
    nonce_b64: str = Form(...),
    wrapped_key_b64: str = Form(...),
    sha256_cipher: str = Form(""),
    alg: str = Form("AES-256-GCM + RSA-OAEP-256"),
    session: dict = Depends(current_user),
):
    """只接收浏览器已经加密好的密文，服务端不接触明文、不接触对称密钥。"""
    blob = await ciphertext.read()
    if not blob:
        raise HTTPException(status_code=400, detail="密文为空")
    if len(blob) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="密文超过 200MB 限制")

    try:
        base64.b64decode(nonce_b64, validate=True)
        wrapped = base64.b64decode(wrapped_key_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="nonce 或封装密钥格式不正确")
    if len(wrapped) < 128:
        raise HTTPException(status_code=400, detail="封装密钥长度异常（应为 RSA 加密后的数据密钥）")

    actual_sha = hashlib.sha256(blob).hexdigest()
    if sha256_cipher and sha256_cipher != actual_sha:
        raise HTTPException(status_code=400, detail="密文校验失败：客户端 SHA-256 与服务端不一致")

    safe_name = Path(filename).name or "unnamed"
    resolved_category = guess_category(safe_name) if category in ("", "auto") else category
    file_id = secrets.token_hex(8)
    (BLOB_DIR / f"{file_id}.enc").write_bytes(blob)

    with db() as conn:
        conn.execute(
            "INSERT INTO files (id, filename, category, orig_size, cipher_size, nonce_b64,"
            " wrapped_key_b64, alg, sha256_cipher, owner, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                file_id,
                safe_name,
                resolved_category,
                max(0, orig_size),
                len(blob),
                nonce_b64,
                wrapped_key_b64,
                alg,
                actual_sha,
                session["username"],
                time.time(),
            ),
        )

    audit(session["username"], "upload_ciphertext", f"{safe_name}（{resolved_category}，{human_size(len(blob))}）")
    return {
        "ok": True,
        "id": file_id,
        "category": resolved_category,
        "cipher_size": len(blob),
        "cipher_size_text": human_size(len(blob)),
        "server_can_decrypt": False,
    }


@app.get("/api/files/{file_id}/ciphertext")
def download_ciphertext(file_id: str, session: dict = Depends(require_admin)):
    """只有小张能取密文；即使取到，也要靠本地私钥才能解开。"""
    with db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="文件不存在")
    path = BLOB_DIR / f"{file_id}.enc"
    if not path.exists():
        raise HTTPException(status_code=410, detail="密文已丢失")
    audit(session["username"], "download_ciphertext", row["filename"])
    return FileResponse(path, media_type="application/octet-stream", filename=f"{row['filename']}.enc")


@app.get("/api/files/{file_id}/envelope")
def download_envelope(file_id: str, session: dict = Depends(require_admin)):
    """封装信息：nonce + 被公钥封装的密钥。它本身不能解密，必须配私钥。"""
    with db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="文件不存在")
    payload = {
        "v": 1,
        "file_id": row["id"],
        "filename": row["filename"],
        "category": row["category"],
        "orig_size": row["orig_size"],
        "cipher_size": row["cipher_size"],
        "alg": row["alg"],
        "nonce_b64": row["nonce_b64"],
        "wrapped_key_b64": row["wrapped_key_b64"],
        "sha256_cipher": row["sha256_cipher"],
        "note": "此文件不含私钥与明文数据密钥，单独持有它无法解密，必须搭配小张的私钥包。",
    }
    audit(session["username"], "download_envelope", row["filename"])
    return JSONResponse(
        payload,
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(row['filename'] + '.envelope.json')}"},
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


# --------------------------------------------------------------------------- #
# 接口：自证 —— 服务端确实解不开
# --------------------------------------------------------------------------- #
@app.get("/api/proof/schema")
def proof_schema(session: dict = Depends(current_user)):
    with db() as conn:
        cols = conn.execute("PRAGMA table_info(files)").fetchall()
        pk = conn.execute("SELECT public_key_b64 FROM admin_public_key WHERE id = 1").fetchone()
        count = conn.execute("SELECT COUNT(*) AS c FROM files").fetchone()["c"]
    columns = [
        {
            "name": row["name"],
            "type": row["type"],
            "holds_secret": row["name"].lower() in ("key", "key_b64", "private_key", "data_key", "secret"),
        }
        for row in cols
    ]
    db_bytes = DB_PATH.read_bytes() if DB_PATH.exists() else b""
    return {
        "table": "files",
        "columns": columns,
        "secret_columns": [c["name"] for c in columns if c["holds_secret"]],
        "db_file": str(DB_PATH.relative_to(BASE_DIR)),
        "db_size": human_size(len(db_bytes)),
        "file_count": count,
        "stored_key_material": "仅 RSA 公钥（公开信息）",
        "public_key_fingerprint": hashlib.sha256(base64.b64decode(pk["public_key_b64"])).hexdigest()[:32] if pk else None,
        "conclusion": "数据库中不存在私钥，也不存在明文 AES 数据密钥；被公钥封装的密钥没有私钥无法解开。",
    }


@app.post("/api/proof/server-decrypt/{file_id}")
def proof_server_decrypt(file_id: str, session: dict = Depends(require_admin)):
    """模拟"搭建者尝试用服务器解密"：必然失败，返回 501。"""
    with db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="文件不存在")
    audit(session["username"], "server_decrypt_attempt", row["filename"], "deny")
    return JSONResponse(
        status_code=501,
        content={
            "ok": False,
            "reason": "NO_PRIVATE_KEY",
            "message": "服务端没有私钥，无法解封 wrapped_key，因此无法解密。这不是权限配置，而是密钥学上做不到。",
            "what_server_has": ["密文 .enc", "GCM nonce", "被 RSA 公钥封装的数据密钥"],
            "what_server_lacks": ["RSA 私钥", "AES 明文数据密钥"],
            "advice": "解密只发生在小张的浏览器本地：他用口令解开自己的私钥包，再用私钥解封数据密钥。",
        },
    )


@app.get("/api/audit")
def get_audit(limit: int = 50, session: dict = Depends(require_admin)):
    with db() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (max(1, min(limit, 200)),)).fetchall()
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
    return {"ok": True, "version": "v2", "mode": "zero-knowledge"}


init_db()
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
