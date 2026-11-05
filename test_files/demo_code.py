"""
demo_code.py — 测试用 Python 源码文件

用途：验证代码类文件（缩进 / 注释 / 中文 docstring / 空行）在加解密往返后完全一致。
这个脚本本身也是"服务端持钥"与"零知识"两种思路的极简对照实现。
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"demo-aad"


def encrypt_server_side(plaintext: bytes) -> dict:
    """V1 思路：密钥在这里生成，并且会跟着密文一起被保存到服务端。"""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, AAD)
    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "key": base64.b64encode(key).decode(),  # ← 服务端能看见密钥，也就能解密
    }


def decrypt_with_key(bundle: dict) -> bytes:
    key = base64.b64decode(bundle["key"])
    nonce = base64.b64decode(bundle["nonce"])
    ciphertext = base64.b64decode(bundle["ciphertext"])
    return AESGCM(key).decrypt(nonce, ciphertext, AAD)


def tamper_detected(bundle: dict) -> bool:
    """GCM 带认证标签：密文被改一位，解密就会抛异常。"""
    bundle = dict(bundle)
    raw = bytearray(base64.b64decode(bundle["ciphertext"]))
    raw[0] ^= 0xFF
    bundle["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    try:
        decrypt_with_key(bundle)
    except Exception:
        return True
    return False


if __name__ == "__main__":
    message = "服务端不应该有能力解开它保管的东西。".encode("utf-8")
    bundle = encrypt_server_side(message)
    assert decrypt_with_key(bundle) == message
    assert tamper_detected(bundle)
    print("演示通过：加解密一致，篡改可被发现。")
