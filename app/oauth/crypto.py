"""Fernet 加解密原语（SHA256(MASTER_KEY) 派生密钥）。

独立成模块的原因：encrypt/decrypt_text 被 oauth.client 与 oauth.credential
双方共用——若留在 credential 内，client ↔ credential 形成顶层导入环
（credential._do_refresh 被迫函数内延迟导入 client）。底层原语下沉后环消解。
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.errors import AppError

_fernet_cache: dict[str, Fernet] = {}


def _fernet(master_key: str) -> Fernet:
    if not master_key:
        # fail-closed：无密钥宁可拒绝加密，绝不落明文（§14.6）
        raise AppError(500, "INTERNAL_ERROR", "MASTER_KEY 未配置，无法加解密 OAuth 凭证")
    f = _fernet_cache.get(master_key)
    if f is None:
        derived = base64.urlsafe_b64encode(
            hashlib.sha256(master_key.encode("utf-8")).digest())
        f = Fernet(derived)
        _fernet_cache[master_key] = f
    return f


def encrypt_text(plaintext: str, master_key: str) -> str:
    return _fernet(master_key).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(ciphertext: str, master_key: str) -> str:
    try:
        return _fernet(master_key).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeEncodeError) as exc:
        raise AppError(500, "INTERNAL_ERROR",
                       "OAuth 凭证解密失败（MASTER_KEY 变更？需重新授权）") from exc
