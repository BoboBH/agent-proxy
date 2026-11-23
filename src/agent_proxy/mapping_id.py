"""随机映射 ID：base62 12 位（约 71 bit 熵），不含任何真实地址信息。"""
from __future__ import annotations

import re
import secrets

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
LENGTH = 12
MAPPING_ID_RE = re.compile(rf"^[A-Za-z0-9]{{{LENGTH}}}\Z")


def new_mapping_id() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))
