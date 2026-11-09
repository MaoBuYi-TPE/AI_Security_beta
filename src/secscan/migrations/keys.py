"""make migrate 用的金鑰（主機上執行，.env 的三組金鑰都在；只有 env.py import，api 不 import）。

v0022 加密既有的報告與摘錄需要 CONTENT_ENCRYPTION_KEYS；三組之間共用金鑰時停止
（docs/DECISIONS.md §30.2、§30.11）。
"""

from pydantic import SecretStr

from secscan.core.config import Settings
from secscan.security.key_rings import (
    CONTENT_SETTING,
    EVIDENCE_SETTING,
    SECRET_SETTING,
    shared_rings,
)


def migration_content_keys(settings: Settings) -> SecretStr | None:
    """make migrate（主機上，三組金鑰都在）用的 CONTENT 金鑰；三組之間共用金鑰時停止。"""
    rings = {
        SECRET_SETTING: settings.secret_encryption_keys,
        EVIDENCE_SETTING: settings.evidence_encryption_keys,
        CONTENT_SETTING: settings.content_encryption_keys,
    }
    problem = shared_rings(
        {name: value.get_secret_value() if value else None for name, value in rings.items()}
    )
    if problem is not None:
        raise RuntimeError(f"{problem}（升級沒有進行）")
    return settings.content_encryption_keys
