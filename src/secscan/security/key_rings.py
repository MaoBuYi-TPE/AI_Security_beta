"""三組平台金鑰（docs/DECISIONS.md §30.2）：名稱、用途與各程序的啟動檢查。

| 設定 | 持有的程序（容器） | 用途 |
|---|---|---|
| SECRET_ENCRYPTION_KEYS | api（加密）、runner（解密） | 目標的 secret（secret_cipher） |
| EVIDENCE_ENCRYPTION_KEYS | runner | runs volume 中的原始證據 |
| CONTENT_ENCRYPTION_KEYS | api、worker | 報告內容與人工複測摘錄 |

每個程序啟動時建立自己持有的 cipher（缺少或不合規則就停止），並確認持有的幾組互不共用金鑰；
主機上的 check-encryption-keys 一次檢查三組。訊息只有設定名稱與位置，不含金鑰。
"""

from collections.abc import Mapping

from secscan.security.blob_cipher import BlobCipher
from secscan.security.secret_cipher import SETTING_NAME as SECRET_SETTING
from secscan.security.secret_cipher import (
    InvalidEncryptionKeysError,
    check_distinct_key_rings,
    parse_keys,
)

EVIDENCE_SETTING = "EVIDENCE_ENCRYPTION_KEYS"
CONTENT_SETTING = "CONTENT_ENCRYPTION_KEYS"
ALL_SETTINGS = (SECRET_SETTING, EVIDENCE_SETTING, CONTENT_SETTING)
EVIDENCE_PURPOSE = "runs volume 中的原始證據"
CONTENT_PURPOSE = "報告內容與人工複測摘錄"

__all__ = [
    "ALL_SETTINGS",
    "CONTENT_SETTING",
    "EVIDENCE_SETTING",
    "SECRET_SETTING",
    "check_held",
    "content_cipher",
    "evidence_cipher",
    "shared_rings",
]


def evidence_cipher(setting: str | None) -> BlobCipher:
    """原始證據的 cipher（只有 runner 與 runner 容器內的 admin 指令建立）。"""
    return BlobCipher.from_setting(setting, setting_name=EVIDENCE_SETTING, purpose=EVIDENCE_PURPOSE)


def content_cipher(setting: str | None) -> BlobCipher:
    """報告內容與人工複測摘錄的 cipher（api、worker 與主機上的換版指令建立）。"""
    return BlobCipher.from_setting(setting, setting_name=CONTENT_SETTING, purpose=CONTENT_PURPOSE)


def check_held(rings: Mapping[str, str | None]) -> None:
    """一個程序持有的幾組互不共用金鑰；沒有設定的略過（缺少與否由建立 cipher 時檢查）。"""
    check_distinct_key_rings({name: value for name, value in rings.items() if value is not None})


def shared_rings(rings: Mapping[str, str | None]) -> str | None:
    """持有的幾組中，合乎格式的有沒有共用金鑰；有的話回傳訊息（只有設定名稱）。

    主機上的 .env 三組都有（admin 指令與 migration）：容器各自只拿到需要的幾組，EVIDENCE 與
    CONTENT 共用只有在這裡看得出來（安全審查 L1）。格式錯誤留給各自建立 cipher 時說明。
    """
    valid: dict[str, str] = {}
    for name, value in rings.items():
        if value is None:
            continue
        try:
            parse_keys(value, name)
        except InvalidEncryptionKeysError:
            continue
        valid[name] = value
    try:
        check_distinct_key_rings(valid)
    except InvalidEncryptionKeysError as exc:
        return str(exc)
    return None
