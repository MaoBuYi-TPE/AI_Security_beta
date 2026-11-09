"""報告內容與人工複測摘錄的 cipher（docs/DECISIONS.md §30.2、§30.4）。

create_app 依 CONTENT_ENCRYPTION_KEYS 建立，放在 app.state.content_cipher；只有報告與人工 triage
的路由取得它（tests/unit/test_blob_cipher_callers.py 檢查）。放在 findings：reports 與 triage 都在
它之上。
"""

from datetime import timedelta
from typing import Annotated

from fastapi import Depends, Request

from secscan.security.blob_cipher import BlobCipher
from secscan.security.key_rings import CONTENT_SETTING


def content_cipher(request: Request) -> BlobCipher:
    cipher = getattr(request.app.state, "content_cipher", None)
    if not isinstance(cipher, BlobCipher) or cipher.setting_name != CONTENT_SETTING:
        # 沒有內容的金鑰就不能加密或解密：直接失敗，不以明文保存或送出。
        raise RuntimeError("內容的加密元件尚未初始化（create_app 應設定 app.state.content_cipher）")
    return cipher


CurrentContentCipher = Annotated[BlobCipher, Depends(content_cipher)]


def excerpt_retention(request: Request) -> timedelta:
    """人工複測摘錄的保留期限（EXCERPT_RETENTION_DAYS；create_app 放在 app.state）。"""
    retention = getattr(request.app.state, "excerpt_retention", None)
    if not isinstance(retention, timedelta):
        raise RuntimeError(
            "摘錄的保留期限尚未設定（create_app 應設定 app.state.excerpt_retention）"
        )
    return retention


CurrentExcerptRetention = Annotated[timedelta, Depends(excerpt_retention)]
