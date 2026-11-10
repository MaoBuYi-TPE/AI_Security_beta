"""SecretCipher 由 create_app 放在 app.state；沒有設定時直接失敗，不以其他方式保存 secret。"""

from datetime import timedelta
from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import Request

from secscan.auth_profiles.dependencies import secret_cipher
from secscan.findings.content_cipher import content_cipher, excerpt_retention
from tests.secret_support import shared_cipher, shared_content_cipher, shared_evidence_cipher


def _request(state: object) -> Request:
    return cast(Request, SimpleNamespace(app=SimpleNamespace(state=state)))


def test_the_cipher_comes_from_app_state() -> None:
    cipher = shared_cipher()

    assert secret_cipher(_request(SimpleNamespace(secret_cipher=cipher))) is cipher


@pytest.mark.parametrize("value", [None, "keys", b"keys"])
def test_missing_or_wrong_cipher_fails_closed(value: object) -> None:
    state = SimpleNamespace() if value is None else SimpleNamespace(secret_cipher=value)

    with pytest.raises(RuntimeError, match=r"app\.state\.secret_cipher"):
        secret_cipher(_request(state))


# --- 報告內容與摘錄的 cipher（docs/DECISIONS.md §30.2）---------------------------------------


def test_the_content_cipher_comes_from_app_state() -> None:
    cipher = shared_content_cipher()

    assert content_cipher(_request(SimpleNamespace(content_cipher=cipher))) is cipher


@pytest.mark.parametrize("value", [None, "keys", "evidence"])
def test_a_missing_or_wrong_content_cipher_fails_closed(value: object) -> None:
    if value == "evidence":
        value = shared_evidence_cipher()
    state = SimpleNamespace() if value is None else SimpleNamespace(content_cipher=value)

    with pytest.raises(RuntimeError, match=r"app\.state\.content_cipher"):
        content_cipher(_request(state))


def test_the_excerpt_retention_comes_from_app_state() -> None:
    state = SimpleNamespace(excerpt_retention=timedelta(days=30))

    assert excerpt_retention(_request(state)) == timedelta(days=30)
    with pytest.raises(RuntimeError, match="excerpt_retention"):
        excerpt_retention(_request(SimpleNamespace(excerpt_retention=30)))
