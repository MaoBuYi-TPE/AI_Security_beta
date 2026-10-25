"""SecretCipher 由 create_app 放在 app.state；沒有設定時直接失敗，不以其他方式保存 secret。"""

from types import SimpleNamespace
from typing import cast

import pytest
from fastapi import Request

from secscan.auth_profiles.dependencies import secret_cipher
from tests.secret_support import shared_cipher


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
