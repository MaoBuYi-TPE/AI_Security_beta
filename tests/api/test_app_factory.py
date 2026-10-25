from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from secscan.core.config import Settings
from secscan.main import create_app
from secscan.security.secret_cipher import InvalidEncryptionKeysError, SecretCipher
from tests.secret_support import TEST_SECRET_ENCRYPTION_KEYS, encryption_keys


def test_create_app_without_settings_hides_docs_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """沒有 APP_ENV、也沒有 .env 時，真正的入口（uvicorn --factory）預設不開 API 文件。"""
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("DB_PASSWORD", "prod-requires-a-password")
    monkeypatch.setenv("SECRET_ENCRYPTION_KEYS", TEST_SECRET_ENCRYPTION_KEYS)
    monkeypatch.chdir(tmp_path)

    with TestClient(create_app()) as client:
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/docs").status_code == 404


def test_create_app_without_settings_reads_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """make dev 以 `uvicorn --factory` 呼叫不帶參數的 create_app()，設定要從環境變數讀取。"""
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("SECRET_ENCRYPTION_KEYS", TEST_SECRET_ENCRYPTION_KEYS)
    monkeypatch.chdir(tmp_path)

    with TestClient(create_app()) as client:
        assert client.get("/openapi.json").status_code == 200


def test_create_app_fails_fast_in_prod_without_db_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """正式環境缺少 DB 密碼時，啟動就失敗，而不是等到第一個請求才發現。"""
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValidationError, match="DB_PASSWORD"):
        create_app()


# --- 目標 secret 的加密金鑰（docs/DECISIONS.md §12.1）---------------------------------------


def _settings(keys: SecretStr | None) -> Settings:
    return Settings(app_env="test", secret_encryption_keys=keys, _env_file=None)


def test_create_app_fails_fast_without_encryption_keys() -> None:
    with pytest.raises(InvalidEncryptionKeysError, match="SECRET_ENCRYPTION_KEYS"):
        create_app(_settings(None))


def test_create_app_rejects_invalid_encryption_keys_without_echoing_them() -> None:
    setting = "not-a-fernet-key-but-maybe-a-secret"

    with pytest.raises(InvalidEncryptionKeysError) as raised:
        create_app(_settings(SecretStr(setting)))

    assert setting not in str(raised.value)


def test_create_app_keeps_the_cipher_in_app_state() -> None:
    app = create_app(_settings(encryption_keys()))

    assert isinstance(app.state.secret_cipher, SecretCipher)


def test_framework_telemetry_is_disabled() -> None:
    """審查建議：FastAPI 0.143 內建 OpenTelemetry；一旦有全域 provider 或自動設定，驗證錯誤與
    例外（可能含請求中的 secret）會被匯出。平台不使用它，三者都明確關閉，自動設定也關閉。"""
    app = create_app(_settings(encryption_keys()))

    # 公開的設定只在建立時傳入；讀回時只能看 FastAPI 保存的設定。
    config = app._telemetry
    assert (config["tracing"], config["metrics"], config["logs"], config["auto_configure"]) == (
        False,
        False,
        False,
        False,
    )
    assert app._native_telemetry.enabled() is False
