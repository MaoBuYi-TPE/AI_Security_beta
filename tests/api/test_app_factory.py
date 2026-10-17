from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secscan.main import create_app


def test_create_app_without_settings_hides_docs_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """沒有 APP_ENV、也沒有 .env 時，真正的入口（uvicorn --factory）預設不開 API 文件。"""
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.chdir(tmp_path)

    with TestClient(create_app()) as client:
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/docs").status_code == 404


def test_create_app_without_settings_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """make dev 以 `uvicorn --factory` 呼叫不帶參數的 create_app()，設定要從環境變數讀取。"""
    monkeypatch.setenv("APP_ENV", "dev")

    with TestClient(create_app()) as client:
        assert client.get("/openapi.json").status_code == 200
