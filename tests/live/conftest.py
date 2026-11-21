"""Live 測試共用的 fixture（T23b-b2；計畫 §3.1.1）。

session 的前提（R1：專案、拋棄式目錄、環境中沒有秘密；全部 skip 不算通過）由 tests/live_session.py
判定：它由 tests/conftest.py 載入，不論怎麼選取測試都會生效（這個檔案在 `pytest -m live` 不帶路徑時
不是 initial conftest，不能依賴它的 session hook；G1 審查 M3）。
"""

from collections.abc import Mapping

import pytest

from tests.live_session import live_environment as recipe_environment


@pytest.fixture(scope="session")
def live_environment(request: pytest.FixtureRequest) -> Mapping[str, str]:
    """recipe 的白名單環境（session 開始時；不受每個測試的隔離影響）。Live 的子程序明確使用它。"""
    return recipe_environment(request.config)
