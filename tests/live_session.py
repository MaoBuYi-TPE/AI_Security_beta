"""Live 測試 session 的前提（T23b-b2；計畫 §3.1.1；§12.8 的 R1、修正 2、17；G1 審查 HIGH-1、M3）。

由 tests/conftest.py 的 pytest_plugins 載入，所以不論怎麼選取測試都會生效（tests/live/conftest.py
不是 initial conftest 時，例如 `pytest -m live` 不帶路徑，它的 pytest_sessionstart 不會被呼叫）。

判定的條件是「開關 ENABLE_LIVE_LAB_TESTS=1，而且這次選中了 live 標記的測試」，不看 -m 的文字
（M3：不帶 -m、複合的選取 `-m "live and not slow"` 也一樣受保護）。只有通過檢查的 session 才算授權：

- pytest_collection_finish（任何測試執行之前）：SECSCAN_LIVE_PROJECT 必須是 secscan-live（shell 中
  殘留的 secscan 會讓測試操作開發的專案）、SECSCAN_LIVE_SECRETS_DIR 是這次的拋棄式目錄、環境中沒有
  任何秘密的名稱；不符就 pytest.exit（fail closed），只輸出名稱。
- 授權的 session 中，live 標記的測試保留 LIVE_PRESERVED_ENV（tests/conftest.py 的
  _isolate_app_settings 對其他測試一律刪除；HIGH-1）。recipe 的白名單環境在設定時另存一份
  （live_environment），Live 的子程序（compose、alembic）明確使用它，不依賴每個測試被改過的環境。
- pytest_sessionfinish：live 標記的測試通過的數量是 0，或其中有任何 skip，就以非零結束（Live 的目標
  都明確指定測試，skip 代表前提不成立，不能當成通過）。只計算 live 的測試。
"""

import os
from collections.abc import Mapping

import pytest

from tests.live.env_guard import live_session_problems

LIVE_SWITCH = "ENABLE_LIVE_LAB_TESTS"
LIVE_MARKER = "live"
EXIT_REFUSED = 3
# Live 需要、tests/conftest.py 對其他測試刪除的變數（tests/unit/test_live_isolation_make.py 以 AST
# 交叉核對）：
# compose.yaml 必填的秘密目錄、Live 測試讀的拋棄式目錄、bench 的金鑰檔（路徑，不是金鑰）。
LIVE_PRESERVED_ENV = frozenset(
    {"SECSCAN_SECRETS_DIR", "SECSCAN_LIVE_SECRETS_DIR", "BENCH_KEY_FILE"}
)
_AUTHORIZED = pytest.StashKey[bool]()
_ENVIRONMENT = pytest.StashKey[Mapping[str, str]]()


def pytest_configure(config: pytest.Config) -> None:
    if os.environ.get(LIVE_SWITCH) == "1":
        config.stash[_ENVIRONMENT] = dict(os.environ)


def pytest_collection_finish(session: pytest.Session) -> None:
    if os.environ.get(LIVE_SWITCH) != "1":
        return
    if not any(item.get_closest_marker(LIVE_MARKER) for item in session.items):
        return
    problems = live_session_problems(os.environ)
    if problems:
        pytest.exit(
            f"Live 的環境不正確（{'、'.join(problems)}）：請以 make 的 Live 目標執行", EXIT_REFUSED
        )
    session.config.stash[_AUTHORIZED] = True


def authorized_live_item(node: pytest.Item) -> bool:
    """這個測試是授權的 Live session 中、有 live 標記的測試。"""
    return (
        node.config.stash.get(_AUTHORIZED, False)
        and node.get_closest_marker(LIVE_MARKER) is not None
    )


def live_environment(config: pytest.Config) -> Mapping[str, str]:
    """授權的 Live session 開始時的環境（recipe 的白名單環境）；沒有授權時 fail。"""
    environment = config.stash.get(_ENVIRONMENT, None)
    if environment is None or not config.stash.get(_AUTHORIZED, False):
        pytest.fail("這不是授權的 Live session：請以 make 的 Live 目標執行")
    return dict(environment)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not session.config.stash.get(_AUTHORIZED, False) or exitstatus != pytest.ExitCode.OK:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    stats = getattr(reporter, "stats", {})
    passed = [report for report in stats.get("passed", []) if _live(report)]
    skipped = [report for report in stats.get("skipped", []) if _live(report)]
    if not passed or skipped:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def _live(report: object) -> bool:
    return LIVE_MARKER in getattr(report, "keywords", {})
