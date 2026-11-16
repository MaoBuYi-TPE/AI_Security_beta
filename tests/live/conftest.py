"""Live 測試 session 的前提（T23b-b2；計畫 §3.1.1；§12.8 的 R1、修正 2、17）。

只在 Live 的 recipe 設定的環境（ENABLE_LIVE_LAB_TESTS=1、pytest -m live）下判定；一般的
`pytest -m "not live"` 也會載入這個檔案，這時什麼都不做。

- pytest_sessionstart（任何有副作用的操作之前）：SECSCAN_LIVE_PROJECT 必須是 secscan-live（shell 中
  殘留的 secscan 會讓測試操作開發的專案）、SECSCAN_LIVE_SECRETS_DIR 是這次的拋棄式目錄、環境中沒有
  任何秘密的名稱；不符就 pytest.exit（fail closed），只輸出名稱。
- pytest_sessionfinish：通過的測試數是 0，或有任何 skip，就以非零結束。Live 的目標都明確指定測試，
  skip 代表前提不成立，不能當成通過。
"""

import os

import pytest

from tests.live.env_guard import live_session_problems

LIVE_SWITCH = "ENABLE_LIVE_LAB_TESTS"
LIVE_MARK_EXPRESSION = "live"
EXIT_REFUSED = 3


def _live_session(config: pytest.Config) -> bool:
    expression = str(config.getoption("markexpr", "") or "")
    return os.environ.get(LIVE_SWITCH) == "1" and expression == LIVE_MARK_EXPRESSION


def pytest_sessionstart(session: pytest.Session) -> None:
    if not _live_session(session.config):
        return
    problems = live_session_problems(os.environ)
    if problems:
        pytest.exit(
            f"Live 的環境不正確（{'、'.join(problems)}）：請以 make 的 Live 目標執行", EXIT_REFUSED
        )


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not _live_session(session.config) or exitstatus != pytest.ExitCode.OK:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    stats = getattr(reporter, "stats", {})
    if not stats.get("passed") or stats.get("skipped"):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
