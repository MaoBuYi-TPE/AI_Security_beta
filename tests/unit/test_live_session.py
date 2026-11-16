"""Live 測試 session 的前提（tests/live_session.py；計畫 §3.1.1；R1、修正 2、17；G1 審查
HIGH-1、M3）。

以 pytester 在暫存目錄執行小的 pytest session：conftest 載入 tests.live_session，並沿用
tests/conftest.py 的 _isolate_app_settings（autouse）。判定的條件是「開關是 1，而且選中了 live 標記
的測試」，不看 -m 的文字。
"""

from pathlib import Path

import pytest

from tests.live_session import LIVE_PRESERVED_ENV

CONFTEST = """
from tests.conftest import _isolate_app_settings  # noqa: F401（沿用根 conftest 的 autouse fixture）

pytest_plugins = ("tests.live_session",)
"""
INI = "[pytest]\nmarkers =\n    live: Live 測試\n    slow: 慢的測試\n"
PASSING = """
import pytest

@pytest.mark.live
def test_live():
    pass
"""
SKIPPING = """
import pytest

@pytest.mark.live
def test_live():
    pytest.skip("前提不成立")
"""
SIDE_EFFECT = """
import pytest

@pytest.mark.live
def test_live():
    open({marker!r}, "w").write("ran")
"""
# 每個測試把看到的變數名稱寫進檔案（只寫名稱，不寫值）。
VISIBILITY = """
import os
import pytest

NAMES = {names!r}

def _record(kind):
    seen = sorted(name for name in NAMES if name in os.environ)
    with open({record!r}, "a") as stream:
        stream.write(kind + ":" + ",".join(seen) + "\\n")

@pytest.mark.live
def test_live():
    _record("live")

def test_not_live():
    _record("not-live")
"""


@pytest.fixture
def live(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> pytest.Pytester:
    pytester.makeini(INI)
    pytester.makeconftest(CONFTEST)
    monkeypatch.setenv("ENABLE_LIVE_LAB_TESTS", "1")
    monkeypatch.setenv("SECSCAN_LIVE_PROJECT", "secscan-live")
    directory = str(tmp_path / "secscan-live-secrets.abc123")
    monkeypatch.setenv("SECSCAN_LIVE_SECRETS_DIR", directory)
    monkeypatch.setenv("SECSCAN_SECRETS_DIR", directory)
    monkeypatch.setenv("BENCH_KEY_FILE", "/srv/bench-keys")
    monkeypatch.setenv("DB_PORT", "55434")
    return pytester


def test_a_passing_live_session_passes(live: pytest.Pytester) -> None:
    live.makepyfile(PASSING)

    assert live.runpytest("-m", "live").ret == pytest.ExitCode.OK


def test_an_all_skipped_live_session_fails(live: pytest.Pytester) -> None:
    """修正 2：ENABLE_LIVE_LAB_TESTS 沒有傳入等原因造成全部 skip 時，不能當成通過。"""
    live.makepyfile(SKIPPING)

    assert live.runpytest("-m", "live").ret == pytest.ExitCode.TESTS_FAILED


def test_only_live_outcomes_are_counted(live: pytest.Pytester) -> None:
    """非 live 的 skip 不影響 Live 的判定；live 的 skip 一定讓 session 失敗。"""
    live.makepyfile(PASSING + "\ndef test_other():\n    pytest.skip('不是 live')\n")

    assert live.runpytest().ret == pytest.ExitCode.OK


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("SECSCAN_LIVE_PROJECT", "secscan"),
        ("SECSCAN_LIVE_SECRETS_DIR", "/Users/someone/canary-dir-0005"),
        ("DB_PASSWORD", "canary-value-0007"),
    ],
    ids=["dev-project", "secrets-elsewhere", "secret-in-environment"],
)
@pytest.mark.parametrize(
    "selection",
    [("-m", "live"), ("-m", "live and not slow"), ("-m", "slow or live"), ()],
    ids=["live", "compound-and", "compound-or", "no-marker-expression"],
)
def test_a_wrong_environment_stops_before_any_test_runs(
    live: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    variable: str,
    value: str,
    selection: tuple[str, ...],
) -> None:
    """R1、M3：shell 中殘留的 SECSCAN_LIVE_PROJECT=secscan 會讓測試操作開發的專案。選中 live 的
    測試時，不論 -m 怎麼寫（或不寫），都在任何測試執行之前停止。"""
    marker = tmp_path / "ran"
    live.makepyfile(SIDE_EFFECT.format(marker=str(marker)))
    monkeypatch.setenv(variable, value)

    result = live.runpytest(*selection)

    assert result.ret == 3
    assert not marker.exists()
    output = result.stdout.str() + result.stderr.str()
    assert variable in output
    # 只輸出名稱（專案名稱 secscan 是 secscan-live 的一部分，不檢查）。
    if value != "secscan":
        leaked = value in output
        assert not leaked


def test_a_session_without_live_tests_is_not_affected(
    live: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    live.makepyfile(SKIPPING.replace("@pytest.mark.live\n", ""))
    monkeypatch.setenv("SECSCAN_LIVE_PROJECT", "secscan")

    assert live.runpytest("-m", "not live").ret == pytest.ExitCode.OK


# --- HIGH-1：只有授權的 live 測試保留 Live 需要的變數 ---------------------------------------


def _visibility(live: pytest.Pytester, tmp_path: Path, *args: str) -> dict[str, set[str]]:
    record = tmp_path / "seen.txt"
    names = sorted(LIVE_PRESERVED_ENV | {"DB_PORT"})
    live.makepyfile(VISIBILITY.format(names=names, record=str(record)))
    live.runpytest(*args)
    seen: dict[str, set[str]] = {}
    for line in record.read_text(encoding="utf-8").splitlines():
        kind, _, listed = line.partition(":")
        seen[kind] = set(listed.split(",")) - {""}
    return seen


def test_authorized_live_tests_keep_the_variables_they_need(
    live: pytest.Pytester, tmp_path: Path
) -> None:
    """正向對照：授權的 live 測試看得到拋棄式目錄、compose 的秘密目錄與 bench 的金鑰檔；同一個
    session 的非 live 測試看不到；不在保留清單的變數（DB_PORT）兩者都看不到。"""
    seen = _visibility(live, tmp_path)

    assert seen["live"] == set(LIVE_PRESERVED_ENV)
    assert seen["not-live"] == set()


def test_unauthorized_live_tests_do_not_keep_them(
    live: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """沒有開關（make test 的情況）：live 標記的測試也一樣被隔離。"""
    monkeypatch.delenv("ENABLE_LIVE_LAB_TESTS")

    seen = _visibility(live, tmp_path)

    assert seen == {"live": set(), "not-live": set()}


@pytest.mark.parametrize("switch", ["", "1"], ids=["no-switch", "switch-without-live-tests"])
def test_the_live_environment_requires_an_authorized_session(
    live: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, switch: str
) -> None:
    """沒有開關，或開關是 1 卻沒有選中 live 的測試（R1 沒有檢查過）：都不提供 recipe 的環境。"""
    live.makepyfile(
        "from tests.live_session import live_environment\n"
        "def test_outside(request):\n"
        "    live_environment(request.config)\n"
    )
    monkeypatch.setenv("ENABLE_LIVE_LAB_TESTS", switch)

    result = live.runpytest()

    assert result.ret == pytest.ExitCode.TESTS_FAILED
    assert "授權的 Live session" in result.stdout.str()


def test_the_live_environment_is_the_recipe_environment(live: pytest.Pytester) -> None:
    """授權的 session：live_environment 是開始時的環境，不受每個測試的隔離影響（DB_PORT 仍在）。"""
    live.makepyfile(
        "import os, pytest\n"
        "from tests.live_session import live_environment\n"
        "@pytest.mark.live\n"
        "def test_live(request):\n"
        "    environment = live_environment(request.config)\n"
        "    assert environment['DB_PORT'] == '55434'\n"
        "    assert 'DB_PORT' not in os.environ\n"
    )

    assert live.runpytest().ret == pytest.ExitCode.OK
