"""tests/live/conftest.py 的 session 檢查（計畫 §3.1.1；§12.8 的 R1、修正 2、17）。

以 pytester 在暫存目錄執行一個小的 pytest session，conftest 的內容和 tests/live/conftest.py 相同。
只有 Live 的 recipe 設定的環境（ENABLE_LIVE_LAB_TESTS=1、pytest -m live）才判定；一般的非 Live
執行不受影響。
"""

from pathlib import Path

import pytest

LIVE_CONFTEST = (Path(__file__).resolve().parents[1] / "live" / "conftest.py").read_text(
    encoding="utf-8"
)
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
def test_live(tmp_path_factory):
    open({marker!r}, "w").write("ran")
"""


@pytest.fixture
def live(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> pytest.Pytester:
    pytester.makeini("[pytest]\nmarkers =\n    live: Live 測試\n")
    pytester.makeconftest(LIVE_CONFTEST)
    monkeypatch.setenv("ENABLE_LIVE_LAB_TESTS", "1")
    monkeypatch.setenv("SECSCAN_LIVE_PROJECT", "secscan-live")
    monkeypatch.setenv("SECSCAN_LIVE_SECRETS_DIR", str(tmp_path / "secscan-live-secrets.abc123"))
    return pytester


def test_a_passing_live_session_passes(live: pytest.Pytester) -> None:
    live.makepyfile(PASSING)

    assert live.runpytest("-m", "live").ret == pytest.ExitCode.OK


def test_an_all_skipped_live_session_fails(live: pytest.Pytester) -> None:
    """修正 2：ENABLE_LIVE_LAB_TESTS 沒有傳入等原因造成全部 skip 時，不能當成通過。"""
    live.makepyfile(SKIPPING)

    assert live.runpytest("-m", "live").ret == pytest.ExitCode.TESTS_FAILED


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("SECSCAN_LIVE_PROJECT", "secscan"),
        ("SECSCAN_LIVE_SECRETS_DIR", "/Users/someone/canary-dir-0005"),
        ("DB_PASSWORD", "canary-value-0007"),
    ],
    ids=["dev-project", "secrets-elsewhere", "secret-in-environment"],
)
def test_a_wrong_environment_stops_before_any_test_runs(
    live: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    variable: str,
    value: str,
) -> None:
    """R1：shell 中殘留的 SECSCAN_LIVE_PROJECT=secscan 會讓測試操作開發的專案：在副作用之前停止。"""
    marker = tmp_path / "ran"
    live.makepyfile(SIDE_EFFECT.format(marker=str(marker)))
    monkeypatch.setenv(variable, value)

    result = live.runpytest("-m", "live")

    assert result.ret == 3
    assert not marker.exists()
    output = result.stdout.str() + result.stderr.str()
    assert variable in output
    # 只輸出名稱（專案名稱 secscan 是 secscan-live 的一部分，不檢查）。
    if value != "secscan":
        assert value not in output


def test_a_non_live_session_is_not_affected(
    live: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    live.makepyfile(SKIPPING.replace("@pytest.mark.live\n", ""))
    monkeypatch.setenv("SECSCAN_LIVE_PROJECT", "secscan")

    assert live.runpytest("-m", "not live").ret == pytest.ExitCode.OK
