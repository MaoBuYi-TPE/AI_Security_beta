"""Live 測試 session 的前提（tests/live_session.py；計畫 §3.1.1；R1、修正 2、17；G1 審查
HIGH-1、M3）。

以 pytester 在暫存目錄執行小的 pytest session：conftest 載入 tests.live_session，並沿用
tests/conftest.py 的 _isolate_app_settings（autouse）。判定的條件是「開關是 1，而且選中了 live 標記
的測試」，不看 -m 的文字。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

from pathlib import Path

import pytest

from tests import live_session
from tests.live_session import DEFAULT_TMPDIR, LIVE_PRESERVED_ENV, live_session_problems

MAKEFILE = (Path(__file__).resolve().parents[2] / "Makefile").read_text(encoding="utf-8")

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
MODULE_SKIPPED = """
import pytest

pytest.skip("整個模組的前提不成立", allow_module_level=True)
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
    disposable = tmp_path / "secscan-live-secrets.abc123"
    disposable.mkdir()
    disposable.chmod(0o700)
    directory = str(disposable)
    monkeypatch.setenv("SECSCAN_LIVE_SECRETS_DIR", directory)
    monkeypatch.setenv("SECSCAN_SECRETS_DIR", directory)
    # recipe 的拋棄式目錄直接在 TMPDIR 之下（R1 核對；TMPDIR 以 / 結尾也一樣）。
    monkeypatch.setenv("TMPDIR", f"{tmp_path}/")
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


def test_a_live_module_skipped_at_collection_fails_the_session(live: pytest.Pytester) -> None:
    """第二輪程式碼審查 LOW-1：模組整個被 skip（收集階段，沒有測試與 live 標記）不能假通過。"""
    live.makepyfile(test_passing=PASSING, test_skipped_module=MODULE_SKIPPED)

    assert live.runpytest("-m", "live").ret == pytest.ExitCode.TESTS_FAILED


def test_a_module_skip_outside_a_live_session_is_not_affected_positive_control(
    live: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """沒有開關（不是授權的 Live session）：同樣的檔案照 pytest 的規則通過。"""
    live.makepyfile(test_passing=PASSING, test_skipped_module=MODULE_SKIPPED)
    monkeypatch.delenv("ENABLE_LIVE_LAB_TESTS")

    assert live.runpytest("-m", "live").ret == pytest.ExitCode.OK


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


# --- R1：Live 的 pytest 開始時的環境（live_session_problems）-------------------------------------

DIRECTORY = "secscan-live-secrets.abc123"


def _live_environment(tmp_path: Path, **changes: str | None) -> dict[str, str]:
    """recipe 的環境：拋棄式目錄實際存在（mktemp -d 建立的 0700 目錄）。"""
    disposable = tmp_path / DIRECTORY
    disposable.mkdir(exist_ok=True)
    disposable.chmod(0o700)
    directory = str(disposable)
    environ = {
        "SECSCAN_LIVE_PROJECT": "secscan-live",
        "SECSCAN_LIVE_SECRETS_DIR": directory,
        "SECSCAN_SECRETS_DIR": directory,
        "TMPDIR": f"{tmp_path}/",
        "PATH": "/bin",
    }
    for key, value in changes.items():
        if value is None:
            environ.pop(key, None)
        else:
            environ[key] = value.replace("{tmp}", str(tmp_path))
    return environ


def test_the_live_session_environment_passes(tmp_path: Path) -> None:
    """TMPDIR 以 / 結尾、SECSCAN_SECRETS_DIR 以 / 結尾也一樣（normpath 之後相同）。"""
    changes = {"SECSCAN_SECRETS_DIR": f"{tmp_path / DIRECTORY}/"}

    assert live_session_problems(_live_environment(tmp_path, **changes)) == []


def test_without_tmpdir_the_recipe_default_is_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TMPDIR 沒有設定時和 recipe 一樣以 /tmp 為準（以暫存目錄代替 /tmp）。"""
    monkeypatch.setattr(live_session, "DEFAULT_TMPDIR", str(tmp_path))

    assert live_session_problems(_live_environment(tmp_path, TMPDIR=None)) == []
    assert "$${TMPDIR:-" + DEFAULT_TMPDIR + "}" in MAKEFILE


@pytest.mark.parametrize("kind", ["missing", "symlink", "file", "group-readable"])
def test_the_disposable_directory_must_be_a_private_directory(tmp_path: Path, kind: str) -> None:
    """第二輪安全 LOW-4：只比對字面時，指向 secrets/ 的 symlink 或不存在的路徑也會通過。"""
    environ = _live_environment(tmp_path)
    disposable = tmp_path / DIRECTORY
    if kind == "group-readable":
        disposable.chmod(0o750)
    else:
        disposable.rmdir()
    if kind == "symlink":
        (tmp_path / "secrets").mkdir(mode=0o700)
        disposable.symlink_to(tmp_path / "secrets")
    if kind == "file":
        disposable.write_text("x", encoding="ascii")

    assert "SECSCAN_LIVE_SECRETS_DIR" in live_session_problems(environ)


@pytest.mark.parametrize(
    ("changes", "problem"),
    [
        ({"SECSCAN_LIVE_PROJECT": "secscan"}, "SECSCAN_LIVE_PROJECT"),
        ({"SECSCAN_LIVE_PROJECT": None}, "SECSCAN_LIVE_PROJECT"),
        ({"SECSCAN_LIVE_PROJECT": "secscan-live-x"}, "SECSCAN_LIVE_PROJECT"),
        ({"SECSCAN_LIVE_SECRETS_DIR": "/Users/someone/secrets"}, "SECSCAN_LIVE_SECRETS_DIR"),
        ({"SECSCAN_LIVE_SECRETS_DIR": None}, "SECSCAN_LIVE_SECRETS_DIR"),
        (
            {"SECSCAN_LIVE_SECRETS_DIR": f"{{tmp}}/{DIRECTORY}/../../etc/{DIRECTORY}"},
            "SECSCAN_LIVE_SECRETS_DIR",
        ),
        ({"SECSCAN_LIVE_SECRETS_DIR": f"{{tmp}}/x/../{DIRECTORY}"}, "SECSCAN_LIVE_SECRETS_DIR"),
        ({"SECSCAN_LIVE_SECRETS_DIR": DIRECTORY}, "SECSCAN_LIVE_SECRETS_DIR"),
        ({"SECSCAN_LIVE_SECRETS_DIR": f"/srv/{DIRECTORY}"}, "SECSCAN_LIVE_SECRETS_DIR"),
        ({"SECSCAN_LIVE_SECRETS_DIR": "{tmp}/secscan-live-secrets.ab"}, "SECSCAN_LIVE_SECRETS_DIR"),
        ({"SECSCAN_SECRETS_DIR": "./secrets"}, "SECSCAN_SECRETS_DIR"),
        ({"SECSCAN_SECRETS_DIR": None}, "SECSCAN_SECRETS_DIR"),
        ({"DB_PASSWORD": "x"}, "DB_PASSWORD"),
        ({"db_password": "x"}, "db_password"),
        ({"Content_Encryption_Keys_File": "/x"}, "Content_Encryption_Keys_File"),
    ],
    ids=[
        "dev-project",
        "no-project",
        "other-live-project",
        "secrets-elsewhere",
        "no-secrets",
        "dot-dot-escape",
        "dot-dot-inside",
        "relative",
        "outside-tmpdir",
        "bad-name",
        "compose-secrets-elsewhere",
        "no-compose-secrets",
        "secret",
        "secret-lowercase",
        "secret-file-mixed-case",
    ],
)
def test_a_live_session_with_the_wrong_environment_is_refused(
    tmp_path: Path, changes: dict[str, str | None], problem: str
) -> None:
    """R1、修正 17、第二輪安全 LOW-3：路徑以 run_id 的規則核對（..、相對路徑、TMPDIR 之外都拒絕），
    compose 的秘密目錄必須是同一個，秘密的名稱不分大小寫。"""
    assert problem in live_session_problems(_live_environment(tmp_path, **changes))


@pytest.mark.parametrize("kind", ["dot-dot-inside", "outside-tmpdir"])
def test_a_real_private_directory_reached_by_another_path_is_refused(
    tmp_path: Path, kind: str
) -> None:
    """路徑規則本身（不靠 lstat；空轉檢查 58a、58d）：目錄真的存在、是自己擁有的 0700 目錄，經由 ..
    到達，或不在 TMPDIR 之下，都拒絕。"""
    if kind == "dot-dot-inside":
        (tmp_path / "x").mkdir()
        path = f"{tmp_path}/x/../{DIRECTORY}"
    else:
        elsewhere = tmp_path / "elsewhere" / DIRECTORY
        elsewhere.mkdir(parents=True)
        elsewhere.chmod(0o700)
        path = str(elsewhere)
    environ = _live_environment(tmp_path, SECSCAN_LIVE_SECRETS_DIR=path, SECSCAN_SECRETS_DIR=path)

    assert "SECSCAN_LIVE_SECRETS_DIR" in live_session_problems(environ)


@pytest.mark.parametrize("suffix", ["/", "/.", "//"])
def test_a_symlink_is_refused_whatever_the_trailing_characters(tmp_path: Path, suffix: str) -> None:
    """程式碼審查第三次的 LOW-1：結尾的 /、/.、// 讓 lstat 跟著最後的 symlink（指向 secrets/）。"""
    environ = _live_environment(tmp_path)
    disposable = tmp_path / DIRECTORY
    disposable.rmdir()
    (tmp_path / "secrets").mkdir(mode=0o700)
    disposable.symlink_to(tmp_path / "secrets")
    path = f"{disposable}{suffix}"
    environ.update(SECSCAN_LIVE_SECRETS_DIR=path, SECSCAN_SECRETS_DIR=path)

    assert "SECSCAN_LIVE_SECRETS_DIR" in live_session_problems(environ)


def test_the_compose_secrets_directory_cannot_reach_secrets_through_dot_dot(
    tmp_path: Path,
) -> None:
    """最後一次的安全審查 INFO-1：`<拋棄式目錄>/x/..`（x 指向 secrets/ 之下）在字面上正規化成拋棄式
    目錄，作業系統卻解析到 secrets/：SECSCAN_SECRETS_DIR 有 .. 就拒絕。"""
    environ = _live_environment(tmp_path)
    (tmp_path / "secrets" / "sub").mkdir(parents=True)
    (tmp_path / DIRECTORY / "x").symlink_to(tmp_path / "secrets" / "sub")
    environ["SECSCAN_SECRETS_DIR"] = f"{tmp_path / DIRECTORY}/x/.."

    assert live_session_problems(environ) == ["SECSCAN_SECRETS_DIR"]
