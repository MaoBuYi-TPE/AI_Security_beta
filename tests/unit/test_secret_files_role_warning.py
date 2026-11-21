"""sync-secret-files 的角色密碼警告（G1e：G1d 安全審查的 LOW-3）。

db 的角色密碼只在第一次初始化時建立：db 已經初始化時，secrets/ 中 db 的密碼檔不論是「新增」（例如
刪掉 secrets/ 之後又改了 .env）還是「更新」，都不會改變 DB 中的密碼。所以 db 的三個密碼檔新增、
更新或狀態不明時都印出警告；沒有改變（不變、只修正權限、rename 之前就失敗）時不印出。不輸出值、
不碰 DB。

每個測試在自己的暫存目錄執行：.env 與秘密都是這次產生的 canary，不碰 repo 的 .env 與 secrets/。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import errno
from pathlib import Path

import pytest

from secscan.cli import EXIT_FAILURE, EXIT_OK
from secscan.cli.secret_files import DB_ROLE_FILES, DB_ROLE_WARNING, Action, SecretSources
from secscan.core.config import ENV_FILE
from tests.unit.test_secret_files_cli import ENV_NAMES, Workspace, _leaks, _run
from tests.unit.test_secret_files_sync_failures import _change, _fail_rename_to

NON_DB_FILES = ("test_db_password", "content_encryption_keys")


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Workspace:
    """和 test_secret_files_cli 的 workspace 相同：只讀暫存目錄的 .env，清掉同名的環境變數。"""
    monkeypatch.setitem(SecretSources.model_config, "env_file", ENV_FILE)
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    space = Workspace(tmp_path)
    space.write_env()
    return space


def test_the_warning_covers_files_that_are_added_as_well_as_updated() -> None:
    assert "新增或更新" in DB_ROLE_WARNING
    assert "請確認兩者一致" in DB_ROLE_WARNING


def test_the_first_sync_warns_because_the_db_password_files_are_added(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    """G2 第一次執行 make secrets 時，db 的密碼檔都是新增：印出警告（預期的行為）。"""
    code, err = _run(capsys)

    assert code == EXIT_OK
    for name in sorted(DB_ROLE_FILES):
        assert f"{name}：{Action.ADDED}" in err
    assert DB_ROLE_WARNING in err
    assert _leaks(err, workspace.values) == []


@pytest.mark.parametrize("name", sorted(DB_ROLE_FILES))
def test_adding_back_a_db_password_file_warns(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    """secrets/ 中 db 的密碼檔不見了、.env 的值也換過：新增的檔案和 DB 中的密碼可能不同。"""
    _run(capsys)
    env_name = next(env for env in ENV_NAMES if env.lower() == name)
    previous = _change(workspace, env_name)
    workspace.file(name).unlink()

    code, err = _run(capsys)

    assert code == EXIT_OK
    assert f"{name}：{Action.ADDED}" in err
    assert DB_ROLE_WARNING in err
    assert _leaks(err, workspace.values | {"old": previous[env_name]}) == []


@pytest.mark.parametrize("name", NON_DB_FILES)
def test_adding_back_a_file_that_is_not_a_db_role_password_does_not_warn(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    _run(capsys)
    workspace.file(name).unlink()

    code, err = _run(capsys)

    assert code == EXIT_OK
    assert f"{name}：{Action.ADDED}" in err
    assert DB_ROLE_WARNING not in err


def test_an_add_that_fails_before_the_rename_does_not_warn(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """rename 之前失敗：檔案沒有建立，以實際的動作（失敗）判斷，不印出警告。"""
    _run(capsys)
    workspace.file("db_password").unlink()
    _fail_rename_to(monkeypatch, "db_password", errno.EACCES)

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert f"db_password：{Action.FAILED}" in err
    assert not workspace.file("db_password").exists()
    assert DB_ROLE_WARNING not in err
    assert _leaks(err, workspace.values) == []


def test_an_add_whose_rename_reports_eio_warns(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """rename 回報 EIO：檔案可能已經建立（狀態不明），印出警告。"""
    _run(capsys)
    workspace.file("db_owner_password").unlink()
    _fail_rename_to(monkeypatch, "db_owner_password", errno.EIO)

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert f"db_owner_password：{Action.UNCERTAIN}" in err
    assert DB_ROLE_WARNING in err


def test_an_added_db_password_file_warns_even_when_a_later_file_fails(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """中途失敗時，之前已經新增的 db 密碼檔仍然要警告（以每個檔案實際的動作判斷）。"""
    _run(capsys)
    workspace.file("db_password").unlink()
    _change(workspace, "SECRET_ENCRYPTION_KEYS")
    _fail_rename_to(monkeypatch, "secret_encryption_keys", errno.EACCES)

    code, err = _run(capsys)

    assert code == EXIT_FAILURE
    assert f"db_password：{Action.ADDED}" in err
    assert f"secret_encryption_keys：{Action.FAILED}" in err
    assert DB_ROLE_WARNING in err
