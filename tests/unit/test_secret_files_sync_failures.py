"""sync-secret-files 中途失敗時的回報（G1d：安全 A1 的 LOW-1、LOW-4，程式碼審查 LOW-2）。

七個秘密檔各自原子替換，檔案之間不是交易。故障注入（write、暫存檔的 fsync、rename、rename 之後
目錄的 fsync、刪不掉的暫存檔、未預期的 stat 錯誤）之下，每個檔案都要回報：已更新、失敗（原本的
檔案沒有改變）、狀態不明，或沒有處理；DB 的密碼檔已更新或狀態不明時印出角色密碼的警告。

每個測試在自己的暫存目錄執行：.env 與秘密都是這次產生的 canary，不碰 repo 的 .env 與 secrets/。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import errno
import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from secscan.cli import EXIT_FAILURE, EXIT_OK
from secscan.cli.secret_files import (
    DB_ROLE_WARNING,
    SECRET_FILES,
    TEMP_PREFIX,
    Action,
    SecretSources,
)
from secscan.core.config import ENV_FILE
from tests.unit.test_secret_files_cli import ENV_NAMES, FILE_NAMES, Workspace, _leaks, _run


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


# --- 故障注入（G1d：部分寫入與錯誤回報；安全 A1 的 LOW-1、LOW-4，程式碼審查 LOW-2）---------------

REAL_RENAME = os.rename
REAL_FSYNC = os.fsync
REAL_UNLINK = os.unlink
REAL_STAT = os.stat
SKIPPED = f"：{Action.SKIPPED}"


def _oserror(code: int) -> OSError:
    return OSError(code, os.strerror(code))


def _raise(code: int) -> Callable[..., None]:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise _oserror(code)

    return fail


def _fail_rename_to(patch: pytest.MonkeyPatch, target: str, code: int) -> None:
    """只有 rename 成 target 時失敗（rename 沒有發生）。"""

    def rename(source: str, destination: str, *args: object, **kwargs: object) -> None:
        if destination == target:
            raise _oserror(code)
        REAL_RENAME(source, destination, *args, **kwargs)  # type: ignore[arg-type]

    patch.setattr(os, "rename", rename)


def _fail_directory_fsync_after(patch: pytest.MonkeyPatch, target: str) -> None:
    """rename 成 target 之後，目錄的 fsync 失敗（rename 已經完成）。"""
    renamed: list[str] = []

    def rename(source: str, destination: str, *args: object, **kwargs: object) -> None:
        REAL_RENAME(source, destination, *args, **kwargs)  # type: ignore[arg-type]
        renamed.append(destination)

    def fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode) and renamed[-1:] == [target]:
            raise _oserror(errno.EIO)
        REAL_FSYNC(descriptor)

    patch.setattr(os, "rename", rename)
    patch.setattr(os, "fsync", fsync)


def _change(workspace: Workspace, *names: str) -> dict[str, str]:
    """只換 names 的值；回傳換之前的值。"""
    previous = workspace.values
    workspace.write_env(**{name: previous[name] for name in ENV_NAMES if name not in names})
    return previous


def _temporaries(workspace: Workspace) -> list[str]:
    return [name for name in os.listdir(workspace.secrets) if name.startswith(TEMP_PREFIX)]


@pytest.mark.parametrize(
    ("failing", "code"),
    [("write", errno.EIO), ("fsync", errno.EIO), ("rename", errno.EACCES)],
    ids=["write", "fsync-of-the-temporary", "rename"],
)
def test_a_failure_before_the_rename_keeps_the_old_file(
    workspace: Workspace,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    failing: str,
    code: int,
) -> None:
    _run(capsys)
    old = workspace.file("db_password").read_bytes()
    previous = _change(workspace, "DB_PASSWORD")

    monkeypatch.setattr(os, failing, _raise(code))
    exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    assert f"db_password：{Action.FAILED}" in err
    assert "原本的檔案沒有改變" in err
    assert "沒有更新任何檔案" in err
    assert workspace.file("db_password").read_bytes() == old
    assert _temporaries(workspace) == []
    # DB 的密碼檔沒有改變：不需要角色密碼的警告。
    assert DB_ROLE_WARNING not in err
    for name in FILE_NAMES[:3]:
        assert f"{name}：{Action.UNCHANGED}" in err
    for name in FILE_NAMES[4:]:
        assert f"{name}{SKIPPED}" in err
    assert _leaks(err, workspace.values | {"old": previous["DB_PASSWORD"]}) == []


def test_an_io_error_from_rename_is_reported_as_uncertain(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSIX 只保證 EIO 以外的 rename 失敗不影響目標：EIO 時不宣稱原本的檔案沒有改變。"""
    _run(capsys)
    _change(workspace, "DB_PASSWORD")
    _fail_rename_to(monkeypatch, "db_password", errno.EIO)

    exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    assert f"db_password：{Action.UNCERTAIN}" in err
    assert "原本的檔案沒有改變" not in err
    assert "無法確認" in err
    assert DB_ROLE_WARNING in err
    assert _temporaries(workspace) == []


def test_an_io_error_from_rename_reports_a_temporary_it_cannot_remove(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    """審查（程式碼 LOW-2、安全 INFO-4）：EIO 的路徑和 rename 之前失敗的路徑一樣，刪不掉的暫存檔
    要回報，不靜默忽略。"""
    _run(capsys)
    previous = _change(workspace, "DB_PASSWORD")

    def unlink(path: str, *args: object, **kwargs: object) -> None:
        if str(path).startswith(TEMP_PREFIX):
            raise _oserror(errno.EACCES)
        REAL_UNLINK(path, *args, **kwargs)  # type: ignore[arg-type]

    with pytest.MonkeyPatch.context() as patch:
        _fail_rename_to(patch, "db_password", errno.EIO)
        patch.setattr(os, "unlink", unlink)
        exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    assert f"db_password：{Action.UNCERTAIN}" in err
    assert "暫存檔可能留著" in err
    assert len(_temporaries(workspace)) == 1
    assert _leaks(err, workspace.values | {"old": previous["DB_PASSWORD"]}) == []


def test_a_failed_directory_fsync_after_the_rename_is_not_reported_as_unchanged(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """安全 A1 的 LOW-4：rename 之後目錄的 fsync 失敗時，檔案已是新的內容，只是無法確認已寫入
    磁碟。"""
    _run(capsys)
    previous = _change(workspace, "DB_PASSWORD")
    _fail_directory_fsync_after(monkeypatch, "db_password")

    exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    assert workspace.file("db_password").read_bytes() == workspace.values["DB_PASSWORD"].encode()
    assert f"db_password：{Action.UNCERTAIN}" in err
    assert "原本的檔案沒有改變" not in err
    assert "已換成新的內容" in err
    assert "無法確認已寫入磁碟" in err
    assert "只更新了一部分" in err
    assert DB_ROLE_WARNING in err
    for name in FILE_NAMES[4:]:
        assert f"{name}{SKIPPED}" in err
    assert _leaks(err, workspace.values | {"old": previous["DB_PASSWORD"]}) == []


def test_an_uncertain_key_file_does_not_warn_about_db_passwords(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(capsys)
    _change(workspace, "CONTENT_ENCRYPTION_KEYS")
    _fail_directory_fsync_after(monkeypatch, "content_encryption_keys")

    exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    assert f"content_encryption_keys：{Action.UNCERTAIN}" in err
    assert DB_ROLE_WARNING not in err


def test_a_failure_part_way_reports_what_was_updated_and_what_was_not(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """安全 A1 的 LOW-1：中途失敗時，已更新的檔案（含 DB 的密碼檔）要回報，也不得說沒有寫入任何
    檔案。

    七個檔案各自原子替換，跨檔案不是交易：失敗之前的已經是新的內容，之後的維持原狀。
    """
    _run(capsys)
    before = {name: workspace.file(name).read_bytes() for name in FILE_NAMES}
    previous = workspace.values
    workspace.write_env()
    _fail_rename_to(monkeypatch, "secret_encryption_keys", errno.EACCES)

    exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    for item in SECRET_FILES[:4]:
        new = workspace.values[item.env_name].encode()
        assert f"{item.file_name}：{Action.UPDATED}" in err
        assert workspace.file(item.file_name).read_bytes() == new
    assert f"secret_encryption_keys：{Action.FAILED}" in err
    for name in FILE_NAMES[4:]:
        assert workspace.file(name).read_bytes() == before[name]
    for name in FILE_NAMES[5:]:
        assert f"{name}{SKIPPED}" in err
    assert DB_ROLE_WARNING in err
    assert "只更新了一部分" in err
    assert "沒有寫入任何檔案" not in err
    assert "沒有更新任何檔案" not in err
    old = {f"old-{name}": value for name, value in previous.items()}
    assert _leaks(err, workspace.values | old) == []


def test_a_temporary_that_cannot_be_removed_does_not_hide_the_original_error(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    """程式碼審查 LOW-2：刪不掉暫存檔時，回報原本的錯誤與暫存檔可能留著；下一次執行時清除。"""
    _run(capsys)
    old = workspace.file("db_password").read_bytes()
    _change(workspace, "DB_PASSWORD")

    def unlink(path: str, *args: object, **kwargs: object) -> None:
        if str(path).startswith(TEMP_PREFIX):
            raise _oserror(errno.EACCES)
        REAL_UNLINK(path, *args, **kwargs)  # type: ignore[arg-type]

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "write", _raise(errno.EIO))
        patch.setattr(os, "unlink", unlink)
        exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    assert os.strerror(errno.EIO) in err
    assert "暫存檔" in err
    assert workspace.file("db_password").read_bytes() == old
    assert len(_temporaries(workspace)) == 1

    exit_code, err = _run(capsys)

    assert exit_code == EXIT_OK
    assert f"db_password：{Action.UPDATED}" in err
    assert _temporaries(workspace) == []


def test_an_unexpected_stat_error_is_reported_with_the_status_so_far(
    workspace: Workspace, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """程式碼審查 LOW-2：未預期的 OSError 不以 traceback 結束，之前與之後的檔案照樣回報。"""
    _run(capsys)

    def refuse(path: object, *args: object, **kwargs: object) -> os.stat_result:
        if path == "db_password" and kwargs.get("dir_fd") is not None:
            raise _oserror(errno.EACCES)
        return REAL_STAT(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "stat", refuse)
    exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    assert "無法確認 db_password" in err
    assert f"db_password：{Action.FAILED}" in err
    assert f"db_admin_password：{Action.UNCHANGED}" in err
    assert f"content_encryption_keys{SKIPPED}" in err


def test_a_failure_before_any_file_writes_nothing(
    workspace: Workspace, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace.secrets.mkdir(mode=0o700)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "listdir", _raise(errno.EIO))
        exit_code, err = _run(capsys)

    assert exit_code == EXIT_FAILURE
    # 審查（程式碼 LOW-1）：其他提早結束的路徑也說「沒有寫入任何檔案」，所以一併確認是這一步。
    assert "無法清除上次留下的暫存檔" in err
    assert "沒有寫入任何檔案" in err
    assert os.listdir(workspace.secrets) == []
