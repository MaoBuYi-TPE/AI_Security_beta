"""run 的工作目錄、secret 檔與輸出的收集（docs/DECISIONS.md §14.5、SEC-18）。

runner 掛著整個 runs volume：收集時跟著工具建立的 symlink，就會讀到其他 run 的資料，所以一律不跟隨。
"""

import errno
import hashlib
import itertools
import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from secscan.runner.domain.admission import PROXY_FILE, SECRET_FILE
from secscan.runner.workspace import (
    MANIFEST_FILE,
    ArtifactIssue,
    ArtifactRejectedError,
    CollectionLimits,
    Workspace,
    WorkspaceError,
    _check_name,
)
from secscan.scanners.domain.plan import InputFile

RUN = uuid4()


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    runs, secrets = tmp_path / "runs", tmp_path / "secrets"
    runs.mkdir()
    secrets.mkdir()
    return runs, secrets


@pytest.fixture
def workspace(dirs: tuple[Path, Path]) -> Workspace:
    runs, secrets = dirs
    return Workspace(runs, secrets)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _out(dirs: tuple[Path, Path]) -> Path:
    return dirs[0] / str(RUN) / "out"


# --- 準備 ----------------------------------------------------------------------------------


def test_prepare_creates_private_directories_and_read_only_inputs(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    workspace.prepare(RUN, (InputFile("run.json", b'{"a": 1}'),))

    run_dir = dirs[0] / str(RUN)
    assert {path.name for path in run_dir.iterdir()} == {"in", "out"}
    for path in (run_dir, run_dir / "in", run_dir / "out"):
        assert _mode(path) == 0o700
    assert (run_dir / "in" / "run.json").read_bytes() == b'{"a": 1}'
    assert _mode(run_dir / "in" / "run.json") == 0o400


def test_a_run_directory_is_never_reused(workspace: Workspace) -> None:
    workspace.prepare(RUN, ())

    with pytest.raises(WorkspaceError):
        workspace.prepare(RUN, ())


# --- secret --------------------------------------------------------------------------------


def test_the_secret_is_a_read_only_file_in_its_own_volume(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    workspace.prepare(RUN, ())
    workspace.write_secrets(RUN, {SECRET_FILE: "Bearer canary-0001"})

    secret_dir = dirs[1] / str(RUN)
    secret = secret_dir / "target-auth"
    assert secret.read_text(encoding="utf-8") == "Bearer canary-0001"
    assert _mode(secret) == 0o400
    assert _mode(secret_dir) == 0o700
    assert "canary" not in "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (dirs[0] / str(RUN)).rglob("*")
        if path.is_file()
    )


def test_a_secret_is_never_overwritten(workspace: Workspace) -> None:
    workspace.write_secrets(RUN, {SECRET_FILE: "first"})

    with pytest.raises(WorkspaceError):
        workspace.write_secrets(RUN, {SECRET_FILE: "second"})


def test_discarding_the_secret_removes_it_and_is_idempotent(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    workspace.write_secrets(RUN, {SECRET_FILE: "value"})

    workspace.discard_secrets(RUN)
    workspace.discard_secrets(RUN)

    assert list(dirs[1].iterdir()) == []


def test_the_proxy_url_and_the_target_secret_share_the_run_directory(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    workspace.write_secrets(RUN, {PROXY_FILE: "http://run:token@guard:8080", SECRET_FILE: "x"})

    secret_dir = dirs[1] / str(RUN)
    assert sorted(path.name for path in secret_dir.iterdir()) == [PROXY_FILE, SECRET_FILE]
    assert {_mode(path) for path in secret_dir.iterdir()} == {0o400}


def test_discarding_removes_every_secret_file(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    """T10 只刪 target-auth：多一個檔案時 rmdir 失敗，目錄就留下來了（修正的回歸測試）。"""
    workspace.write_secrets(RUN, {PROXY_FILE: "proxy", SECRET_FILE: "x"})

    workspace.discard_secrets(RUN)

    assert list(dirs[1].iterdir()) == []


@pytest.mark.parametrize("files", [{}, {"other": "x"}, {PROXY_FILE: "x", "../escape": "y"}])
def test_only_known_secret_files_can_be_written(
    workspace: Workspace, dirs: tuple[Path, Path], files: dict[str, str]
) -> None:
    with pytest.raises(WorkspaceError):
        workspace.write_secrets(RUN, files)

    assert list(dirs[1].iterdir()) == []


def test_a_failure_on_the_second_file_leaves_nothing_behind(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = os.write
    calls: list[int] = []

    def second_fails(descriptor: int, data: bytes) -> int:
        calls.append(descriptor)
        if len(calls) > 1:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(descriptor, data)

    monkeypatch.setattr(os, "write", second_fails)

    with pytest.raises(WorkspaceError):
        workspace.write_secrets(RUN, {PROXY_FILE: "proxy", SECRET_FILE: "canary-0001"})

    assert list(dirs[1].iterdir()) == []


def test_sweeping_removes_secrets_left_by_a_previous_runner(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    for _ in range(3):
        workspace.write_secrets(uuid4(), {SECRET_FILE: "left over"})
    (dirs[1] / "stray").write_bytes(b"x")
    (dirs[1] / "link").symlink_to(dirs[0])

    assert workspace.sweep_secrets() == 5
    assert dirs[0].exists()
    assert list(dirs[1].iterdir()) == []


# --- 收集 ----------------------------------------------------------------------------------


def _prepared(workspace: Workspace, dirs: tuple[Path, Path]) -> Path:
    workspace.prepare(RUN, ())
    return _out(dirs)


def test_an_empty_output_is_collected(workspace: Workspace, dirs: tuple[Path, Path]) -> None:
    _prepared(workspace, dirs)

    manifest = workspace.collect(RUN)

    assert manifest.files == ()
    assert manifest.total_bytes == 0


def test_files_are_hashed_and_listed_outside_the_output(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    (out / "report.json").write_bytes(b"{}")
    (out / "nested").mkdir()
    (out / "nested" / "b.txt").write_bytes(b"hello")

    manifest = workspace.collect(RUN)

    assert [(item.path, item.size, item.sha256) for item in manifest.files] == [
        ("nested/b.txt", 5, hashlib.sha256(b"hello").hexdigest()),
        ("report.json", 2, hashlib.sha256(b"{}").hexdigest()),
    ]
    assert manifest.total_bytes == 7
    written = dirs[0] / str(RUN) / MANIFEST_FILE
    assert _mode(written) == 0o400
    assert json.loads(written.read_bytes()) == {
        "files": [
            {"path": "nested/b.txt", "sha256": hashlib.sha256(b"hello").hexdigest(), "size": 5},
            {"path": "report.json", "sha256": hashlib.sha256(b"{}").hexdigest(), "size": 2},
        ],
        "run_id": str(RUN),
        "total_bytes": 7,
    }


def _rejected(workspace: Workspace) -> ArtifactIssue:
    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN)
    return caught.value.issue


def test_a_symlink_to_another_runs_secret_is_not_followed(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    other = uuid4()
    workspace.write_secrets(other, {SECRET_FILE: "canary-other-run"})
    out = _prepared(workspace, dirs)
    (out / "steal").symlink_to(dirs[1] / str(other) / "target-auth")

    assert _rejected(workspace) is ArtifactIssue.SYMLINK


def test_a_symlinked_directory_is_rejected(workspace: Workspace, dirs: tuple[Path, Path]) -> None:
    out = _prepared(workspace, dirs)
    (out / "up").symlink_to(dirs[0])

    assert _rejected(workspace) is ArtifactIssue.SYMLINK


def test_an_output_directory_replaced_by_a_symlink_is_rejected(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    out.rmdir()
    out.symlink_to(dirs[1])

    assert _rejected(workspace) is ArtifactIssue.SYMLINK


def test_a_missing_output_directory_is_rejected(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    _prepared(workspace, dirs).rmdir()

    assert _rejected(workspace) is ArtifactIssue.MISSING_OUTPUT


def test_a_hardlink_is_rejected(workspace: Workspace, dirs: tuple[Path, Path]) -> None:
    out = _prepared(workspace, dirs)
    (out / "a").write_bytes(b"x")
    os.link(out / "a", out / "b")

    assert _rejected(workspace) is ArtifactIssue.HARDLINK


def test_a_fifo_is_rejected(workspace: Workspace, dirs: tuple[Path, Path]) -> None:
    out = _prepared(workspace, dirs)
    os.mkfifo(out / "pipe")

    assert _rejected(workspace) is ArtifactIssue.SPECIAL_FILE


@pytest.mark.parametrize("name", ["bad\nname", "tab\tname", "esc\x1bname"])
def test_names_with_control_characters_are_rejected(
    workspace: Workspace, dirs: tuple[Path, Path], name: str
) -> None:
    out = _prepared(workspace, dirs)
    (out / name).write_bytes(b"x")

    assert _rejected(workspace) is ArtifactIssue.NAME_NOT_ALLOWED


def test_names_that_are_not_utf8_are_rejected(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    try:
        descriptor = os.open(os.fsencode(out) + b"/\xff.bin", os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        pytest.skip("這個檔案系統不接受非 UTF-8 的檔名")
    os.close(descriptor)

    assert _rejected(workspace) is ArtifactIssue.NAME_NOT_ALLOWED


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_unreadable_output_is_rejected(
    workspace: Workspace, dirs: tuple[Path, Path], kind: str
) -> None:
    out = _prepared(workspace, dirs)
    target = out / "locked"
    if kind == "file":
        target.write_bytes(b"x")
    else:
        target.mkdir()
    target.chmod(0)
    try:
        assert _rejected(workspace) is ArtifactIssue.UNREADABLE
    finally:
        target.chmod(0o700)


def test_a_file_swapped_after_the_check_is_rejected(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """lstat 與開檔之間被換掉（例如換成 FIFO）：開檔之後以 fstat 再確認一次。"""
    out = _prepared(workspace, dirs)
    (out / "a").write_bytes(b"x")
    real_fstat = os.fstat

    def swapped(descriptor: int) -> os.stat_result:
        info = real_fstat(descriptor)
        fifo = stat.S_IFIFO | stat.S_IMODE(info.st_mode)
        return os.stat_result((fifo, *tuple(info)[1:]))

    monkeypatch.setattr(os, "fstat", swapped)

    assert _rejected(workspace) is ArtifactIssue.SPECIAL_FILE


def test_names_that_cannot_be_utf8_are_refused_by_the_check() -> None:
    """macOS 的檔案系統不接受非 UTF-8 的檔名（上一個測試在這裡會 skip）：直接檢查判斷的函式。"""
    with pytest.raises(ArtifactRejectedError) as caught:
        _check_name(os.fsdecode(b"\xff.bin"))

    assert caught.value.issue is ArtifactIssue.NAME_NOT_ALLOWED


def _limited(dirs: tuple[Path, Path], **limits: int) -> Workspace:
    return Workspace(dirs[0], dirs[1], limits=CollectionLimits(**limits))


def test_too_deep_is_rejected(dirs: tuple[Path, Path]) -> None:
    workspace = _limited(dirs, max_depth=2)
    out = _prepared(workspace, dirs)
    (out / "a" / "b" / "c").mkdir(parents=True)

    assert _rejected(workspace) is ArtifactIssue.TOO_DEEP


def test_too_many_entries_are_rejected(dirs: tuple[Path, Path]) -> None:
    workspace = _limited(dirs, max_entries=2)
    out = _prepared(workspace, dirs)
    for name in ("a", "b", "c"):
        (out / name).write_bytes(b"")

    assert _rejected(workspace) is ArtifactIssue.TOO_MANY_ENTRIES


def test_a_large_file_is_rejected(dirs: tuple[Path, Path]) -> None:
    workspace = _limited(dirs, max_file_bytes=4)
    out = _prepared(workspace, dirs)
    (out / "big").write_bytes(b"12345")

    assert _rejected(workspace) is ArtifactIssue.FILE_TOO_LARGE


def test_a_large_total_is_rejected(dirs: tuple[Path, Path]) -> None:
    workspace = _limited(dirs, max_total_bytes=6)
    out = _prepared(workspace, dirs)
    (out / "a").write_bytes(b"1234")
    (out / "b").write_bytes(b"1234")

    assert _rejected(workspace) is ArtifactIssue.TOTAL_TOO_LARGE


def test_limits_at_the_boundary_are_accepted(dirs: tuple[Path, Path]) -> None:
    workspace = _limited(dirs, max_depth=1, max_entries=3, max_file_bytes=4, max_total_bytes=8)
    out = _prepared(workspace, dirs)
    (out / "a").mkdir()
    (out / "a" / "x").write_bytes(b"1234")
    (out / "y").write_bytes(b"1234")

    assert workspace.collect(RUN).total_bytes == 8


def test_the_rejection_names_no_path(workspace: Workspace, dirs: tuple[Path, Path]) -> None:
    out = _prepared(workspace, dirs)
    (out / "secret-looking-name").symlink_to("/etc/passwd")

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN)

    assert "secret-looking-name" not in str(caught.value)
    assert "/etc" not in str(caught.value)


def test_an_existing_manifest_is_never_overwritten(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    """收集的結果不可變：manifest 已經存在（例如上一次收集留下的）就失敗，不覆寫。"""
    _prepared(workspace, dirs)
    manifest = dirs[0] / str(RUN) / MANIFEST_FILE
    manifest.write_bytes(b"{}")
    manifest.chmod(0o600)

    with pytest.raises(WorkspaceError):
        workspace.collect(RUN)

    assert manifest.read_bytes() == b"{}"


# --- 審查後補上：權限、條目數、寫入與執行中的用量 ----------------------------------------------


def test_a_directory_without_search_permission_is_unreadable(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    """r-- 的目錄列得出名稱，卻 stat 不到裡面的檔案（審查發現：原本拋出 PermissionError）。"""
    out = _prepared(workspace, dirs)
    locked = out / "d"
    locked.mkdir()
    (locked / "x").write_bytes(b"x")
    locked.chmod(0o400)
    try:
        assert _rejected(workspace) is ArtifactIssue.UNREADABLE
    finally:
        locked.chmod(0o700)


def test_directories_count_toward_the_entry_limit(dirs: tuple[Path, Path]) -> None:
    workspace = _limited(dirs, max_entries=2)
    out = _prepared(workspace, dirs)
    for name in ("a", "b", "c"):
        (out / name).mkdir()

    assert _rejected(workspace) is ArtifactIssue.TOO_MANY_ENTRIES


def test_the_walk_stops_at_the_limit_without_reading_the_whole_directory(
    dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """工具可以建立數百萬個條目：超過上限就停，不先把整個目錄的名稱讀進記憶體。"""
    workspace = _limited(dirs, max_entries=2)
    out = _prepared(workspace, dirs)
    (out / "a").write_bytes(b"")
    (out / "b").write_bytes(b"")
    real_scandir = os.scandir
    consumed: list[str] = []

    class Endless:
        def __init__(self, descriptor: int) -> None:
            self._real = real_scandir(descriptor)

        def __enter__(self) -> "Endless":
            return self

        def __exit__(self, *_exc: object) -> None:
            self._real.close()

        def __iter__(self) -> Iterator[object]:
            for entry in sorted(self._real, key=lambda item: item.name):
                consumed.append(entry.name)
                yield entry
            for index in itertools.count():
                consumed.append(f"ghost-{index}")
                yield SimpleNamespace(name=f"ghost-{index}")

    monkeypatch.setattr(os, "scandir", Endless)

    assert _rejected(workspace) is ArtifactIssue.TOO_MANY_ENTRIES
    assert len(consumed) == 3


@pytest.mark.parametrize("name", ["right\u202eto-left", "zero\u200bwidth", "\ufeffbom"])
def test_names_with_format_characters_are_rejected(
    workspace: Workspace, dirs: tuple[Path, Path], name: str
) -> None:
    """bidi 覆寫等格式字元會讓 manifest 與之後的報告顯示成另一個名稱（審查建議）。"""
    out = _prepared(workspace, dirs)
    (out / name).write_bytes(b"x")

    assert _rejected(workspace) is ArtifactIssue.NAME_NOT_ALLOWED


def _read_only(path: Path) -> Iterator[None]:
    path.chmod(0o500)
    try:
        yield
    finally:
        path.chmod(0o700)


def test_an_unwritable_runs_volume_is_a_workspace_error(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    for _ in _read_only(dirs[0]):
        with pytest.raises(WorkspaceError) as caught:
            workspace.prepare(RUN, (InputFile("run.json", b"{}"),))

    assert str(dirs[0]) not in str(caught.value)


def test_an_unwritable_secrets_volume_is_a_workspace_error(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    for _ in _read_only(dirs[1]):
        with pytest.raises(WorkspaceError) as caught:
            workspace.write_secrets(RUN, {SECRET_FILE: "canary-0001"})

    assert str(dirs[1]) not in str(caught.value)
    assert "canary" not in str(caught.value)


def test_a_full_disk_while_writing_the_secret_leaves_nothing_behind(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    def full(_descriptor: int, _data: bytes) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "write", full)

    with pytest.raises(WorkspaceError):
        workspace.write_secrets(RUN, {SECRET_FILE: "canary-0001"})

    assert list(dirs[1].iterdir()) == []


def test_short_writes_are_completed(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = os.write

    def one_byte(descriptor: int, data: bytes) -> int:
        return real_write(descriptor, bytes(data[:1]))

    monkeypatch.setattr(os, "write", one_byte)

    workspace.write_secrets(RUN, {SECRET_FILE: "Bearer canary-0001"})

    assert (dirs[1] / str(RUN) / "target-auth").read_text(encoding="utf-8") == "Bearer canary-0001"


def test_writability_is_checked_for_both_volumes(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    assert workspace.writable()
    for index in (0, 1):
        for _ in _read_only(dirs[index]):
            assert not workspace.writable()
    assert sorted(path.name for path in dirs[0].iterdir()) == []
    assert sorted(path.name for path in dirs[1].iterdir()) == []


def test_output_within_limits_is_accepted_while_running(dirs: tuple[Path, Path]) -> None:
    workspace = _limited(dirs, max_entries=2, max_total_bytes=8)
    out = _prepared(workspace, dirs)
    (out / "sub").mkdir()
    (out / "sub" / "a").write_bytes(b"1234")

    workspace.check_output(RUN)


@pytest.mark.parametrize(
    ("limits", "issue"),
    [
        ({"max_total_bytes": 4}, ArtifactIssue.TOTAL_TOO_LARGE),
        ({"max_entries": 1}, ArtifactIssue.TOO_MANY_ENTRIES),
        ({"max_depth": 0}, ArtifactIssue.TOO_DEEP),
    ],
)
def test_output_over_the_limits_is_caught_while_running(
    dirs: tuple[Path, Path], limits: dict[str, int], issue: ArtifactIssue
) -> None:
    """out/ 沒有磁碟配額：執行中就檢查用量，超過時 runner 停止容器（審查發現）。"""
    workspace = _limited(dirs, **limits)
    out = _prepared(workspace, dirs)
    (out / "sub").mkdir()
    (out / "sub" / "a").write_bytes(b"12345")

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.check_output(RUN)

    assert caught.value.issue is issue


def test_the_running_check_does_not_follow_symlinks(dirs: tuple[Path, Path]) -> None:
    workspace = _limited(dirs, max_total_bytes=100)
    big = dirs[0] / "big"
    big.write_bytes(b"x" * 1000)
    out = _prepared(workspace, dirs)
    (out / "link").symlink_to(big)

    workspace.check_output(RUN)


def test_an_unreadable_directory_while_running_is_rejected(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    hidden = out / "hidden"
    hidden.mkdir()
    hidden.chmod(0)
    try:
        with pytest.raises(ArtifactRejectedError) as caught:
            workspace.check_output(RUN)
    finally:
        hidden.chmod(0o700)

    assert caught.value.issue is ArtifactIssue.UNREADABLE


def test_collecting_a_run_without_a_directory_is_a_workspace_error(workspace: Workspace) -> None:
    with pytest.raises(WorkspaceError):
        workspace.collect(RUN)


@pytest.mark.parametrize("failing", ["scandir", "read", "open_and_stat"])
def test_io_errors_while_walking_are_unreadable(
    workspace: Workspace,
    dirs: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    failing: str,
) -> None:
    """消失或讀不到的條目（例如檔案系統錯誤）一律拒絕，不拋出含路徑的 OSError。"""
    out = _prepared(workspace, dirs)
    (out / "sub").mkdir()
    (out / "sub" / "a").write_bytes(b"x")
    real = {name: getattr(os, name) for name in ("scandir", "read", "open", "stat")}

    def broken(*_args: object, **_kwargs: object) -> object:
        raise OSError(errno.EIO, "I/O error")

    if failing == "scandir":
        calls: list[int] = []

        def second_scandir(descriptor: int) -> object:
            calls.append(descriptor)
            return broken() if len(calls) > 1 else real["scandir"](descriptor)

        monkeypatch.setattr(os, "scandir", second_scandir)
    elif failing == "read":
        monkeypatch.setattr(os, "read", broken)
    else:

        def no_sub(name: object, *args: object, **kwargs: object) -> object:
            if name == "sub":
                broken()
            return real["open"](name, *args, **kwargs)

        def stat_fails_for_sub(name: object, *args: object, **kwargs: object) -> object:
            if name == "sub" and not kwargs.get("follow_symlinks", True) and len(stats) > 0:
                broken()
            stats.append(1)
            return real["stat"](name, *args, **kwargs)

        stats: list[int] = []
        monkeypatch.setattr(os, "open", no_sub)
        monkeypatch.setattr(os, "stat", stat_fails_for_sub)

    assert _rejected(workspace) is ArtifactIssue.UNREADABLE


def test_a_secret_that_cannot_be_deleted_is_a_workspace_error(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    workspace.write_secrets(RUN, {SECRET_FILE: "canary-0001"})
    for _ in _read_only(dirs[1] / str(RUN)):
        with pytest.raises(WorkspaceError) as caught:
            workspace.discard_secrets(RUN)

    assert "canary" not in str(caught.value)
    assert str(dirs[1]) not in str(caught.value)
