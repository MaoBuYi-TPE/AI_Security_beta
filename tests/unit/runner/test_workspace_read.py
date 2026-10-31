"""workspace 讀回 out/ 的檔案（capability probe，docs/DECISIONS.md §18.8）：不跟隨 symlink。"""

import os
import stat
from pathlib import Path
from uuid import uuid4

import pytest

from secscan.runner.workspace import Workspace, WorkspaceError

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


def _prepared(workspace: Workspace, dirs: tuple[Path, Path]) -> Path:
    workspace.prepare(RUN, ())
    return dirs[0] / str(RUN) / "out"


def test_an_output_file_is_read_up_to_the_limit(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    (out / "plugins.txt").write_bytes(b"spider-release-0.20.0.zap\n")

    assert workspace.read_output(RUN, "plugins.txt", max_bytes=1024) == (
        b"spider-release-0.20.0.zap\n"
    )
    assert workspace.read_output(RUN, "plugins.txt", max_bytes=4) is None
    assert workspace.read_output(RUN, "missing.txt", max_bytes=1024) is None


def test_reading_an_output_never_follows_a_symlink(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    secret = dirs[1] / "other"
    secret.write_bytes(b"token")
    (out / "plugins.txt").symlink_to(secret)
    (out / "fifo").mkdir()

    assert workspace.read_output(RUN, "plugins.txt", max_bytes=1024) is None
    assert workspace.read_output(RUN, "fifo", max_bytes=1024) is None


def test_reading_an_output_from_a_swapped_out_directory_fails(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    out.rmdir()
    target = dirs[1]
    (target / "plugins.txt").write_bytes(b"secret")
    out.symlink_to(target)

    assert workspace.read_output(RUN, "plugins.txt", max_bytes=1024) is None


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "../x", "x\x00"])
def test_only_plain_names_can_be_read(workspace: Workspace, name: str) -> None:
    with pytest.raises(ValueError, match="檔名"):
        workspace.read_output(RUN, name, max_bytes=1024)


def test_an_output_of_a_run_that_was_never_prepared_is_none(workspace: Workspace) -> None:
    assert workspace.read_output(uuid4(), "plugins.txt", max_bytes=1024) is None


def test_short_reads_are_joined_and_read_errors_are_none(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _prepared(workspace, dirs)
    (out / "plugins.txt").write_bytes(b"spider-release-0.20.0.zap\n")
    real_read = os.read

    def short(descriptor: int, size: int) -> bytes:
        return real_read(descriptor, min(size, 3))

    monkeypatch.setattr(os, "read", short)
    assert workspace.read_output(RUN, "plugins.txt", max_bytes=1024) == (
        b"spider-release-0.20.0.zap\n"
    )
    assert workspace.read_output(RUN, "plugins.txt", max_bytes=8) is None

    def failing(descriptor: int, size: int) -> bytes:
        raise OSError(5, "I/O error")

    monkeypatch.setattr(os, "read", failing)
    assert workspace.read_output(RUN, "plugins.txt", max_bytes=1024) is None


def test_a_secret_directory_that_cannot_be_created_is_a_workspace_error(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    dirs[1].chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(WorkspaceError, match="無法建立 secret 目錄"):
            workspace.create_secret_dir(RUN)
    finally:
        dirs[1].chmod(stat.S_IRWXU)
