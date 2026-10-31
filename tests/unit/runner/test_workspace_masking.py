"""收集時以已知的 secret 遮罩輸出（docs/DECISIONS.md §19.5；只有 redact_outputs 的引擎）。

先走訪、驗證完才動檔案；遮罩後的內容以暫存檔取代原檔，manifest 記下遮罩後的 hash 與次數。
"""

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from secscan.runner.workspace import (
    MANIFEST_FILE,
    ArtifactIssue,
    ArtifactRejectedError,
    CollectionLimits,
    Workspace,
    WorkspaceError,
)
from secscan.security.secret_masking import PROXY_TOKEN_MARK, TARGET_SECRET_MARK, SecretMasker

RUN = uuid4()
SECRET = "canary-secret-value"
TOKEN = "canary-proxy-token"
MARK = TARGET_SECRET_MARK.encode()
MASKER = SecretMasker.of({TARGET_SECRET_MARK: (SECRET,), PROXY_TOKEN_MARK: (TOKEN,)})
CHUNK = 1024 * 1024


@pytest.fixture
def dirs(tmp_path: Path) -> tuple[Path, Path]:
    runs, secrets = tmp_path / "runs", tmp_path / "secrets"
    runs.mkdir()
    secrets.mkdir()
    return runs, secrets


@pytest.fixture
def workspace(dirs: tuple[Path, Path]) -> Workspace:
    return Workspace(*dirs)


def _prepared(workspace: Workspace, dirs: tuple[Path, Path]) -> Path:
    workspace.prepare(RUN, ())
    return dirs[0] / str(RUN) / "out"


def _files(run_dir: Path) -> set[str]:
    return {item.name for item in run_dir.iterdir()}


def test_the_secret_is_gone_and_the_manifest_describes_the_masked_file(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(f"a {SECRET} b {SECRET} c {TOKEN} d".encode())

    manifest = workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    content = (out / "zap.log").read_bytes()
    assert (
        content == f"a {TARGET_SECRET_MARK} b {TARGET_SECRET_MARK} c {PROXY_TOKEN_MARK} d".encode()
    )
    [entry] = manifest.files
    assert entry.size == len(content)
    assert entry.sha256 == hashlib.sha256(content).hexdigest()
    assert entry.redactions == 3
    assert manifest.total_bytes == len(content)
    document = json.loads((out.parent / MANIFEST_FILE).read_text())
    assert document["files"][0]["redactions"] == 3
    assert document["files"][0]["sha256"] == entry.sha256


def test_every_file_is_masked_also_in_subdirectories(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    (out / "sub" / "deeper").mkdir(parents=True)
    (out / "a.json").write_text(json.dumps({"k": f'x"{SECRET}'}))
    (out / "sub" / "deeper" / "b.txt").write_text(SECRET)

    manifest = workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert SECRET.encode() not in (out / "a.json").read_bytes()
    assert (out / "sub" / "deeper" / "b.txt").read_bytes() == MARK
    assert {entry.path: entry.redactions for entry in manifest.files} == {
        "a.json": 1,
        "sub/deeper/b.txt": 1,
    }


def test_a_secret_across_two_chunks_is_masked(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    data = b"x" * (CHUNK - 5) + SECRET.encode() + b"y" * 100
    (out / "big.log").write_bytes(data)

    manifest = workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert (out / "big.log").read_bytes() == b"x" * (CHUNK - 5) + MARK + b"y" * 100
    assert manifest.files[0].redactions == 1


def test_a_file_without_secrets_keeps_its_content(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    (out / "clean.log").write_bytes(b"nothing here\n")
    (out / "empty.log").write_bytes(b"")

    manifest = workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert (out / "clean.log").read_bytes() == b"nothing here\n"
    assert [(entry.path, entry.redactions) for entry in manifest.files] == [
        ("clean.log", 0),
        ("empty.log", 0),
    ]


def test_without_a_masker_the_output_is_not_touched(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    """preflight 存原始的 HTTP 回應（§16.5）：遮罩會讓 Content-Length 不符。"""
    out = _prepared(workspace, dirs)
    (out / "response").write_bytes(SECRET.encode())

    manifest = workspace.collect(RUN, exit_code=0, inputs=())

    assert (out / "response").read_bytes() == SECRET.encode()
    assert manifest.files[0].redactions == 0


def test_nothing_is_left_beside_the_output(workspace: Workspace, dirs: tuple[Path, Path]) -> None:
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(SECRET.encode())

    workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert _files(out.parent) == {"in", "out", MANIFEST_FILE}
    assert _files(out) == {"zap.log"}


def test_growing_past_the_file_limit_is_rejected(dirs: tuple[Path, Path]) -> None:
    workspace = Workspace(*dirs, limits=CollectionLimits(max_file_bytes=len(SECRET) + 4))
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(SECRET.encode())

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert caught.value.issue is ArtifactIssue.FILE_TOO_LARGE
    assert _files(out.parent) == {"in", "out"}


def test_growing_past_the_total_limit_is_rejected(dirs: tuple[Path, Path]) -> None:
    limits = CollectionLimits(max_total_bytes=2 * len(SECRET) + 4)
    workspace = Workspace(*dirs, limits=limits)
    out = _prepared(workspace, dirs)
    (out / "a.log").write_bytes(SECRET.encode())
    (out / "b.log").write_bytes(SECRET.encode())

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert caught.value.issue is ArtifactIssue.TOTAL_TOO_LARGE


def test_the_rules_of_the_walk_still_apply(workspace: Workspace, dirs: tuple[Path, Path]) -> None:
    out = _prepared(workspace, dirs)
    (out / "link").symlink_to("/etc/hosts")

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert caught.value.issue is ArtifactIssue.SYMLINK


def test_a_hardlink_is_rejected_before_anything_changes(
    workspace: Workspace, dirs: tuple[Path, Path], tmp_path: Path
) -> None:
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(SECRET.encode())
    os.link(out / "zap.log", tmp_path / "elsewhere")

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert caught.value.issue is ArtifactIssue.HARDLINK
    assert (out / "zap.log").read_bytes() == SECRET.encode()


def _swap_after_walking(monkeypatch: pytest.MonkeyPatch, swap: Callable[[], None]) -> None:
    """走訪之後、遮罩之前換掉檔案（容器已刪除，只有縱深防禦）。"""
    walk = Workspace._walk_output

    def walked(self: Workspace, run_id: object, state: object) -> None:
        walk(self, run_id, state)  # type: ignore[arg-type]
        swap()

    monkeypatch.setattr(Workspace, "_walk_output", walked)


def test_a_file_replaced_by_a_symlink_after_the_walk_is_rejected(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(b"x")

    def swap() -> None:
        (out / "zap.log").unlink()
        (out / "zap.log").symlink_to("/etc/hosts")

    _swap_after_walking(monkeypatch, swap)

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert caught.value.issue is ArtifactIssue.SYMLINK


def test_a_file_hardlinked_after_the_walk_is_rejected(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(b"x")
    _swap_after_walking(monkeypatch, lambda: os.link(out / "zap.log", tmp_path / "elsewhere"))

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert caught.value.issue is ArtifactIssue.HARDLINK


def test_a_directory_replaced_after_the_walk_is_rejected(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    out = _prepared(workspace, dirs)
    (out / "sub").mkdir()
    (out / "sub" / "a.log").write_bytes(b"x")

    def swap() -> None:
        (out / "sub").rename(tmp_path / "moved")
        (out / "sub").symlink_to(tmp_path / "moved")

    _swap_after_walking(monkeypatch, swap)

    with pytest.raises(ArtifactRejectedError) as caught:
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert caught.value.issue is ArtifactIssue.SYMLINK


def test_a_run_directory_that_disappeared_is_a_workspace_error(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(b"x")

    def swap() -> None:
        (out / "zap.log").unlink()
        out.rmdir()
        (out.parent / "in").rmdir()
        out.parent.rmdir()

    _swap_after_walking(monkeypatch, swap)

    with pytest.raises(WorkspaceError):
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)


def test_progress_is_reported_for_every_chunk(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    (out / "big.log").write_bytes(b"x" * (3 * CHUNK))
    calls: list[int] = []

    workspace.collect(
        RUN, exit_code=0, inputs=(), masker=MASKER, on_progress=lambda: calls.append(1)
    )

    assert len(calls) >= 3


class _LostLeaseError(Exception):
    pass


def test_an_error_from_the_progress_callback_leaves_no_temporary_file(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    (out / "big.log").write_bytes(SECRET.encode())

    def lost() -> None:
        raise _LostLeaseError

    with pytest.raises(_LostLeaseError):
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER, on_progress=lost)

    assert _files(out.parent) == {"in", "out"}


def test_a_failed_cleanup_still_closes_the_directory(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """暫存檔刪不掉（EIO）時，out/ 的目錄 fd 也要關閉（審查發現）。"""
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(SECRET.encode())
    opened: list[int] = []
    closed: list[int] = []
    real_open, real_close, real_unlink = os.open, os.close, os.unlink

    def tracked_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        descriptor = real_open(path, flags, *args, **kwargs)
        if path == "out":
            opened.append(descriptor)
        return descriptor

    def tracked_close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    def broken_unlink(path: Any, *args: Any, **kwargs: Any) -> None:
        if str(path).startswith(".masking-"):
            raise OSError(5, "Input/output error")
        real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "close", tracked_close)
    monkeypatch.setattr(os, "unlink", broken_unlink)

    with pytest.raises(WorkspaceError):
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert opened
    assert set(opened) <= set(closed)


def test_a_failed_write_is_a_workspace_error_without_paths(
    workspace: Workspace, dirs: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(SECRET.encode())

    def no_space(descriptor: int, data: object) -> int:
        raise OSError(28, "No space left on device", str(out))

    monkeypatch.setattr(os, "write", no_space)

    with pytest.raises(WorkspaceError) as caught:
        workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert str(out) not in str(caught.value)
    assert "ENOSPC" in str(caught.value)


def test_the_replacement_keeps_the_file_private(
    workspace: Workspace, dirs: tuple[Path, Path]
) -> None:
    out = _prepared(workspace, dirs)
    (out / "zap.log").write_bytes(SECRET.encode())

    workspace.collect(RUN, exit_code=0, inputs=(), masker=MASKER)

    assert (out / "zap.log").stat().st_mode & 0o077 == 0
