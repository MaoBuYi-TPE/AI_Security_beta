"""runs volume 中原始證據的加密、清除與換版（EVID-02、EVID-03、EVID-05、ROT-01 的檔案部分；
docs/DECISIONS.md §30.3）。

真的檔案（pytest 的暫存目錄）、真的金鑰；不連 DB。
"""

import hashlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from cryptography.fernet import Fernet

from secscan.runner import fs as fs_module
from secscan.runner.evidence import SEALED_DIR, EvidenceError, EvidenceLimitError, EvidenceVault
from secscan.runner.fs import TreeLimits
from secscan.runner.workspace import Workspace
from secscan.scans.domain.evidence import EvidenceHoldCode
from secscan.security.blob_cipher import SealedDataUnreadableError
from secscan.security.key_rings import evidence_cipher

RUN = "6f1c2d3e-4b5a-4c6d-8e7f-001122334455"
OTHER = "00000000-0000-4000-8000-000000000001"
RUN_UUID = UUID(RUN)
CANARY = b"canary-evidence-plaintext-5e1d"
FILES = {
    "in/plan.json": b'{"plan": true}',
    "out/zap-report.json": b'{"site": "' + CANARY + b'"}',
    "out/nested/deeper/messages.txt": CANARY * 3,
    "manifest.json": b'{"files": []}',
}


def _key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture
def key() -> str:
    return _key()


@pytest.fixture
def runs(tmp_path: Path) -> Path:
    directory = tmp_path / "runs"
    directory.mkdir()
    return directory


def _vault(runs: Path, *keys: str, limits: TreeLimits | None = None) -> EvidenceVault:
    return EvidenceVault(runs, evidence_cipher(",".join(keys)), limits=limits)


def _run(runs: Path, name: str = RUN, files: dict[str, bytes] = FILES) -> Path:
    root = runs / name
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o400)
    return root


def _everything(root: Path) -> Iterator[Path]:
    for directory, names, files in os.walk(root, followlinks=False):
        for name in (*names, *files):
            yield Path(directory) / name


def _all_bytes(root: Path) -> bytes:
    """目錄中所有一般檔案的內容與所有條目的名稱。"""
    parts: list[bytes] = []
    for path in _everything(root):
        parts.append(os.fsencode(path.name))
        if path.is_file() and not path.is_symlink():
            parts.append(path.read_bytes())
    return b"\n".join(parts)


def _top(root: Path) -> set[str]:
    return {entry.name for entry in root.iterdir()}


def _export(vault: EvidenceVault, path: str, name: str = RUN) -> bytes:
    class Sink:
        def __init__(self) -> None:
            self.parts: list[bytes] = []

        def write(self, data: bytes, /) -> int:
            self.parts.append(data)
            return len(data)

    sink = Sink()
    vault.export(name, path, sink)
    return b"".join(sink.parts)


# --- 加密 ----------------------------------------------------------------------------------------


def test_sealing_leaves_only_verified_ciphertext(runs: Path, key: str) -> None:
    root = _run(runs)
    vault = _vault(runs, key)

    sealed = vault.seal(RUN)

    assert sealed is not None
    assert sealed.files == len(FILES)
    assert sealed.plaintext_bytes == sum(len(content) for content in FILES.values())
    assert _top(root) == {SEALED_DIR}
    assert CANARY not in _all_bytes(root)
    for relative in FILES:
        assert os.fsencode(Path(relative).name) not in _all_bytes(root)
    listing = {info.path: info for info in vault.listing(RUN)}
    assert set(listing) == set(FILES)
    for relative, content in FILES.items():
        assert listing[relative].sha256 == hashlib.sha256(content).hexdigest()
        assert _export(vault, relative) == content


def test_sealed_files_are_read_only(runs: Path, key: str) -> None:
    root = _run(runs)
    _vault(runs, key).seal(RUN)

    for path in (root / SEALED_DIR).iterdir():
        assert path.stat().st_mode & 0o777 == 0o400


def test_a_missing_directory_is_reported_as_none(runs: Path, key: str) -> None:
    assert _vault(runs, key).seal(RUN) is None
    assert _vault(runs, key).inspect(RUN) is None
    _vault(runs, key).purge(RUN)


def test_sealing_again_is_harmless(runs: Path, key: str) -> None:
    root = _run(runs)
    vault = _vault(runs, key)
    first = vault.seal(RUN)
    before = {path.name: path.read_bytes() for path in (root / SEALED_DIR).iterdir()}

    again = vault.seal(RUN)

    assert again == first
    assert {path.name: path.read_bytes() for path in (root / SEALED_DIR).iterdir()} == before


def test_a_crash_between_rename_and_unlink_is_finished_later(runs: Path, key: str) -> None:
    """加密檔已經就位、明文還在：下一次重做同一個檔案（取代同一個加密檔），不會多一份。"""
    root = _run(runs)
    vault = _vault(runs, key)
    first = vault.seal(RUN)
    leftover = root / "out" / "zap-report.json"
    leftover.parent.mkdir(parents=True)
    leftover.write_bytes(FILES["out/zap-report.json"])

    again = vault.seal(RUN)

    assert again == first
    assert _top(root) == {SEALED_DIR}
    assert len(list((root / SEALED_DIR).iterdir())) == len(FILES)


def test_partial_files_from_interrupted_work_are_discarded(runs: Path, key: str) -> None:
    root = _run(runs)
    (root / SEALED_DIR).mkdir()
    (root / SEALED_DIR / ".sealing-0123").write_bytes(b"half a token")
    (root / SEALED_DIR / ".rotating-4567").write_bytes(b"half a token")
    (root / ".masking-89ab").write_bytes(CANARY + b" partially masked")
    vault = _vault(runs, key)

    sealed = vault.seal(RUN)

    assert sealed is not None
    assert sealed.files == len(FILES)
    assert all(not path.name.startswith(".") for path in (root / SEALED_DIR).iterdir())
    assert {info.path for info in vault.listing(RUN)} == set(FILES)
    assert CANARY not in _all_bytes(root)


# --- 失敗時保留明文（先驗證才刪除）--------------------------------------------------------------


def _plaintext_kept(root: Path) -> None:
    for relative, content in FILES.items():
        assert (root / relative).read_bytes() == content, relative
    sealed = root / SEALED_DIR
    assert not sealed.exists() or all(not p.name.startswith(".") for p in sealed.iterdir())


@pytest.mark.parametrize("step", ["replace", "fsync", "fchmod"])
def test_a_failed_write_keeps_the_plaintext(
    runs: Path, key: str, monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    root = _run(runs)

    def broken(*_args: Any, **_kwargs: Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, step, broken)

    with pytest.raises(EvidenceError) as raised:
        _vault(runs, key).seal(RUN)

    monkeypatch.undo()
    assert str(runs) not in str(raised.value)
    _plaintext_kept(root)


def test_a_failed_verification_keeps_the_plaintext(
    runs: Path, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _run(runs)
    vault = _vault(runs, key)

    def unreadable(*_args: Any, **_kwargs: Any) -> None:
        raise SealedDataUnreadableError("broken")

    monkeypatch.setattr(vault, "_verify", unreadable)

    with pytest.raises(EvidenceError):
        vault.seal(RUN)

    _plaintext_kept(root)


def test_a_mismatching_verification_keeps_the_plaintext(
    runs: Path, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _run(runs)
    vault = _vault(runs, key)
    real = vault._verify

    def different(reader: Any, name: str, path: str | None) -> Any:
        info = real(reader, name, path)
        return type(info)(info.path, info.size, "0" * 64, info.sealed_at)

    monkeypatch.setattr(vault, "_verify", different)

    with pytest.raises(EvidenceError, match="不符"):
        vault.seal(RUN)

    _plaintext_kept(root)
    assert not (root / SEALED_DIR).exists() or not list((root / SEALED_DIR).iterdir())


def test_deleting_only_happens_after_verification(
    runs: Path, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """每個明文被刪除的時候，它的加密檔已經存在而且驗證過。"""
    _run(runs)
    vault = _vault(runs, key)
    verified: set[str] = set()
    real_verify = vault._verify
    real_unlink = os.unlink

    def verify(reader: Any, name: str, path: str | None) -> Any:
        info = real_verify(reader, name, path)
        if path is not None:
            verified.add(path)
        return info

    def unlink(path: Any, *, dir_fd: int | None = None) -> None:
        relative = next((r for r in FILES if Path(r).name == path), None)
        if relative is not None:
            assert relative in verified, relative
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(vault, "_verify", verify)
    monkeypatch.setattr(os, "unlink", unlink)

    vault.seal(RUN)

    assert verified == set(FILES)


# --- 不一般的檔案 ---------------------------------------------------------------------------------


def test_links_and_special_files_are_removed_without_being_followed(
    runs: Path, key: str, tmp_path: Path
) -> None:
    root = _run(runs)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"not evidence")
    (root / "out" / "link").symlink_to(outside)
    (root / "out" / "dir-link").symlink_to(tmp_path, target_is_directory=True)
    os.mkfifo(root / "out" / "fifo")
    os.link(outside, root / "out" / "hardlink")

    vault = _vault(runs, key)
    vault.seal(RUN)

    assert outside.read_bytes() == b"not evidence"
    assert {info.path for info in vault.listing(RUN)} == {*FILES, "out/hardlink"}
    assert _top(root) == {SEALED_DIR}


def test_long_names_and_deep_paths_are_sealed(runs: Path, key: str) -> None:
    """加密檔的名稱是路徑的 sha256：原本的名稱多長都不會 ENAMETOOLONG；路徑超過 4096 bytes 時，
    標頭改記路徑的 sha256。"""
    root = _run(runs, files={"out/" + "n" * 255: CANARY})
    component = "d" * 250
    fd = os.open(root / "out", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for _ in range(17):
            os.mkdir(component, dir_fd=fd)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
        descriptor = os.open("deep.txt", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=fd)
        os.write(descriptor, CANARY)
        os.close(descriptor)
    finally:
        os.close(fd)
    vault = _vault(runs, key)

    sealed = vault.seal(RUN)

    assert sealed is not None
    assert sealed.files == 2
    paths = {info.path for info in vault.listing(RUN)}
    assert "out/" + "n" * 255 in paths
    assert any(path.startswith("overlong-path/") for path in paths)
    assert _top(root) == {SEALED_DIR}


def test_too_many_entries_fail_closed(runs: Path, key: str) -> None:
    root = _run(runs)

    with pytest.raises(EvidenceError):
        _vault(runs, key, limits=TreeLimits(max_entries=3)).seal(RUN)

    _plaintext_kept(root)


@pytest.mark.parametrize(
    ("limits", "code"),
    [
        (TreeLimits(max_depth=2), EvidenceHoldCode.TREE_TOO_DEEP),
        (TreeLimits(max_entries=3), EvidenceHoldCode.TREE_TOO_MANY_ENTRIES),
        (TreeLimits(max_path_chars=20), EvidenceHoldCode.TREE_PATHS_TOO_LONG),
    ],
)
def test_limit_failures_carry_a_hold_code(
    runs: Path, key: str, limits: TreeLimits, code: EvidenceHoldCode
) -> None:
    """keeper 以錯誤代碼分辨可以隔離的失敗（EVID-08；docs/DECISIONS.md §30.12）。"""
    root = _run(runs)
    vault = _vault(runs, key, limits=limits)

    with pytest.raises(EvidenceLimitError) as sealing:
        vault.seal(RUN)
    with pytest.raises(EvidenceLimitError) as inspecting:
        vault.inspect(RUN)

    assert sealing.value.code is code
    assert inspecting.value.code is code
    assert str(runs) not in str(sealing.value)
    _plaintext_kept(root)


def test_a_volume_with_too_many_directories_is_not_a_limit_failure(runs: Path, key: str) -> None:
    """整個 runs volume 的問題不能只隔離一個目錄：維持一般的失敗（全域 fail closed）。"""
    _run(runs)
    _run(runs, OTHER)

    with pytest.raises(EvidenceError) as raised:
        _vault(runs, key, limits=TreeLimits(max_entries=1)).entries()

    assert not isinstance(raised.value, EvidenceLimitError)


def test_a_sealed_directory_larger_than_the_limit_can_be_purged(runs: Path, key: str) -> None:
    """retry-evidence 以較高的上限加密之後，sealed/ 可能超過一般的條目上限（§30.12）。"""
    root = _run(runs, files={f"out/{index}.txt": b"x" for index in range(6)})
    _vault(runs, key, limits=TreeLimits(max_entries=10)).seal(RUN)
    assert len(list((root / SEALED_DIR).iterdir())) == 6

    _vault(runs, key, limits=TreeLimits(max_entries=4)).purge(RUN)

    assert not root.exists()


def test_a_directory_inside_sealed_stops_the_purge(runs: Path, key: str) -> None:
    """sealed/ 只由 runner 寫入、而且是平的；有子目錄代表被改過：不刪除、fail closed。"""
    root = _run(runs)
    vault = _vault(runs, key)
    vault.seal(RUN)
    (root / SEALED_DIR / ("0" * 64)).mkdir()

    with pytest.raises(EvidenceError):
        vault.purge(RUN)

    assert (root / SEALED_DIR).is_dir()


def test_unknown_files_in_the_sealed_directory_fail_closed(runs: Path, key: str) -> None:
    root = _run(runs)
    vault = _vault(runs, key)
    vault.seal(RUN)
    (root / SEALED_DIR / "not-a-sealed-name").write_bytes(b"?")

    with pytest.raises(EvidenceError, match="不認得"):
        vault.seal(RUN)


def test_names_must_be_canonical_run_ids(runs: Path, key: str) -> None:
    for name in ("../etc", RUN.upper(), "x"):
        with pytest.raises(ValueError, match="run_id"):
            _vault(runs, key).seal(name)


# --- 清除、檢查與列出 -----------------------------------------------------------------------------


def test_purging_removes_the_whole_directory(runs: Path, key: str) -> None:
    _run(runs)
    vault = _vault(runs, key)
    vault.seal(RUN)

    vault.purge(RUN)

    assert not (runs / RUN).exists()


def test_purging_seals_leftover_plaintext_first(
    runs: Path, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _run(runs)
    vault = _vault(runs, key)
    calls: list[str] = []
    real = vault.seal

    def seal(name: str) -> Any:
        calls.append(name)
        return real(name)

    monkeypatch.setattr(vault, "seal", seal)

    vault.purge(RUN)

    assert calls == [RUN]
    assert not (runs / RUN).exists()


def test_purging_keeps_plaintext_that_cannot_be_sealed(
    runs: Path, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _run(runs)
    monkeypatch.setattr(os, "fsync", _raise_enospc)

    with pytest.raises(EvidenceError):
        _vault(runs, key).purge(RUN)

    monkeypatch.undo()
    _plaintext_kept(root)


def _raise_enospc(*_args: Any, **_kwargs: Any) -> None:
    raise OSError(28, "No space left on device")


def test_inspect_and_sealed_at(runs: Path, key: str) -> None:
    _run(runs)
    vault = _vault(runs, key)
    before = vault.inspect(RUN)
    assert before is not None
    assert (before.plaintext, before.sealed_files) == (True, 0)
    assert vault.sealed_at(RUN) is None

    vault.seal(RUN)

    after = vault.inspect(RUN)
    assert after is not None
    assert (after.plaintext, after.sealed_files) == (False, len(FILES))
    sealed_at = vault.sealed_at(RUN)
    assert sealed_at is not None
    assert sealed_at > 1_700_000_000


def test_entries_are_only_canonical_run_directories(runs: Path, key: str, tmp_path: Path) -> None:
    _run(runs)
    _run(runs, OTHER)
    (runs / "not-a-run").mkdir()
    (runs / RUN.replace("-", "")).mkdir()
    (runs / "00000000-0000-4000-8000-000000000002").write_bytes(b"file")
    (runs / "00000000-0000-4000-8000-000000000003").symlink_to(tmp_path)

    assert _vault(runs, key).entries() == tuple(sorted((RUN, OTHER)))


def test_export_needs_the_directory_and_the_file(runs: Path, key: str) -> None:
    _run(runs)
    vault = _vault(runs, key)

    with pytest.raises(EvidenceError, match="不存在"):
        _export(vault, "out/zap-report.json", OTHER)
    vault.seal(RUN)
    with pytest.raises(EvidenceError, match="找不到"):
        _export(vault, "out/missing.json")
    with pytest.raises(EvidenceError, match="解不開"):
        _export(_vault(runs, _key()), "out/zap-report.json")
    with pytest.raises(EvidenceError):
        _vault(runs, _key()).listing(RUN)


def test_a_directory_moved_to_another_run_is_unreadable(runs: Path, key: str) -> None:
    _run(runs)
    vault = _vault(runs, key)
    vault.seal(RUN)
    (runs / RUN).rename(runs / OTHER)

    with pytest.raises(EvidenceError):
        vault.listing(OTHER)


# --- 換版 ---------------------------------------------------------------------------------------


def test_rotation_moves_every_file_to_the_first_key(runs: Path) -> None:
    old, new = _key(), _key()
    root = _run(runs)
    _vault(runs, old).seal(RUN)

    rotated = _vault(runs, new, old).rotate(RUN)

    assert rotated == len(FILES)
    only_new = _vault(runs, new)
    for relative, content in FILES.items():
        assert _export(only_new, relative) == content
    assert all(not p.name.startswith(".") for p in (root / SEALED_DIR).iterdir())


def test_rotation_skips_unsealed_or_missing_directories(runs: Path, key: str) -> None:
    root = _run(runs)

    assert _vault(runs, key).rotate(RUN) == 0
    assert _vault(runs, key).rotate(OTHER) == 0
    _plaintext_kept(root)


def test_rotation_without_the_old_key_changes_nothing(runs: Path) -> None:
    old = _key()
    root = _run(runs)
    _vault(runs, old).seal(RUN)
    before = {p.name: p.read_bytes() for p in (root / SEALED_DIR).iterdir()}

    with pytest.raises(EvidenceError, match="解不開"):
        _vault(runs, _key()).rotate(RUN)

    assert {p.name: p.read_bytes() for p in (root / SEALED_DIR).iterdir()} == before


def test_rotation_refuses_a_mismatching_result(runs: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    old, new = _key(), _key()
    root = _run(runs)
    _vault(runs, old).seal(RUN)
    before = {p.name: p.read_bytes() for p in (root / SEALED_DIR).iterdir()}
    vault = _vault(runs, new, old)
    real = vault._verify

    def different(reader: Any, name: str, path: str | None) -> Any:
        info = real(reader, name, path)
        return type(info)(info.path, info.size + 1, info.sha256, info.sealed_at)

    monkeypatch.setattr(vault, "_verify", different)

    with pytest.raises(EvidenceError, match="不符"):
        vault.rotate(RUN)

    assert {p.name: p.read_bytes() for p in (root / SEALED_DIR).iterdir()} == before


# --- probe 的目錄 --------------------------------------------------------------------------------


def test_the_workspace_discards_a_probe_directory(runs: Path, tmp_path: Path) -> None:
    root = _run(runs)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"keep")
    (root / "out" / "link").symlink_to(outside)
    workspace = Workspace(runs, tmp_path)

    workspace.discard_run(RUN_UUID)
    workspace.discard_run(RUN_UUID)

    assert not root.exists()
    assert outside.read_bytes() == b"keep"


def test_errors_never_include_paths(runs: Path, key: str) -> None:
    root = _run(runs)
    root.chmod(0o000)
    try:
        with pytest.raises(EvidenceError) as raised:
            _vault(runs, key).seal(RUN)
    finally:
        root.chmod(0o700)
    assert str(runs) not in str(raised.value)
    assert RUN not in str(raised.value)


# --- 審查之後（docs/DECISIONS.md §30.11）--------------------------------------------------------


def test_an_unreadable_sealed_header_is_an_evidence_error(runs: Path, key: str) -> None:
    """孤兒目錄的加密檔解不開（金鑰移除、損壞）時，sealed_at 不能讓例外跳出 keeper
    （審查 HIGH-1）。"""
    _run(runs)
    _vault(runs, key).seal(RUN)

    with pytest.raises(EvidenceError, match="解不開"):
        _vault(runs, _key()).sealed_at(RUN)


@pytest.mark.parametrize("operation", ["inspect", "sealed_at", "seal", "purge", "rotate"])
def test_a_missing_runs_volume_is_an_error_not_a_missing_directory(
    tmp_path: Path, key: str, operation: str
) -> None:
    """runs 的根目錄不存在（主機上執行、volume 沒有掛上）時不能回報成「沒有這個目錄」：否則
    keeper 會把待加密的 run 永久記成 none（審查 HIGH-2）。"""
    vault = _vault(tmp_path / "missing", key)

    with pytest.raises(EvidenceError, match="runs volume"):
        getattr(vault, operation)(RUN)


def test_check_needs_a_writable_runs_volume(runs: Path, tmp_path: Path, key: str) -> None:
    _vault(runs, key).check()
    with pytest.raises(EvidenceError, match="runs volume"):
        _vault(tmp_path / "missing", key).check()
    runs.chmod(0o500)
    try:
        with pytest.raises(EvidenceError, match="runs volume"):
            _vault(runs, key).check()
    finally:
        runs.chmod(0o700)
    assert list(runs.iterdir()) == []


def test_export_and_listing_of_an_unsealed_directory_are_evidence_errors(
    runs: Path, key: str
) -> None:
    _run(runs)
    vault = _vault(runs, key)

    with pytest.raises(EvidenceError):
        _export(vault, "out/zap-report.json")
    with pytest.raises(EvidenceError):
        vault.listing(RUN)


def test_entries_over_the_limit_fail_instead_of_being_cut(runs: Path, key: str) -> None:
    """超過上限時截斷會讓換版漏掉目錄、卻回報成功（安全審查 L2）。"""
    _run(runs)
    _run(runs, OTHER)

    with pytest.raises(EvidenceError, match="上限"):
        _vault(runs, key, limits=TreeLimits(max_entries=1)).entries()


def test_entries_the_container_made_unreadable_are_sealed(runs: Path, key: str) -> None:
    """掃描容器和 runner 是同一個 uid：chmod 000 的目錄與檔案不能讓 keeper 永久失敗
    （安全審查 M1）。"""
    root = _run(runs)
    locked = [
        root / "out" / "nested" / "deeper" / "messages.txt",
        root / "out" / "nested",
        root / "out",
    ]
    for path in locked:
        path.chmod(0)
    try:
        sealed = _vault(runs, key).seal(RUN)
    finally:
        for path in reversed(locked):
            if path.exists():
                path.chmod(0o700)

    assert sealed is not None
    assert sealed.files == len(FILES)
    assert _top(root) == {SEALED_DIR}
    assert CANARY not in _all_bytes(root)
    for relative, content in FILES.items():
        assert _export(_vault(runs, key), relative) == content


def test_the_sealed_directory_is_synced_before_plaintext_is_deleted(
    runs: Path, key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """rename 之後先讓 sealed/ 的目錄項目落盤，再刪除明文（安全審查 L4）。"""
    _run(runs)
    vault = _vault(runs, key)
    events: list[str] = []
    real_fsync = fs_module.fsync_directory
    real_unlink = os.unlink

    def fsync_directory(fd: int) -> None:
        events.append("fsync")
        real_fsync(fd)

    def unlink(path: Any, *, dir_fd: int | None = None) -> None:
        if any(Path(relative).name == path for relative in FILES):
            events.append("unlink")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr("secscan.runner.evidence.fsync_directory", fsync_directory)
    monkeypatch.setattr(os, "unlink", unlink)

    vault.seal(RUN)

    assert events.count("unlink") == len(FILES)
    for index, event in enumerate(events):
        if event == "unlink":
            assert events[index - 1] == "fsync", events
