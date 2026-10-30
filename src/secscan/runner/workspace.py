"""run 的工作目錄、target secret 與輸出的收集（docs/DECISIONS.md §14.5；SEC-18）。

- runs volume：`<run_id>/in`（runner 寫入的輸入檔，容器唯讀）、`<run_id>/out`（容器可寫）、
  `<run_id>/manifest.json`（runner 收集後寫入，在 out/ 之外，容器改不到）。
- secrets volume：`<run_id>/proxy-url`（guard 的帳密）與有認證時的 `<run_id>/target-auth`
  （都是 0400），只有 runner 與該 run 的容器掛載；worker 永遠不掛。
- 收集在容器刪除之後進行，以 dir fd 加 O_NOFOLLOW 走過 out/：只接受一般檔案，不跟隨任何 symlink。
  runner 掛著整個 runs 與 secrets volume，跟著工具建立的 symlink 就會讀到其他 run 的資料。
- out/ 沒有磁碟配額：容器執行中，runner 以同樣的走訪（只 lstat、不開檔）檢查用量，超過就停止容器。
- 走訪逐一處理條目（目錄也計數），超過上限就停：不先把整個目錄的名稱讀進記憶體。
- 只計算大小與 sha256，不解析內容（解析在 worker）。
- 檔案系統的錯誤一律轉成 WorkspaceError 或 ArtifactRejectedError，訊息不含路徑。
"""

import errno
import hashlib
import json
import os
import shutil
import stat
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from uuid import UUID, uuid4

from secscan.runner.domain.admission import SECRET_FILES
from secscan.scanners.domain.plan import InputFile

MANIFEST_FILE = "manifest.json"
_PRIVATE_DIR = 0o700
_READ_ONLY_FILE = 0o400
_CHUNK = 64 * 1024
_MAX_NAME_LENGTH = 255
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
# 檔名不能有控制字元（Cc）與格式字元（Cf，例如 bidi 覆寫、零寬字元）。
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf"})


class WorkspaceError(Exception):
    """工作目錄無法使用（已經存在、沒有權限、磁碟滿…）。訊息不含路徑或秘密。"""


class ArtifactIssue(StrEnum):
    MISSING_OUTPUT = "MISSING_OUTPUT"
    SYMLINK = "SYMLINK"
    HARDLINK = "HARDLINK"
    SPECIAL_FILE = "SPECIAL_FILE"
    NAME_NOT_ALLOWED = "NAME_NOT_ALLOWED"
    TOO_DEEP = "TOO_DEEP"
    TOO_MANY_ENTRIES = "TOO_MANY_ENTRIES"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    TOTAL_TOO_LARGE = "TOTAL_TOO_LARGE"
    UNREADABLE = "UNREADABLE"


class ArtifactRejectedError(Exception):
    """輸出不符合規則。訊息只有原因，不含檔名或路徑（檔名由不可信的工具決定）。"""

    def __init__(self, issue: ArtifactIssue) -> None:
        super().__init__(f"輸出被拒絕：{issue.value}")
        self.issue = issue


@dataclass(frozen=True, slots=True)
class CollectionLimits:
    """max_entries 計算 out/ 底下所有的條目（檔案、目錄與其他）。"""

    max_depth: int = 8
    max_entries: int = 1_000
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CollectedFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Manifest:
    run_id: UUID
    files: tuple[CollectedFile, ...]
    total_bytes: int


@dataclass
class _Walk:
    """走訪 out/ 時累計的數量。hashing 為 False 時只 lstat（容器執行中的用量檢查）。"""

    limits: CollectionLimits
    hashing: bool
    files: list[CollectedFile] = field(default_factory=list)
    entries: int = 0
    total_bytes: int = 0


class Workspace:
    def __init__(
        self, runs_dir: Path, secrets_dir: Path, *, limits: CollectionLimits | None = None
    ) -> None:
        self._runs = runs_dir
        self._secrets = secrets_dir
        self._limits = limits if limits is not None else CollectionLimits()

    def writable(self) -> bool:
        """兩個 volume 都能建立與刪除檔案（capability probe 用：權限錯了就不認領）。"""
        for directory in (self._runs, self._secrets):
            probe = directory / f".probe-{uuid4().hex}"
            try:
                os.close(os.open(probe, _NEW_FILE, _READ_ONLY_FILE))
                probe.unlink()
            except OSError:
                return False
        return True

    def prepare(self, run_id: UUID, inputs: Sequence[InputFile]) -> None:
        """建立全新的 in/、out/（同一個 run 不會用第二次），寫入唯讀的輸入檔。"""
        run_dir = self._runs / str(run_id)
        try:
            for directory in (run_dir, run_dir / "in", run_dir / "out"):
                directory.mkdir(mode=_PRIVATE_DIR)
                directory.chmod(_PRIVATE_DIR)
            for item in inputs:
                _write_new(run_dir / "in" / item.name, item.content)
        except FileExistsError:
            raise WorkspaceError("這個 run 的工作目錄已經存在") from None
        except OSError as exc:
            raise WorkspaceError(f"無法建立工作目錄（{_reason(exc)}）") from None

    def write_secrets(self, run_id: UUID, files: Mapping[str, str]) -> None:
        """把 run 的 secret 檔（proxy-url、target-auth）寫成 0400 的檔案；目錄只建立一次，已經存在就
        拒絕（不覆寫）。全部成功，或什麼都不留下。
        """
        if not files or not set(files) <= SECRET_FILES:
            raise WorkspaceError("只能寫入已知的 secret 檔")
        secret_dir = self._secrets / str(run_id)
        try:
            secret_dir.mkdir(mode=_PRIVATE_DIR)
        except FileExistsError:
            raise WorkspaceError("這個 run 的 secret 已經存在") from None
        except OSError as exc:
            raise WorkspaceError(f"無法寫入 secret（{_reason(exc)}）") from None
        try:
            secret_dir.chmod(_PRIVATE_DIR)
            for name, value in files.items():
                _write_new(secret_dir / name, value.encode("utf-8"))
        except OSError as exc:
            self.discard_secrets(run_id)
            raise WorkspaceError(f"無法寫入 secret（{_reason(exc)}）") from None

    def discard_secrets(self, run_id: UUID) -> None:
        """刪除 run 的每一個 secret 檔與目錄；不存在也算成功。"""
        secret_dir = self._secrets / str(run_id)
        try:
            for name in SECRET_FILES:
                (secret_dir / name).unlink(missing_ok=True)
            secret_dir.rmdir()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise WorkspaceError(f"無法刪除 secret（{_reason(exc)}）") from None

    def secret_runs(self) -> frozenset[UUID]:
        """secrets volume 中留下 secret 的 run（標準格式的 run_id 目錄；不跟隨 symlink）。"""
        runs = set()
        for entry in self._secrets.iterdir():
            run_id = _run_id(entry.name)
            if run_id is not None and entry.is_dir() and not entry.is_symlink():
                runs.add(run_id)
        return frozenset(runs)

    def sweep_secrets(self) -> int:
        """刪除上一個 runner 留下的 secret（呼叫端先確認沒有其他存活的 runner）。"""
        removed = 0
        for entry in self._secrets.iterdir():
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
            removed += 1
        return removed

    def check_output(self, run_id: UUID) -> None:
        """容器執行中的用量檢查：條目數、深度與總大小（只 lstat，不開檔、不跟隨 symlink）。"""
        self._walk_output(run_id, _Walk(self._limits, hashing=False))

    def collect(self, run_id: UUID) -> Manifest:
        """走過 out/、計算 hash，寫入 manifest.json；不符合規則就拋 ArtifactRejectedError。"""
        walk = _Walk(self._limits, hashing=True)
        self._walk_output(run_id, walk)
        files = tuple(sorted(walk.files, key=lambda item: item.path))
        manifest = Manifest(run_id=run_id, files=files, total_bytes=walk.total_bytes)
        try:
            _write_new(self._runs / str(run_id) / MANIFEST_FILE, _manifest_json(manifest))
        except OSError as exc:
            raise WorkspaceError(f"無法寫入 manifest（{_reason(exc)}）") from None
        return manifest

    def _walk_output(self, run_id: UUID, walk: _Walk) -> None:
        try:
            run_fd = os.open(self._runs / str(run_id), _DIRECTORY)
        except OSError as exc:
            raise WorkspaceError(f"無法開啟工作目錄（{_reason(exc)}）") from None
        try:
            out_fd = _open_directory("out", run_fd, missing=ArtifactIssue.MISSING_OUTPUT)
            try:
                _walk(out_fd, "", 0, walk)
            finally:
                os.close(out_fd)
        finally:
            os.close(run_fd)


def _run_id(text: str) -> UUID | None:
    try:
        run_id = UUID(text)
    except ValueError:
        return None
    return run_id if str(run_id) == text else None


def _reason(exc: OSError) -> str:
    """只回報錯誤的種類（例如 EACCES、ENOSPC）：OSError 的訊息含路徑。"""
    return errno.errorcode.get(exc.errno or 0, type(exc).__name__)


def _write_new(path: Path, content: bytes) -> None:
    descriptor = os.open(path, _NEW_FILE, _READ_ONLY_FILE)
    try:
        os.fchmod(descriptor, _READ_ONLY_FILE)
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_directory(name: str, parent_fd: int, *, missing: ArtifactIssue | None = None) -> int:
    try:
        return os.open(name, _DIRECTORY, dir_fd=parent_fd)
    except FileNotFoundError:
        raise ArtifactRejectedError(missing or ArtifactIssue.UNREADABLE) from None
    except OSError:
        raise ArtifactRejectedError(_open_failure(name, parent_fd)) from None


def _open_failure(name: str, parent_fd: int) -> ArtifactIssue:
    """開不了：被換成 symlink（Linux 回 ELOOP、macOS 回 ENOTDIR），或沒有權限讀。"""
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return ArtifactIssue.UNREADABLE
    return ArtifactIssue.SYMLINK if stat.S_ISLNK(info.st_mode) else ArtifactIssue.UNREADABLE


def _walk(dir_fd: int, prefix: str, depth: int, walk: _Walk) -> None:
    try:
        entries = os.scandir(dir_fd)
    except OSError:
        raise ArtifactRejectedError(ArtifactIssue.UNREADABLE) from None
    with entries:
        for entry in entries:
            walk.entries += 1
            if walk.entries > walk.limits.max_entries:
                raise ArtifactRejectedError(ArtifactIssue.TOO_MANY_ENTRIES)
            _visit(entry.name, dir_fd, prefix, depth, walk)


def _visit(name: str, dir_fd: int, prefix: str, depth: int, walk: _Walk) -> None:
    if walk.hashing:
        _check_name(name)
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        raise ArtifactRejectedError(ArtifactIssue.UNREADABLE) from None
    relative = f"{prefix}{name}"
    if stat.S_ISDIR(info.st_mode):
        if depth + 1 > walk.limits.max_depth:
            raise ArtifactRejectedError(ArtifactIssue.TOO_DEEP)
        child = _open_directory(name, dir_fd)
        try:
            _walk(child, f"{relative}/", depth + 1, walk)
        finally:
            os.close(child)
    elif not walk.hashing:
        # 執行中只計算大小：symlink 與特殊檔留給收集時拒絕，這裡不跟隨也不開檔。
        if stat.S_ISREG(info.st_mode):
            _add_bytes(walk, info.st_size, info.st_size)
    elif stat.S_ISLNK(info.st_mode):
        raise ArtifactRejectedError(ArtifactIssue.SYMLINK)
    elif stat.S_ISREG(info.st_mode):
        walk.files.append(_hash_file(name, dir_fd, relative, walk))
    else:
        raise ArtifactRejectedError(ArtifactIssue.SPECIAL_FILE)


def _add_bytes(walk: _Walk, size: int, file_size: int) -> None:
    if file_size > walk.limits.max_file_bytes:
        raise ArtifactRejectedError(ArtifactIssue.FILE_TOO_LARGE)
    if walk.total_bytes + size > walk.limits.max_total_bytes:
        raise ArtifactRejectedError(ArtifactIssue.TOTAL_TOO_LARGE)
    walk.total_bytes += size


def _hash_file(name: str, dir_fd: int, relative: str, walk: _Walk) -> CollectedFile:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError:
        raise ArtifactRejectedError(_open_failure(name, dir_fd)) from None
    try:
        info = os.fstat(descriptor)
        # 開檔之後再確認一次（lstat 與 open 之間可能被換掉）。
        if not stat.S_ISREG(info.st_mode):
            raise ArtifactRejectedError(ArtifactIssue.SPECIAL_FILE)
        if info.st_nlink != 1:
            raise ArtifactRejectedError(ArtifactIssue.HARDLINK)
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, _CHUNK):
            size += len(chunk)
            _add_bytes(walk, len(chunk), size)
            digest.update(chunk)
    except OSError:
        raise ArtifactRejectedError(ArtifactIssue.UNREADABLE) from None
    finally:
        os.close(descriptor)
    return CollectedFile(path=relative, size=size, sha256=digest.hexdigest())


def _check_name(name: str) -> None:
    """檔名寫進 manifest（JSON）：必須是 UTF-8、沒有控制與格式字元，長度有上限。"""
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        raise ArtifactRejectedError(ArtifactIssue.NAME_NOT_ALLOWED) from None
    if len(name) > _MAX_NAME_LENGTH or any(
        unicodedata.category(character) in _FORBIDDEN_CATEGORIES for character in name
    ):
        raise ArtifactRejectedError(ArtifactIssue.NAME_NOT_ALLOWED)


def _manifest_json(manifest: Manifest) -> bytes:
    document = {
        "files": [
            {"path": item.path, "sha256": item.sha256, "size": item.size} for item in manifest.files
        ],
        "run_id": str(manifest.run_id),
        "total_bytes": manifest.total_bytes,
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")
