"""runs volume 中原始證據的加密、清除、換版與匯出（docs/DECISIONS.md §30.3、§30.6）。

一個 run 的目錄（名稱是 run_id）加密之後只剩 `sealed/`：每個原本的檔案各一個加密檔，檔名是原本
相對路徑的 sha256（不會太長；同一個檔案重做時取代同一個加密檔，所以可以重複執行），原本的路徑
寫在已驗證的標頭中（security/blob_cipher.py）。

加密一個檔案（先驗證才刪除）：
1. 寫進 sealed/ 中的暫存檔（.sealing-<隨機>，O_EXCL）→ fsync；
2. rename 成正式的名稱；
3. 串流解密，核對原本的路徑、大小與 sha256；
4. 才刪除明文；全部完成之後 fsync 目錄。
任何一步失敗都保留明文並拋出 EvidenceError：呼叫端不記下「已加密」，API 如實顯示 pending。

開始之前先處理中斷留下的檔案：sealed/ 中的 .sealing-*、.rotating-* 是不完整的密文，直接刪除；
run 目錄的 .masking-* 是收集時只遮罩了一部分的明文暫存檔（不是證據），也直接刪除。symlink 與
特殊檔案不跟隨、直接刪除；一般檔案不論 link 數都加密。
例外與 log 只帶錯誤的種類，不帶路徑或內容。
"""

import contextlib
import hashlib
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from uuid import UUID, uuid4

from secscan.core.identifiers import canonical_uuid
from secscan.runner.fs import (
    DIRECTORY_FLAGS,
    NEW_FILE_FLAGS,
    PRIVATE_DIR,
    READ_FLAGS,
    READ_ONLY_FILE,
    TreeError,
    TreeLimits,
    fsync_directory,
    list_tree,
    open_child,
    open_directory,
    open_parent,
    opened,
    reason,
    remove_empty_directories,
    remove_tree,
    unlink_at,
)
from secscan.scans.domain.evidence import SealedEvidence, evidence_context
from secscan.security.blob_cipher import (
    CHUNK_BYTES,
    MAX_PATH_BYTES,
    BlobCipher,
    SealedDataUnreadableError,
    Sink,
    StreamInfo,
)

SEALED_DIR = "sealed"
_SEALING_PREFIX = ".sealing-"
_ROTATING_PREFIX = ".rotating-"
_PARTIAL_PREFIXES = (_SEALING_PREFIX, _ROTATING_PREFIX)
_MASKING_PREFIX = ".masking-"
_STAGING_MODE = 0o600
_SEALED_NAME_LENGTH = 64


class EvidenceError(Exception):
    """原始證據無法加密、驗證、清除或換版。訊息只有原因，不含路徑或內容。"""


@dataclass(frozen=True, slots=True)
class DirectoryState:
    """一個目錄目前的樣子：sealed/ 之外是否還有條目、最近的修改時間、加密檔的數量。"""

    plaintext: bool
    newest_mtime: float
    sealed_files: int


class EvidenceVault:
    def __init__(
        self, runs_dir: Path, cipher: BlobCipher, *, limits: TreeLimits | None = None
    ) -> None:
        self._runs = runs_dir
        self._cipher = cipher
        self._limits = limits if limits is not None else TreeLimits()

    # --- 列出與檢查 ------------------------------------------------------------------------

    def entries(self) -> tuple[str, ...]:
        """runs volume 中名稱是標準 UUID 的目錄（不跟隨 symlink；有數量上限）。"""
        names: list[str] = []
        with opened(open_directory(self._runs)) as runs_fd:
            try:
                listing = os.scandir(runs_fd)
            except OSError as exc:
                raise EvidenceError(f"無法列出 runs volume（{reason(exc)}）") from None
            with listing:
                for entry in listing:
                    if len(names) >= self._limits.max_entries:
                        break
                    if canonical_uuid(entry.name) is not None and entry.is_dir(
                        follow_symlinks=False
                    ):
                        names.append(entry.name)
        return tuple(sorted(names))

    def inspect(self, name: str) -> DirectoryState | None:
        """目錄目前的樣子；沒有這個目錄時回 None。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            return None
        with opened(run_fd):
            try:
                tree = list_tree(run_fd, self._limits, skip=frozenset({SEALED_DIR}))
                own = os.fstat(run_fd).st_mtime
            except (TreeError, OSError) as exc:
                raise EvidenceError(_describe(exc)) from None
            sealed = self._sealed_names(run_fd)
        newest = max(tree.newest_mtime, own)
        return DirectoryState(tree.entries > 0, newest, len(sealed))

    def sealed_at(self, name: str) -> int | None:
        """所有加密檔的標頭中最晚的加密時間（已驗證）；沒有加密檔時回 None。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            return None
        newest: int | None = None
        with opened(run_fd):
            for sealed_name in self._sealed_names(run_fd):
                header = self._read(run_fd, sealed_name, lambda f: self._header(f, name))
                newest = header if newest is None else max(newest, header)
        return newest

    # --- 加密與清除 ------------------------------------------------------------------------

    def seal(self, name: str) -> SealedEvidence | None:
        """加密目錄中 sealed/ 之外的每個檔案；沒有這個目錄時回 None。可以重複執行。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            return None
        try:
            with opened(run_fd):
                return self._seal(run_fd, name)
        except (TreeError, OSError) as exc:
            raise EvidenceError(_describe(exc)) from None
        except SealedDataUnreadableError:
            raise EvidenceError("加密檔驗證不通過") from None

    def purge(self, name: str) -> None:
        """刪除整個目錄。sealed/ 之外還有條目時先加密（絕不在未加密時刪除）。"""
        state = self.inspect(name)
        if state is None:
            return
        if state.plaintext:
            self.seal(name)
        try:
            with opened(open_directory(self._runs)) as runs_fd:
                remove_tree(runs_fd, name, self._limits)
        except (TreeError, OSError) as exc:
            raise EvidenceError(_describe(exc)) from None

    # --- 換版與匯出（admin 指令） ---------------------------------------------------------

    def rotate(self, name: str) -> int:
        """把目錄中每個加密檔改用第一個金鑰重新加密（驗證之後才取代）；回傳換版的數量。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            return 0
        try:
            with opened(run_fd):
                if not self._sealed_names(run_fd):
                    return 0
                return self._rotate_all(run_fd, name)
        except (TreeError, OSError) as exc:
            raise EvidenceError(_describe(exc)) from None
        except SealedDataUnreadableError:
            raise EvidenceError("加密檔解不開：金鑰不對，或內容被改過") from None

    def _rotate_all(self, run_fd: int, name: str) -> int:
        with opened(open_child(SEALED_DIR, run_fd)) as sealed_fd:
            self._discard_partials(sealed_fd)
            names = self._listed(sealed_fd)
            for sealed_name in names:
                self._rotate_file(sealed_fd, sealed_name, name)
            fsync_directory(sealed_fd)
            return len(names)

    def export(self, name: str, path: str, sink: Sink) -> StreamInfo:
        """解密一個原本的檔案寫進 sink（驗證路徑；例外時 sink 已寫了一部分，呼叫端必須丟棄）。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            raise EvidenceError("沒有這個 run 的原始證據（不存在或已清除）")
        try:
            with opened(run_fd):
                return self._read(
                    run_fd,
                    _sealed_name(path),
                    lambda f: self._cipher.unseal_stream(
                        f, sink, context=evidence_context(name), path=_header_path(path)
                    ),
                )
        except SealedDataUnreadableError:
            raise EvidenceError("加密檔解不開：金鑰不對，或內容被改過") from None

    def listing(self, name: str) -> tuple[StreamInfo, ...]:
        """目錄中每個加密檔的原本路徑、大小與 sha256（逐一完整驗證）。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            raise EvidenceError("沒有這個 run 的原始證據（不存在或已清除）")
        try:
            with opened(run_fd):
                return tuple(
                    sorted(
                        (
                            self._read(run_fd, sealed_name, lambda f: self._verify(f, name, None))
                            for sealed_name in self._sealed_names(run_fd)
                        ),
                        key=lambda info: info.path,
                    )
                )
        except SealedDataUnreadableError:
            raise EvidenceError("加密檔解不開：金鑰不對，或內容被改過") from None

    # --- 內部 ------------------------------------------------------------------------------

    def _open_run(self, name: str) -> int | None:
        if _uuid_or_none(name) is None:
            raise ValueError("目錄名稱必須是標準格式的 run_id")
        try:
            return os.open(self._runs / name, DIRECTORY_FLAGS)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise EvidenceError(f"無法開啟目錄（{reason(exc)}）") from None

    def _seal(self, run_fd: int, name: str) -> SealedEvidence:
        for entry in _top_level(run_fd):
            if entry.startswith(_MASKING_PREFIX):
                unlink_at(run_fd, entry)
        sealed_fd = self._sealed_directory(run_fd)
        with opened(sealed_fd):
            self._discard_partials(sealed_fd)
            earlier = set(self._listed(sealed_fd))
            tree = list_tree(run_fd, self._limits, skip=frozenset({SEALED_DIR}))
            for relative in tree.others:
                unlink_at(run_fd, relative)
            sizes: dict[str, int] = {}
            for relative in tree.files:
                sealed_name, size = self._seal_file(run_fd, sealed_fd, name, relative)
                sizes[sealed_name] = size
            for sealed_name in sorted(earlier - set(sizes)):
                info = self._read_at(sealed_fd, sealed_name, lambda f: self._verify(f, name, None))
                sizes[sealed_name] = info.size
            fsync_directory(sealed_fd)
        remove_empty_directories(run_fd, tree.directories)
        if list_tree(run_fd, self._limits, skip=frozenset({SEALED_DIR})).entries:
            raise EvidenceError("加密之後 sealed/ 之外仍有條目")
        fsync_directory(run_fd)
        return SealedEvidence(files=len(sizes), plaintext_bytes=sum(sizes.values()))

    def _seal_file(self, run_fd: int, sealed_fd: int, name: str, relative: str) -> tuple[str, int]:
        sealed_name = _sealed_name(relative)
        header_path = _header_path(relative)
        parent, base = open_parent(run_fd, relative)
        with opened(parent):
            info = self._write_sealed(parent, base, sealed_fd, sealed_name, name, header_path)
            verified = self._read_at(
                sealed_fd, sealed_name, lambda f: self._verify(f, name, header_path)
            )
            if (verified.size, verified.sha256) != (info.size, info.sha256):
                _unlink_quietly(sealed_name, sealed_fd)
                raise EvidenceError("加密檔的內容和明文不符")
            with contextlib.suppress(FileNotFoundError):
                os.unlink(base, dir_fd=parent)
        return sealed_name, info.size

    def _write_sealed(
        self, parent: int, base: str, sealed_fd: int, sealed_name: str, name: str, header: str
    ) -> StreamInfo:
        temporary = f"{_SEALING_PREFIX}{uuid4().hex}"
        source = os.open(base, READ_FLAGS, dir_fd=parent)
        with os.fdopen(source, "rb", buffering=CHUNK_BYTES) as reader:
            if not stat.S_ISREG(os.fstat(reader.fileno()).st_mode):
                raise EvidenceError("不是一般檔案")
            try:
                target = os.open(temporary, NEW_FILE_FLAGS, _STAGING_MODE, dir_fd=sealed_fd)
                with os.fdopen(target, "wb") as writer:
                    info = self._cipher.seal_stream(
                        reader, writer, context=evidence_context(name), path=header
                    )
                    writer.flush()
                    os.fchmod(writer.fileno(), READ_ONLY_FILE)
                    os.fsync(writer.fileno())
                os.replace(temporary, sealed_name, src_dir_fd=sealed_fd, dst_dir_fd=sealed_fd)
            except BaseException:
                _unlink_quietly(temporary, sealed_fd)
                raise
        return info

    def _rotate_file(self, sealed_fd: int, sealed_name: str, name: str) -> None:
        temporary = f"{_ROTATING_PREFIX}{uuid4().hex}"
        try:
            target = os.open(temporary, NEW_FILE_FLAGS, _STAGING_MODE, dir_fd=sealed_fd)
            with os.fdopen(target, "wb") as writer:
                info = self._read_at(
                    sealed_fd,
                    sealed_name,
                    lambda f: self._cipher.rotate_stream(f, writer, context=evidence_context(name)),
                )
                writer.flush()
                os.fchmod(writer.fileno(), READ_ONLY_FILE)
                os.fsync(writer.fileno())
            verified = self._read_at(
                sealed_fd, temporary, lambda f: self._verify(f, name, info.path)
            )
            if (verified.size, verified.sha256) != (info.size, info.sha256):
                raise EvidenceError("換版之後的內容和原本不符")
            os.replace(temporary, sealed_name, src_dir_fd=sealed_fd, dst_dir_fd=sealed_fd)
        except BaseException:
            _unlink_quietly(temporary, sealed_fd)
            raise

    def _verify(self, reader: BinaryIO, name: str, path: str | None) -> StreamInfo:
        return self._cipher.unseal_stream(reader, None, context=evidence_context(name), path=path)

    def _header(self, reader: BinaryIO, name: str) -> int:
        return self._cipher.read_stream_header(reader, context=evidence_context(name)).sealed_at

    def _sealed_directory(self, run_fd: int) -> int:
        with contextlib.suppress(FileExistsError):
            os.mkdir(SEALED_DIR, PRIVATE_DIR, dir_fd=run_fd)
        return open_child(SEALED_DIR, run_fd)

    def _discard_partials(self, sealed_fd: int) -> None:
        for entry in _top_level(sealed_fd):
            if entry.startswith(_PARTIAL_PREFIXES):
                unlink_at(sealed_fd, entry)

    def _sealed_names(self, run_fd: int) -> tuple[str, ...]:
        try:
            sealed_fd = os.open(SEALED_DIR, DIRECTORY_FLAGS, dir_fd=run_fd)
        except FileNotFoundError:
            return ()
        except OSError as exc:
            raise EvidenceError(f"無法開啟 sealed/（{reason(exc)}）") from None
        with opened(sealed_fd):
            return self._listed(sealed_fd)

    def _listed(self, sealed_fd: int) -> tuple[str, ...]:
        names = [entry for entry in _top_level(sealed_fd) if not entry.startswith(".")]
        if any(len(entry) != _SEALED_NAME_LENGTH for entry in names):
            raise EvidenceError("sealed/ 中有不認得的檔案")
        return tuple(sorted(names))

    def _read[T](self, run_fd: int, sealed_name: str, action: Callable[[BinaryIO], T]) -> T:
        with opened(open_child(SEALED_DIR, run_fd)) as sealed_fd:
            return self._read_at(sealed_fd, sealed_name, action)

    def _read_at[T](self, sealed_fd: int, sealed_name: str, action: Callable[[BinaryIO], T]) -> T:
        try:
            descriptor = os.open(sealed_name, READ_FLAGS, dir_fd=sealed_fd)
        except FileNotFoundError:
            raise EvidenceError("找不到這個檔案的加密檔") from None
        with os.fdopen(descriptor, "rb", buffering=CHUNK_BYTES) as reader:
            if not stat.S_ISREG(os.fstat(reader.fileno()).st_mode):
                raise EvidenceError("加密檔不是一般檔案")
            return action(reader)


def _sealed_name(relative: str) -> str:
    return hashlib.sha256(os.fsencode(relative)).hexdigest()


def _header_path(relative: str) -> str:
    """標頭中的路徑：太長時改用 sha256（加密檔的名稱一樣以原本的路徑計算）。"""
    if len(os.fsencode(relative)) <= MAX_PATH_BYTES:
        return relative
    return f"overlong-path/{_sealed_name(relative)}"


def _top_level(dir_fd: int) -> list[str]:
    try:
        with os.scandir(dir_fd) as listing:
            return [entry.name for entry in listing]
    except OSError as exc:
        raise EvidenceError(f"無法列出目錄（{reason(exc)}）") from None


def _unlink_quietly(name: str, dir_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        return


def _uuid_or_none(name: str) -> UUID | None:
    return canonical_uuid(name)


def _describe(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return f"檔案系統錯誤（{reason(exc)}）"
    return str(exc)
