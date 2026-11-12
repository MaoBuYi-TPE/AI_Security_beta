"""runs volume 中加密檔的底層操作（docs/DECISIONS.md §30.3）：EvidenceVault 共用。

- 每個操作都先開啟 runs volume 的根目錄，再以 O_NOFOLLOW 開啟這個 vault 的區域（active/ 或
  held/；§30.13），開不了就是錯誤：根目錄不存在（主機上執行、volume 沒有掛上）時不能回報成
  「沒有這個 run 的目錄」，否則 keeper 會把待加密的 run 永久記成 none（審查 HIGH-2，§30.11）。
  run 的目錄以區域的 dir fd 加 O_NOFOLLOW 開啟。
- 加密檔放在 run 目錄的 `sealed/`，檔名是原本相對路徑的 sha256；原本的路徑寫在已驗證的標頭中
  （security/blob_cipher.py）。
- 例外一律轉成 EvidenceError（guarded），訊息只有原因，不含路徑或內容：任何一種失敗都不能讓
  keeper 的執行緒結束（審查 HIGH-1）。目錄樹超過深度、條目數或路徑總長度的上限是
  EvidenceLimitError，帶有隔離的錯誤代碼（§30.12）。
"""

import hashlib
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import BinaryIO

from secscan.core.identifiers import canonical_uuid
from secscan.runner.fs import (
    DIRECTORY_FLAGS,
    PRIVATE_DIR,
    READ_FLAGS,
    TreeError,
    TreeLimit,
    TreeLimitError,
    TreeLimits,
    open_child,
    opened,
    reason,
    unlink_at,
)
from secscan.runner.layout import Area
from secscan.scans.domain.evidence import EvidenceHoldCode, evidence_context
from secscan.security.blob_cipher import (
    CHUNK_BYTES,
    MAX_PATH_BYTES,
    BlobCipher,
    SealedDataUnreadableError,
    StreamInfo,
)

SEALED_DIR = "sealed"
SEALING_PREFIX = ".sealing-"
ROTATING_PREFIX = ".rotating-"
MASKING_PREFIX = ".masking-"
STAGING_MODE = 0o600
UNREADABLE = "加密檔解不開：金鑰不對，或內容被改過"
_PARTIAL_PREFIXES = (SEALING_PREFIX, ROTATING_PREFIX)
_SEALED_NAME_LENGTH = 64


class EvidenceError(Exception):
    """原始證據無法加密、驗證、清除或換版。訊息只有原因，不含路徑或內容。"""


class EvidenceLimitError(EvidenceError):
    """一個目錄超過資源上限（深度、條目數或路徑總長度）：keeper 連續 3 次就隔離它（§30.12）。"""

    def __init__(self, code: EvidenceHoldCode, message: str) -> None:
        super().__init__(message)
        self.code = code


_HOLD_CODES = {
    TreeLimit.DEPTH: EvidenceHoldCode.TREE_TOO_DEEP,
    TreeLimit.ENTRIES: EvidenceHoldCode.TREE_TOO_MANY_ENTRIES,
    TreeLimit.PATHS: EvidenceHoldCode.TREE_PATHS_TOO_LONG,
}


@contextmanager
def guarded(unreadable: str = UNREADABLE) -> Iterator[None]:
    """檔案系統與解密的錯誤一律轉成 EvidenceError（EvidenceError 本身照原樣拋出）。"""
    try:
        yield
    except TreeLimitError as exc:
        raise EvidenceLimitError(_HOLD_CODES[exc.limit], str(exc)) from None
    except (TreeError, OSError) as exc:
        raise EvidenceError(describe(exc)) from None
    except SealedDataUnreadableError:
        raise EvidenceError(unreadable) from None


class SealedFiles:
    def __init__(
        self,
        runs_dir: Path,
        cipher: BlobCipher,
        *,
        limits: TreeLimits | None = None,
        area: Area = Area.ACTIVE,
    ) -> None:
        """runs_dir 是 runs volume 的根目錄；area 是這個 vault 處理的區域。"""
        self._runs = runs_dir
        self._area = area
        self._cipher = cipher
        self._limits = limits if limits is not None else TreeLimits()

    def _open_volume(self) -> int:
        try:
            return os.open(self._runs, DIRECTORY_FLAGS)
        except OSError as exc:
            raise EvidenceError(f"無法開啟 runs volume（{reason(exc)}）") from None

    def _open_area(self, area: Area | None = None) -> int:
        """區域的目錄（以 O_NOFOLLOW 開啟：active、held 是 symlink 時失敗）。"""
        name = (area or self._area).value
        with opened(self._open_volume()) as root_fd:
            try:
                return os.open(name, DIRECTORY_FLAGS, dir_fd=root_fd)
            except OSError as exc:
                raise EvidenceError(f"無法開啟 {name}/（{reason(exc)}）") from None

    def _open_run(self, name: str) -> int | None:
        """run 的目錄；區域正常而這個目錄不存在時回 None。"""
        if canonical_uuid(name) is None:
            raise ValueError("目錄名稱必須是標準格式的 run_id")
        with opened(self._open_area()) as area_fd:
            try:
                return os.open(name, DIRECTORY_FLAGS, dir_fd=area_fd)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise EvidenceError(f"無法開啟目錄（{reason(exc)}）") from None

    def _refuse_held(self, name: str) -> None:
        """active/ 中沒有這個目錄時，確認它不在 held/：在 held/ 代表 DB 不認為它是隔離的目錄，
        它卻在 held/（不一致），一律失敗、fail closed（§30.13）。"""
        if self._area is not Area.ACTIVE:
            return
        with opened(self._open_area(Area.HELD)) as held_fd:
            try:
                os.stat(name, dir_fd=held_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            except OSError as exc:
                raise EvidenceError(f"無法檢查 held/（{reason(exc)}）") from None
        raise EvidenceError("這個目錄在 held/ 中（已隔離），不能在 active/ 處理")

    def _verify(self, reader: BinaryIO, name: str, path: str | None) -> StreamInfo:
        return self._cipher.unseal_stream(reader, None, context=evidence_context(name), path=path)

    def _header(self, reader: BinaryIO, name: str) -> int:
        return self._cipher.read_stream_header(reader, context=evidence_context(name)).sealed_at

    def _sealed_directory(self, run_fd: int) -> int:
        with suppress(FileExistsError):
            os.mkdir(SEALED_DIR, PRIVATE_DIR, dir_fd=run_fd)
        return open_child(SEALED_DIR, run_fd)

    def _discard_partials(self, sealed_fd: int) -> None:
        for entry in top_level(sealed_fd):
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
        names = [entry for entry in top_level(sealed_fd) if not entry.startswith(".")]
        if any(len(entry) != _SEALED_NAME_LENGTH for entry in names):
            raise EvidenceError("sealed/ 中有不認得的檔案")
        return tuple(sorted(names))

    def _read[T](self, run_fd: int, sealed_name: str, action: Callable[[BinaryIO], T]) -> T:
        try:
            sealed_fd = os.open(SEALED_DIR, DIRECTORY_FLAGS, dir_fd=run_fd)
        except FileNotFoundError:
            raise EvidenceError("這個 run 還沒有加密檔") from None
        with opened(sealed_fd):
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


def sealed_name(relative: str) -> str:
    return hashlib.sha256(os.fsencode(relative)).hexdigest()


def header_path(relative: str) -> str:
    """標頭中的路徑：太長時改用 sha256（加密檔的名稱一樣以原本的路徑計算）。"""
    if len(os.fsencode(relative)) <= MAX_PATH_BYTES:
        return relative
    return f"overlong-path/{sealed_name(relative)}"


def top_level(dir_fd: int) -> list[str]:
    try:
        with os.scandir(dir_fd) as listing:
            return [entry.name for entry in listing]
    except OSError as exc:
        raise EvidenceError(f"無法列出目錄（{reason(exc)}）") from None


def unlink_quietly(name: str, dir_fd: int) -> None:
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        return


def describe(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return f"檔案系統錯誤（{reason(exc)}）"
    return str(exc)
