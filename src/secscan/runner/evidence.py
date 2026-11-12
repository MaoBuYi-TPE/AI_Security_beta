"""runs volume 中原始證據的加密、清除、換版與匯出（docs/DECISIONS.md §30.3、§30.6）。

一個 run 的目錄（名稱是 run_id）加密之後只剩 `sealed/`：每個原本的檔案各一個加密檔，檔名是原本
相對路徑的 sha256（不會太長；同一個檔案重做時取代同一個加密檔，所以可以重複執行），原本的路徑
寫在已驗證的標頭中（security/blob_cipher.py）。底層的操作在 sealed_files.py。

加密一個檔案（先驗證才刪除）：
1. 寫進 sealed/ 中的暫存檔（.sealing-<隨機>，O_EXCL）→ fsync；
2. rename 成正式的名稱；
3. 串流解密，核對原本的路徑、大小與 sha256；
4. fsync sealed/（目錄項目落盤），才刪除明文；全部完成之後 fsync run 的目錄。
任何一步失敗都保留明文並拋出 EvidenceError：呼叫端不記下「已加密」，API 如實顯示 pending。

開始之前先處理中斷留下的檔案：sealed/ 中的 .sealing-*、.rotating-* 是不完整的密文，直接刪除；
run 目錄的 .masking-* 是收集時只遮罩了一部分的明文暫存檔（不是證據），也直接刪除。symlink 與
特殊檔案不跟隨、直接刪除；一般檔案不論 link 數都加密；缺少擁有者權限的目錄與檔案先補上權限。
例外與 log 只帶錯誤的種類，不帶路徑或內容。

vault 處理 runs volume 的一個區域（§30.13）：keeper 與一般的指令是 active/，retry-evidence 與換版
另外處理 held/。active/ 中找不到、卻在 held/ 中的目錄，加密、清除與匯出一律失敗（fail closed）。
"""

import contextlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Self
from uuid import uuid4

from secscan.core.identifiers import canonical_uuid
from secscan.runner.fs import (
    DIRECTORY_FLAGS,
    NEW_FILE_FLAGS,
    READ_FLAGS,
    READ_ONLY_FILE,
    fsync_directory,
    list_tree,
    open_child,
    open_parent,
    opened,
    reason,
    remove_empty_directories,
    remove_tree,
    unlink_at,
)
from secscan.runner.layout import Area, LayoutError, check_layout
from secscan.runner.sealed_files import (
    MASKING_PREFIX,
    ROTATING_PREFIX,
    SEALED_DIR,
    SEALING_PREFIX,
    STAGING_MODE,
    EvidenceError,
    EvidenceLimitError,
    SealedFiles,
    guarded,
    header_path,
    sealed_name,
    top_level,
    unlink_quietly,
)
from secscan.scans.domain.evidence import SealedEvidence, evidence_context
from secscan.security.blob_cipher import CHUNK_BYTES, Sink, StreamInfo

__all__ = ["SEALED_DIR", "DirectoryState", "EvidenceError", "EvidenceLimitError", "EvidenceVault"]

_CHECK_PREFIX = ".keeper-check-"
_SEALED_NAME_LENGTH = 64
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class DirectoryState:
    """一個目錄目前的樣子：sealed/ 之外是否還有條目、最近的修改時間、加密檔的數量。"""

    plaintext: bool
    newest_mtime: float
    sealed_files: int


class EvidenceVault(SealedFiles):
    @property
    def volume(self) -> Path:
        """runs volume 的根目錄。"""
        return self._runs

    def in_area(self, area: Area) -> Self:
        """同一個 volume、金鑰與上限，處理另一個區域（retry-evidence、換版處理 held/）。"""
        return type(self)(self._runs, self._cipher, limits=self._limits, area=area)

    # --- 列出與檢查 ------------------------------------------------------------------------

    def check(self) -> None:
        """runs volume 是預期的 layout（runner/layout.py），active/ 與 held/ 都可以寫入（keeper
        每一輪加密與清除之前）：沒有掛上 volume 時，找不到 run 的目錄不能當成「從來沒有目錄」。"""
        try:
            check_layout(self._runs)
        except LayoutError as exc:
            raise EvidenceError(str(exc)) from None
        for area in Area:
            probe = f"{_CHECK_PREFIX}{uuid4().hex}"
            with opened(self._open_area(area)) as area_fd:
                try:
                    os.close(os.open(probe, NEW_FILE_FLAGS, STAGING_MODE, dir_fd=area_fd))
                    os.unlink(probe, dir_fd=area_fd)
                except OSError as exc:
                    raise EvidenceError(f"{area.value}/ 無法寫入（{reason(exc)}）") from None

    def inode(self, name: str) -> int:
        """區域中這個目錄的 inode（隔離紀錄的 source_ino）；不是真的目錄（含 symlink）就失敗。"""
        if canonical_uuid(name) is None:
            raise ValueError("目錄名稱必須是標準格式的 run_id")
        with opened(self._open_area()) as area_fd:
            try:
                info = os.stat(name, dir_fd=area_fd, follow_symlinks=False)
            except OSError as exc:
                raise EvidenceError(f"無法檢查目錄（{reason(exc)}）") from None
        if not stat.S_ISDIR(info.st_mode):
            raise EvidenceError("不是目錄")
        return info.st_ino

    def entries(self) -> tuple[str, ...]:
        """區域中名稱是標準 UUID 的目錄（不跟隨 symlink）；超過上限就失敗、不截斷。"""
        names: list[str] = []
        with opened(self._open_area()) as runs_fd, guarded(), os.scandir(runs_fd) as listing:
            for entry in listing:
                if _is_run(entry):
                    names.append(entry.name)
                if len(names) > self._limits.max_entries:
                    raise EvidenceError("runs volume 中的目錄數量超過上限")
        return tuple(sorted(names))

    def inspect(self, name: str) -> DirectoryState | None:
        """目錄目前的樣子；沒有這個目錄時回 None。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            return None
        with opened(run_fd), guarded():
            tree = list_tree(run_fd, self._limits, skip=frozenset({SEALED_DIR}))
            own = os.fstat(run_fd).st_mtime
            sealed = self._sealed_names(run_fd)
        return DirectoryState(tree.entries > 0, max(tree.newest_mtime, own), len(sealed))

    def require_sealed_only(self, name: str) -> None:
        """目錄中只有 sealed/，sealed/ 中只有加密檔（64 個十六進位字元的一般檔案；沒有暫存檔、
        點開頭的條目或子目錄）。retry-evidence 搬回 active/ 之前與之後都檢查（安全審查 LOW-2）。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            raise EvidenceError("找不到這個目錄")
        with opened(run_fd), guarded():
            if top_level(run_fd) != [SEALED_DIR]:
                raise EvidenceError("sealed/ 之外仍有條目")
            with opened(open_child(SEALED_DIR, run_fd)) as sealed_fd:
                for entry in top_level(sealed_fd):
                    info = os.stat(entry, dir_fd=sealed_fd, follow_symlinks=False)
                    if not (_is_sealed_name(entry) and stat.S_ISREG(info.st_mode)):
                        raise EvidenceError("sealed/ 中有加密檔以外的條目")

    def sealed_at(self, name: str) -> int | None:
        """所有加密檔的標頭中最晚的加密時間（已驗證）；沒有加密檔時回 None。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            return None
        newest: int | None = None
        with opened(run_fd), guarded():
            for item in self._sealed_names(run_fd):
                header = self._read(run_fd, item, lambda f: self._header(f, name))
                newest = header if newest is None else max(newest, header)
        return newest

    # --- 加密與清除 ------------------------------------------------------------------------

    def seal(self, name: str) -> SealedEvidence | None:
        """加密目錄中 sealed/ 之外的每個檔案；沒有這個目錄時回 None。可以重複執行。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            self._refuse_held(name)
            return None
        with opened(run_fd), guarded("加密檔驗證不通過"):
            return self._seal(run_fd, name)

    def purge(self, name: str) -> None:
        """刪除整個目錄。sealed/ 之外還有條目時先加密（絕不在未加密時刪除）。

        先逐一刪除 sealed/ 中的加密檔，再刪除其餘部分：retry-evidence 以較高的上限加密的目錄，
        sealed/ 可能超過一般的條目上限（§30.12）。sealed/ 只由 runner 寫入、而且是平的（掃描容器
        只掛 in/ 與 out/）；其中有子目錄代表被改過，刪除失敗、fail closed。
        """
        state = self.inspect(name)
        if state is None:
            self._refuse_held(name)
            return
        if state.plaintext:
            self.seal(name)
        run_fd = self._open_run(name)
        if run_fd is None:
            return
        with opened(run_fd), guarded():
            self._empty_sealed(run_fd)
        with opened(self._open_area()) as runs_fd, guarded():
            remove_tree(runs_fd, name, self._limits)

    # --- 換版與匯出（admin 指令） ---------------------------------------------------------

    def rotate(self, name: str) -> int:
        """把目錄中每個加密檔改用第一個金鑰重新加密（驗證之後才取代）；回傳換版的數量。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            return 0
        with opened(run_fd), guarded():
            if not self._sealed_names(run_fd):
                return 0
            with opened(open_child(SEALED_DIR, run_fd)) as sealed_fd:
                self._discard_partials(sealed_fd)
                names = self._listed(sealed_fd)
                for item in names:
                    self._rotate_file(sealed_fd, item, name)
                fsync_directory(sealed_fd)
                return len(names)

    def export(self, name: str, path: str, sink: Sink) -> StreamInfo:
        """解密一個原本的檔案寫進 sink（驗證路徑；例外時 sink 已寫了一部分，呼叫端必須丟棄）。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            self._refuse_held(name)
            raise EvidenceError("沒有這個 run 的原始證據（不存在或已清除）")
        with opened(run_fd), guarded():
            return self._read(
                run_fd,
                sealed_name(path),
                lambda f: self._cipher.unseal_stream(
                    f, sink, context=evidence_context(name), path=header_path(path)
                ),
            )

    def listing(self, name: str) -> tuple[StreamInfo, ...]:
        """目錄中每個加密檔的原本路徑、大小與 sha256（逐一完整驗證）。"""
        run_fd = self._open_run(name)
        if run_fd is None:
            self._refuse_held(name)
            raise EvidenceError("沒有這個 run 的原始證據（不存在或已清除）")
        with opened(run_fd), guarded():
            try:
                sealed_fd = os.open(SEALED_DIR, DIRECTORY_FLAGS, dir_fd=run_fd)
            except FileNotFoundError:
                raise EvidenceError("這個 run 還沒有加密檔") from None
            with opened(sealed_fd):
                infos = [
                    self._read_at(sealed_fd, item, lambda f: self._verify(f, name, None))
                    for item in self._listed(sealed_fd)
                ]
        return tuple(sorted(infos, key=lambda info: info.path))

    # --- 內部 ------------------------------------------------------------------------------

    def _empty_sealed(self, run_fd: int) -> None:
        try:
            sealed_fd = os.open(SEALED_DIR, DIRECTORY_FLAGS, dir_fd=run_fd)
        except FileNotFoundError:
            return
        with opened(sealed_fd):
            for entry in top_level(sealed_fd):
                unlink_at(sealed_fd, entry)
            fsync_directory(sealed_fd)

    def _seal(self, run_fd: int, name: str) -> SealedEvidence:
        for entry in top_level(run_fd):
            if entry.startswith(MASKING_PREFIX):
                unlink_at(run_fd, entry)
        sealed_fd = self._sealed_directory(run_fd)
        with opened(sealed_fd):
            self._discard_partials(sealed_fd)
            earlier = set(self._listed(sealed_fd))
            tree = list_tree(
                run_fd, self._limits, skip=frozenset({SEALED_DIR}), restore_access=True
            )
            for relative in tree.others:
                unlink_at(run_fd, relative)
            sizes: dict[str, int] = {}
            for relative in tree.files:
                item, size = self._seal_file(run_fd, sealed_fd, name, relative)
                sizes[item] = size
            for item in sorted(earlier - set(sizes)):
                info = self._read_at(sealed_fd, item, lambda f: self._verify(f, name, None))
                sizes[item] = info.size
            fsync_directory(sealed_fd)
        remove_empty_directories(run_fd, tree.directories)
        if list_tree(run_fd, self._limits, skip=frozenset({SEALED_DIR})).entries:
            raise EvidenceError("加密之後 sealed/ 之外仍有條目")
        fsync_directory(run_fd)
        return SealedEvidence(files=len(sizes), plaintext_bytes=sum(sizes.values()))

    def _seal_file(self, run_fd: int, sealed_fd: int, name: str, relative: str) -> tuple[str, int]:
        item = sealed_name(relative)
        header = header_path(relative)
        parent, base = open_parent(run_fd, relative)
        with opened(parent):
            info = self._write_sealed(parent, base, sealed_fd, item, name, header)
            verified = self._read_at(sealed_fd, item, lambda f: self._verify(f, name, header))
            if (verified.size, verified.sha256) != (info.size, info.sha256):
                unlink_quietly(item, sealed_fd)
                raise EvidenceError("加密檔的內容和明文不符")
            # rename 之後的目錄項目先落盤，當機時才不會明文與密文都不見（安全審查 L4）。
            fsync_directory(sealed_fd)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(base, dir_fd=parent)
        return item, info.size

    def _write_sealed(
        self, parent: int, base: str, sealed_fd: int, item: str, name: str, header: str
    ) -> StreamInfo:
        temporary = f"{SEALING_PREFIX}{uuid4().hex}"
        source = os.open(base, READ_FLAGS, dir_fd=parent)
        with os.fdopen(source, "rb", buffering=CHUNK_BYTES) as reader:
            if not stat.S_ISREG(os.fstat(reader.fileno()).st_mode):
                raise EvidenceError("不是一般檔案")
            try:
                target = os.open(temporary, NEW_FILE_FLAGS, STAGING_MODE, dir_fd=sealed_fd)
                with os.fdopen(target, "wb") as writer:
                    info = self._cipher.seal_stream(
                        reader, writer, context=evidence_context(name), path=header
                    )
                    writer.flush()
                    os.fchmod(writer.fileno(), READ_ONLY_FILE)
                    os.fsync(writer.fileno())
                os.replace(temporary, item, src_dir_fd=sealed_fd, dst_dir_fd=sealed_fd)
            except BaseException:
                unlink_quietly(temporary, sealed_fd)
                raise
        return info

    def _rotate_file(self, sealed_fd: int, item: str, name: str) -> None:
        temporary = f"{ROTATING_PREFIX}{uuid4().hex}"
        try:
            target = os.open(temporary, NEW_FILE_FLAGS, STAGING_MODE, dir_fd=sealed_fd)
            with os.fdopen(target, "wb") as writer:
                info = self._read_at(
                    sealed_fd,
                    item,
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
            os.replace(temporary, item, src_dir_fd=sealed_fd, dst_dir_fd=sealed_fd)
        except BaseException:
            unlink_quietly(temporary, sealed_fd)
            raise


def _is_sealed_name(name: str) -> bool:
    return len(name) == _SEALED_NAME_LENGTH and all(char in _HEX for char in name)


def _is_run(entry: os.DirEntry[str]) -> bool:
    return canonical_uuid(entry.name) is not None and entry.is_dir(follow_symlinks=False)
