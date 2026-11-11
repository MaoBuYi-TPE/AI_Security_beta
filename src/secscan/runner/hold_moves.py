"""隔離目錄在 runs volume 的 active/ 與 held/ 之間的搬移（docs/DECISIONS.md §30.13）。

只有 runner（keeper 的對帳，以及 runner 容器內的 retry-evidence、migrate-runs-layout）使用。
搬移（move）：
1. 以 dir fd 開啟來源與目的地的區域（O_NOFOLLOW）；
2. lstat 來源：必須是真的目錄（不跟隨 symlink），inode 等於隔離紀錄的 source_ino，否則是衝突；
3. lstat 目的地：必須不存在；
4. rename（兩個 dir fd）；
5. fsync 目的地與來源的區域；
6. 確認目的地的 inode 等於 source_ino、和目的地的區域在同一個裝置上，而且來源已不存在。

第 3 步是緩解措施，不是原子保證：檢查與 rename 之間有空檔，rename 會取代已存在的「空」目錄；
非空的目的地讓 rename 本身失敗（ENOTEMPTY、EEXIST），既有的證據不會被覆寫。真正的保證來自
「只有持有 evidence advisory lock 的 runner 寫 held/」（§30.13 的剩餘風險）。

identify：對帳補寫 isolated_at 之前，確認區域中的條目是真的目錄、在同一個裝置上（不是另一個掛載
點）、inode 等於 source_ino。不符合是衝突。
例外只帶代碼與原因，不帶路徑。
"""

import errno
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from secscan.core.identifiers import canonical_uuid
from secscan.runner.fs import DIRECTORY_FLAGS, TreeError, fsync_directory, opened, reason
from secscan.runner.layout import Area
from secscan.runner.sealed_files import EvidenceError
from secscan.scans.domain.evidence import HoldMoveCode

# held/ 中的條目上限：超過就全域 fail closed（和一般的目錄條目上限相同）。
MAX_HELD_ENTRIES = 20_000
_CONFLICTS = (errno.ENOTEMPTY, errno.EEXIST, errno.ENOTDIR, errno.EISDIR)


class MoveError(EvidenceError):
    """這個目錄搬不動或身分不符；只讓這個目錄退避（不是全域的失敗）。"""

    def __init__(self, code: HoldMoveCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class Presence:
    """一個名稱是否出現在 active/ 與 held/（任何種類的條目都算）。"""

    active: bool
    held: bool


@dataclass(frozen=True, slots=True)
class HeldListing:
    """held/ 中標準 UUID 名稱的真實目錄，以及其他條目的數量。"""

    directories: tuple[str, ...]
    others: int


class HoldMoves:
    def __init__(self, runs_dir: Path) -> None:
        """runs_dir 是 runs volume 的根目錄。"""
        self._runs = runs_dir

    def presence(self, name: str) -> Presence:
        _require_uuid(name)
        with self._areas() as (active_fd, held_fd):
            return Presence(_exists(active_fd, name), _exists(held_fd, name))

    def move(self, name: str, source: Area, target: Area, source_ino: int) -> None:
        _require_uuid(name)
        if source is target:
            raise ValueError("來源與目的地必須是不同的區域")
        with self._areas() as (active_fd, held_fd):
            fds = {Area.ACTIVE: active_fd, Area.HELD: held_fd}
            move_entry(fds[source], fds[target], name, source_ino)

    def identify(self, name: str, area: Area, source_ino: int) -> None:
        """區域中的條目就是原本的目錄；不是就拋 MoveError（CONFLICT）。"""
        _require_uuid(name)
        with self._areas() as (active_fd, held_fd):
            verify_entry(active_fd if area is Area.ACTIVE else held_fd, name, source_ino)

    def settle(self) -> None:
        """fsync held/ 與 active/（對帳補寫 isolated_at 之前，讓目錄項目落盤）。"""
        with self._areas() as (active_fd, held_fd):
            _sync(held_fd, active_fd)

    def held_entries(self) -> HeldListing:
        directories: list[str] = []
        others = 0
        with self._areas() as (_, held_fd):
            try:
                with os.scandir(held_fd) as listing:
                    for count, entry in enumerate(listing, start=1):
                        if count > MAX_HELD_ENTRIES:
                            raise EvidenceError("held/ 的條目數量超過上限")
                        if canonical_uuid(entry.name) is not None and entry.is_dir(
                            follow_symlinks=False
                        ):
                            directories.append(entry.name)
                        else:
                            others += 1
            except OSError as exc:
                raise EvidenceError(f"無法列出 held/（{reason(exc)}）") from None
        return HeldListing(tuple(sorted(directories)), others)

    @contextmanager
    def _areas(self) -> Iterator[tuple[int, int]]:
        """(active/, held/) 的 dir fd；開不了是全域的錯誤（EvidenceError）。"""
        try:
            root_fd = os.open(self._runs, DIRECTORY_FLAGS)
        except OSError as exc:
            raise EvidenceError(f"無法開啟 runs volume（{reason(exc)}）") from None
        with opened(root_fd):
            active_fd = _open_area(root_fd, Area.ACTIVE)
            with opened(active_fd):
                held_fd = _open_area(root_fd, Area.HELD)
                with opened(held_fd):
                    yield active_fd, held_fd


def move_entry(source_fd: int, target_fd: int, name: str, source_ino: int) -> None:
    """把 source_fd 中的目錄 name 搬到 target_fd（模組說明的第 2 到 6 步）。"""
    _check_source(source_fd, name, source_ino)
    if _exists(target_fd, name):
        raise MoveError(HoldMoveCode.CONFLICT, "目的地已有同名的條目")
    try:
        os.rename(name, name, src_dir_fd=source_fd, dst_dir_fd=target_fd)
    except OSError as exc:
        raise _rename_error(exc) from None
    _sync(target_fd, source_fd)
    verify_entry(target_fd, name, source_ino)
    if _exists(source_fd, name):
        raise MoveError(HoldMoveCode.CONFLICT, "搬移之後來源仍有同名的條目")


def directory_inode(dir_fd: int, name: str) -> int:
    """dir_fd 中這個條目的 inode；不是真的目錄（含 symlink）就拋 MoveError。"""
    info = _lstat(dir_fd, name)
    if not stat.S_ISDIR(info.st_mode):
        raise MoveError(HoldMoveCode.NOT_DIRECTORY, "不是目錄（可能是 symlink）")
    return info.st_ino


def _open_area(root_fd: int, area: Area) -> int:
    try:
        return os.open(area.value, DIRECTORY_FLAGS, dir_fd=root_fd)
    except OSError as exc:
        raise EvidenceError(f"無法開啟 {area.value}/（{reason(exc)}）") from None


def _require_uuid(name: str) -> None:
    if canonical_uuid(name) is None:
        raise ValueError("目錄名稱必須是標準格式的 UUID")


def _exists(dir_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise MoveError(HoldMoveCode.MOVE_FAILED, f"無法檢查目錄（{reason(exc)}）") from None
    return True


def _lstat(dir_fd: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise MoveError(HoldMoveCode.DIRECTORY_MISSING, "找不到這個目錄") from None
    except OSError as exc:
        raise MoveError(HoldMoveCode.MOVE_FAILED, f"無法檢查目錄（{reason(exc)}）") from None


def _check_source(dir_fd: int, name: str, source_ino: int) -> None:
    if directory_inode(dir_fd, name) != source_ino:
        raise MoveError(HoldMoveCode.CONFLICT, "目錄的 inode 和隔離紀錄不符")


def verify_entry(area_fd: int, name: str, source_ino: int) -> None:
    """area_fd 中的條目是真的目錄、和 area_fd 在同一個裝置上，而且 inode 等於 source_ino。"""
    info = _lstat(area_fd, name)
    if not stat.S_ISDIR(info.st_mode):
        raise MoveError(HoldMoveCode.CONFLICT, "不是目錄（可能是 symlink）")
    if info.st_dev != os.fstat(area_fd).st_dev:
        raise MoveError(HoldMoveCode.CONFLICT, "目錄不在同一個裝置上（可能是另一個掛載點）")
    if info.st_ino != source_ino:
        raise MoveError(HoldMoveCode.CONFLICT, "目錄的 inode 和隔離紀錄不符")


def _sync(*fds: int) -> None:
    try:
        for fd in fds:
            fsync_directory(fd)
    except TreeError as exc:
        raise MoveError(HoldMoveCode.MOVE_FAILED, str(exc)) from None


def _rename_error(exc: OSError) -> MoveError:
    if exc.errno in _CONFLICTS:
        return MoveError(HoldMoveCode.CONFLICT, f"目的地已有同名的條目（{reason(exc)}）")
    if exc.errno == errno.ENOENT:
        return MoveError(HoldMoveCode.DIRECTORY_MISSING, "找不到這個目錄")
    return MoveError(HoldMoveCode.MOVE_FAILED, f"無法搬移（{reason(exc)}）")
