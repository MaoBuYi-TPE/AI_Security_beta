"""既有的 runs volume 搬到新的 layout（docs/DECISIONS.md §30.13）。

secscan-admin migrate-runs-layout 使用。

只處理根目錄下直接的條目：
- 標準 UUID 名稱的真實目錄（lstat）：有還沒解除的隔離紀錄就搬到 held/，其他的搬到 active/（還沒有
  active/ 時先搬到暫存目錄 .active-migrating/，全部完成之後再以一次 rename 改名成 active，所以
  active/ 一出現就是完整的）。
- 搬到 held/ 之前，v0024 之前留下的紀錄先記下來源 inode（轉換 0）；搬移與驗證和 keeper 的隔離相同
  （runner/hold_moves.py：inode 比對、目的地必須不存在、rename、fsync、事後驗證）。
- 其他條目不動，只計數（名稱以 ASCII 跳脫後顯示）。
步驟：建立 held/ 與目的地 → 逐一搬移（衝突的不動）→ fsync → 有衝突就停止（不完成 layout）→
.active-migrating 改名成 active → 寫 .layout → 搬到 held/ 的紀錄確認身分之後寫入 isolated_at →
check_root 確認完成。

可以重跑：檔案系統的狀態就是進度。中斷在寫 isolated_at 之前時，keeper 的對帳也會補寫。
DB 的前提（lease、容器、advisory lock）與 audit 由 cli/runs_layout.py 負責。
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Protocol
from uuid import UUID

from secscan.core.identifiers import canonical_uuid
from secscan.runner.fs import TreeError, fsync_directory, open_child, opened
from secscan.runner.hold_moves import MoveError, directory_inode, move_entry, verify_entry
from secscan.runner.layout import (
    LAYOUT_FILE,
    MIGRATING_DIR,
    Area,
    LayoutError,
    check_root,
    has_marker,
    make_area,
    open_volume,
    write_marker,
)
from secscan.runner.sealed_files import EvidenceError
from secscan.scans.domain.evidence import HoldMoveCode, HoldStage
from secscan.scans.evidence_holds import HeldDirectory

_STRUCTURE = frozenset({LAYOUT_FILE, MIGRATING_DIR, Area.ACTIVE.value, Area.HELD.value})
_CONFLICT = HoldMoveCode.CONFLICT


class MigrationStore(Protocol):
    """DB 的部分（scans.evidence_hold_isolation.HoldIsolationStore）。"""

    def record_source(self, directory: UUID, source_ino: int) -> bool: ...

    def mark_isolated(self, held: HeldDirectory) -> bool: ...


@dataclass(frozen=True, slots=True)
class MigrationPlan:
    """blocking：根目錄中 UUID 名稱、但不是目錄的條目（例如 symlink）。layout 的檢查不允許它們，
    所以有的話不能完成，必須人工處理（程式碼審查 L1）。"""

    to_active: tuple[str, ...]
    to_held: tuple[str, ...]
    others: tuple[str, ...]
    has_marker: bool
    blocking: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MigrationResult:
    """unverified：已搬到 held/、但身分驗證不通過而沒有寫入 isolated_at 的紀錄（交給 keeper 的
    對帳，維持隔離中、看得見）。"""

    moved_active: int
    moved_held: int
    isolated: int
    conflicts: tuple[str, ...]
    unverified: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.conflicts


class LayoutMigrator:
    def __init__(
        self, runs_dir: Path, holds: Mapping[str, HeldDirectory], store: MigrationStore
    ) -> None:
        """holds：還沒解除的隔離紀錄（目錄名稱 → 紀錄）。"""
        self._runs = runs_dir
        self._holds = dict(holds)
        self._store = store

    def plan(self) -> MigrationPlan:
        to_active: list[str] = []
        to_held: list[str] = []
        others: list[str] = []
        blocking: list[str] = []
        with opened(open_volume(self._runs)) as root_fd:
            marker = has_marker(root_fd)
            try:
                with os.scandir(root_fd) as listing:
                    for entry in listing:
                        if entry.name in _STRUCTURE:
                            continue
                        if canonical_uuid(entry.name) is None:
                            others.append(escaped(entry.name))
                        elif not entry.is_dir(follow_symlinks=False):
                            blocking.append(escaped(entry.name))
                        else:
                            target = to_held if entry.name in self._holds else to_active
                            target.append(entry.name)
            except OSError as exc:
                raise LayoutError(f"無法列出 runs volume（{type(exc).__name__}）") from None
        return MigrationPlan(
            tuple(sorted(to_active)),
            tuple(sorted(to_held)),
            tuple(others),
            marker,
            tuple(sorted(blocking)),
        )

    def migrate(self, plan: MigrationPlan) -> MigrationResult:
        """搬移並完成 layout；有衝突時不完成（回傳衝突的名稱），其他的照常搬移。"""
        with opened(open_volume(self._runs)) as root_fd:
            make_area(root_fd, Area.HELD)
            staging = not _exists(root_fd, Area.ACTIVE.value)
            target = MIGRATING_DIR if staging else Area.ACTIVE.value
            make_area(root_fd, target)
            conflicts: list[str] = []
            with opened(_child(root_fd, Area.HELD.value)) as held_fd:
                with opened(_child(root_fd, target)) as target_fd:
                    moved_held = self._move_held(root_fd, held_fd, plan.to_held, conflicts)
                    moved_active = _move_all(root_fd, target_fd, plan.to_active, conflicts)
                    _sync(root_fd, held_fd, target_fd)
                if conflicts:
                    return MigrationResult(moved_active, moved_held, 0, tuple(conflicts))
                if staging:
                    _rename(root_fd, MIGRATING_DIR, Area.ACTIVE.value)
                if not has_marker(root_fd):
                    write_marker(root_fd)
                isolated, unverified = self._isolate(held_fd)
            check_root(root_fd)
            return MigrationResult(moved_active, moved_held, isolated, (), unverified)

    def _move_held(
        self, root_fd: int, held_fd: int, names: tuple[str, ...], conflicts: list[str]
    ) -> int:
        moved = 0
        for name in names:
            held = self._holds[name]
            try:
                source_ino = directory_inode(root_fd, name)
                if held.hold.stage is not HoldStage.ISOLATING:
                    raise MoveError(_CONFLICT, "隔離紀錄不是隔離中，目錄卻在根目錄")
                if held.source_ino is None:
                    if not self._store.record_source(held.directory, source_ino):
                        raise MoveError(_CONFLICT, "無法記下來源 inode")
                    self._holds[name] = replace(held, source_ino=source_ino)
                elif held.source_ino != source_ino:
                    raise MoveError(_CONFLICT, "目錄的 inode 和隔離紀錄不符")
                move_entry(root_fd, held_fd, name, source_ino)
            except MoveError:
                conflicts.append(name)
                continue
            moved += 1
        return moved

    def _isolate(self, held_fd: int) -> tuple[int, tuple[str, ...]]:
        """held/ 中、還在隔離中的紀錄：確認身分（目錄項目已在上一步 fsync）之後寫入 isolated_at。
        身分不符的紀錄不寫入、繼續處理其他的（程式碼審查 L1），回傳隔離完成的數量與不符的名稱。"""
        isolated = 0
        unverified: list[str] = []
        for name, held in sorted(self._holds.items()):
            if held.hold.stage is not HoldStage.ISOLATING or held.source_ino is None:
                continue
            if not _exists(held_fd, name):
                continue
            try:
                verify_entry(held_fd, name, held.source_ino)
            except MoveError:
                unverified.append(name)
                continue
            if self._store.mark_isolated(held):
                isolated += 1
        return isolated, tuple(unverified)


def _move_all(root_fd: int, target_fd: int, names: tuple[str, ...], conflicts: list[str]) -> int:
    moved = 0
    for name in names:
        try:
            move_entry(root_fd, target_fd, name, directory_inode(root_fd, name))
        except MoveError:
            conflicts.append(name)
            continue
        moved += 1
    return moved


def escaped(name: str) -> str:
    """不可信的檔名：以 ASCII 跳脫（不把控制字元與 bidi 直接印到終端）。"""
    return "".join(
        chr(byte) if 0x20 <= byte < 0x7F and byte != 0x5C else f"\\x{byte:02x}"
        for byte in os.fsencode(name)
    )


def _exists(dir_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise EvidenceError(f"無法檢查 runs volume（{type(exc).__name__}）") from None
    return True


def _child(root_fd: int, name: str) -> int:
    try:
        return open_child(name, root_fd)
    except TreeError as exc:
        raise LayoutError(str(exc)) from None


def _sync(*fds: int) -> None:
    try:
        for fd in fds:
            fsync_directory(fd)
    except TreeError as exc:
        raise LayoutError(str(exc)) from None


def _rename(root_fd: int, source: str, target: str) -> None:
    try:
        os.rename(source, target, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError as exc:
        raise LayoutError(f"無法完成 active/（{type(exc).__name__}）") from None
