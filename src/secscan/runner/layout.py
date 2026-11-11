"""runs volume 的 layout（docs/DECISIONS.md §30.13）：worker 只掛載 active/，隔離的目錄放在 held/。

    <volume 的根目錄>
    ├── .layout          一般檔案，內容剛好是 {"layout": 2}
    ├── active/<run_id>/ 一般的 run 目錄（in/、out/、manifest.json、sealed/）
    └── held/<名稱>/     隔離的目錄（明文，或解除中的加密檔）

- check_layout：runs-init、runner 啟動時與 keeper 每一輪（vault.check）都呼叫。有 .layout 也重新
  檢查全部條件，不只相信標記：標記是一般檔案而且內容正確、根目錄沒有還沒搬移的 UUID 目錄、沒有
  搬移中的暫存目錄、active/ 與 held/ 是真的目錄（不是 symlink）而且權限是 0700。其他條目只計數。
- init_layout（runs-init）：根目錄是空的才建立結構；其他情況只檢查，不通過就要求執行
  make runs-layout-migrate（搬移由管理員指令處理，不由 runner 自動搬移）。
- 例外只帶原因，不帶路徑。
"""

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from secscan.core.identifiers import canonical_uuid
from secscan.runner.domain.areas import ACTIVE_AREA, HELD_AREA
from secscan.runner.fs import (
    DIRECTORY_FLAGS,
    NEW_FILE_FLAGS,
    PRIVATE_DIR,
    READ_FLAGS,
    opened,
    reason,
)

LAYOUT_FILE = ".layout"
LAYOUT_CONTENT = b'{"layout": 2}'
MIGRATING_DIR = ".active-migrating"
_LAYOUT_PREFIX = ".layout-"
_MAX_LAYOUT_BYTES = 64
_MIGRATE = "請執行 make runs-layout-migrate"


class Area(StrEnum):
    """runs volume 中的兩個區域。"""

    ACTIVE = ACTIVE_AREA
    HELD = HELD_AREA


class LayoutError(Exception):
    """runs volume 不是預期的 layout。訊息只有原因，不含路徑。"""


@dataclass(frozen=True, slots=True)
class LayoutReport:
    """layout 正確；others 是根目錄中其他條目的數量（不阻擋，只顯示）。"""

    others: int
    created: bool = False


def active_dir(runs_dir: Path) -> Path:
    return runs_dir / Area.ACTIVE.value


def held_dir(runs_dir: Path) -> Path:
    return runs_dir / Area.HELD.value


def check_layout(runs_dir: Path) -> LayoutReport:
    with opened(open_volume(runs_dir)) as root_fd:
        return check_root(root_fd)


def init_layout(runs_dir: Path) -> LayoutReport:
    """根目錄是空的就建立 active/、held/ 與 .layout；否則和 check_layout 相同。"""
    with opened(open_volume(runs_dir)) as root_fd:
        if _entries(root_fd):
            return check_root(root_fd)
        for area in Area:
            make_area(root_fd, area)
        write_marker(root_fd)
        return LayoutReport(others=0, created=True)


def open_volume(runs_dir: Path) -> int:
    try:
        return os.open(runs_dir, DIRECTORY_FLAGS)
    except OSError as exc:
        raise LayoutError(f"無法開啟 runs volume（{reason(exc)}）") from None


def check_root(root_fd: int) -> LayoutReport:
    _check_marker(root_fd)
    others = 0
    for name in _entries(root_fd):
        if canonical_uuid(name) is not None:
            raise LayoutError(f"runs volume 的根目錄還有沒搬移的 run 目錄：{_MIGRATE}")
        if name == MIGRATING_DIR:
            raise LayoutError(f"runs volume 的搬移還沒完成：{_MIGRATE}")
        if name not in (LAYOUT_FILE, Area.ACTIVE.value, Area.HELD.value):
            others += 1
    for area in Area:
        check_area(root_fd, area)
    return LayoutReport(others=others)


def check_area(root_fd: int, area: Area) -> None:
    """area 是真的目錄（不是 symlink），而且只有擁有者能存取。"""
    try:
        info = os.stat(area.value, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise LayoutError(f"runs volume 沒有 {area.value}/：{_MIGRATE}") from None
    except OSError as exc:
        raise LayoutError(f"無法檢查 {area.value}/（{reason(exc)}）") from None
    if not stat.S_ISDIR(info.st_mode):
        raise LayoutError(f"runs volume 的 {area.value} 不是目錄（可能是 symlink）")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise LayoutError(f"runs volume 的 {area.value}/ 權限必須是 0700")


def make_area(root_fd: int, area: Area | str) -> None:
    """建立區域（已存在就不動，由 check_area 檢查）。"""
    name = area.value if isinstance(area, Area) else area
    try:
        os.mkdir(name, PRIVATE_DIR, dir_fd=root_fd)
    except FileExistsError:
        return
    except OSError as exc:
        raise LayoutError(f"無法建立 {name}/（{reason(exc)}）") from None


def write_marker(root_fd: int) -> None:
    """先寫暫存檔、fsync、rename，再 fsync 根目錄（當機時不會留下不完整的標記）。"""
    temporary = f"{_LAYOUT_PREFIX}{uuid4().hex}"
    try:
        descriptor = os.open(temporary, NEW_FILE_FLAGS, 0o600, dir_fd=root_fd)
        with os.fdopen(descriptor, "wb") as writer:
            writer.write(LAYOUT_CONTENT)
            writer.flush()
            os.fsync(writer.fileno())
        os.rename(temporary, LAYOUT_FILE, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
    except OSError as exc:
        with _quietly():
            os.unlink(temporary, dir_fd=root_fd)
        raise LayoutError(f"無法寫入 {LAYOUT_FILE}（{reason(exc)}）") from None


def has_marker(root_fd: int) -> bool:
    try:
        _check_marker(root_fd)
    except LayoutError:
        return False
    return True


def _check_marker(root_fd: int) -> None:
    try:
        info = os.stat(LAYOUT_FILE, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise LayoutError(f"runs volume 沒有 {LAYOUT_FILE}（舊的 layout）：{_MIGRATE}") from None
    except OSError as exc:
        raise LayoutError(f"無法檢查 {LAYOUT_FILE}（{reason(exc)}）") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_LAYOUT_BYTES:
        raise LayoutError(f"{LAYOUT_FILE} 不是預期的一般檔案")
    try:
        descriptor = os.open(LAYOUT_FILE, READ_FLAGS, dir_fd=root_fd)
    except OSError as exc:
        raise LayoutError(f"無法讀取 {LAYOUT_FILE}（{reason(exc)}）") from None
    with os.fdopen(descriptor, "rb") as reader:
        if not stat.S_ISREG(os.fstat(reader.fileno()).st_mode):
            raise LayoutError(f"{LAYOUT_FILE} 不是預期的一般檔案")
        content = reader.read(_MAX_LAYOUT_BYTES + 1)
    if content != LAYOUT_CONTENT:
        raise LayoutError(f"{LAYOUT_FILE} 的內容不是預期的版本")


def _entries(root_fd: int) -> list[str]:
    try:
        with os.scandir(root_fd) as listing:
            return [entry.name for entry in listing]
    except OSError as exc:
        raise LayoutError(f"無法列出 runs volume（{reason(exc)}）") from None


@contextmanager
def _quietly() -> Iterator[None]:
    try:
        yield
    except OSError:
        return
