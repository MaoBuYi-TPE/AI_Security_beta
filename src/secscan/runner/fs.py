"""runs volume 的檔案操作（docs/DECISIONS.md §30.3）：加密、清除與刪除 probe 的目錄共用。

- 一律以 dir fd 加 O_NOFOLLOW 開啟：工具建立的 symlink 不會讓 runner 讀到或刪到別的地方
  （和 workspace.py 收集輸出的做法相同）。
- 走訪有深度與條目數的上限，先列出整棵樹再處理（走訪中改變目錄，os.scandir 可能重複或漏掉條目）。
- 例外只帶錯誤的種類，不帶路徑（檔名由不可信的工具決定）。
"""

import errno
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
NEW_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
PRIVATE_DIR = 0o700
READ_ONLY_FILE = 0o400


class TreeError(Exception):
    """目錄樹無法處理（超過上限、沒有權限、被換掉…）。訊息只有原因，不含路徑。"""


@dataclass(frozen=True, slots=True)
class TreeLimits:
    max_depth: int = 32
    max_entries: int = 20_000


@dataclass(slots=True)
class Tree:
    """一棵目錄樹（相對路徑以 / 分隔）：一般檔案、其他條目（symlink、裝置檔…）與目錄。"""

    files: list[str] = field(default_factory=list)
    others: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    newest_mtime: float = 0.0
    entries: int = 0


def reason(exc: OSError) -> str:
    """只回報錯誤的種類（例如 EACCES、ENOSPC）：OSError 的訊息含路徑。"""
    return errno.errorcode.get(exc.errno or 0, type(exc).__name__)


def open_directory(path: Path) -> int:
    try:
        return os.open(path, DIRECTORY_FLAGS)
    except OSError as exc:
        raise TreeError(f"無法開啟目錄（{reason(exc)}）") from None


def open_child(name: str, dir_fd: int) -> int:
    try:
        return os.open(name, DIRECTORY_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise TreeError(f"無法開啟子目錄（{reason(exc)}）") from None


@contextmanager
def opened(fd: int) -> Iterator[int]:
    try:
        yield fd
    finally:
        os.close(fd)


def open_parent(root_fd: int, relative: str) -> tuple[int, str]:
    """root 底下這個路徑的上層目錄（一層一層以 O_NOFOLLOW 開啟）與最後的名稱。"""
    *directories, name = relative.split("/")
    current = os.dup(root_fd)
    for directory in directories:
        try:
            child = open_child(directory, current)
        finally:
            os.close(current)
        current = child
    return current, name


def list_tree(
    root_fd: int,
    limits: TreeLimits,
    *,
    skip: frozenset[str] = frozenset(),
    restore_access: bool = False,
) -> Tree:
    """列出 root 底下的整棵樹（不跟隨 symlink）；skip 是 root 這一層要略過的名稱。

    restore_access：目錄與一般檔案缺少擁有者的權限時先補上（目錄 rwx、檔案 r）。掃描容器和
    runner 是同一個 uid，可以把 out/ 或其中的檔案改成 000；容器已確認刪除、worker 只能唯讀，
    走訪期間沒有其他程序會改這棵樹（docs/DECISIONS.md §30.11）。
    """
    walk = _Walk(Tree(), limits, restore_access)
    _list(walk, root_fd, "", 0, skip)
    return walk.tree


@dataclass(frozen=True, slots=True)
class _Walk:
    tree: Tree
    limits: TreeLimits
    restore_access: bool


def _list(walk: _Walk, dir_fd: int, prefix: str, depth: int, skip: frozenset[str]) -> None:
    try:
        entries = os.scandir(dir_fd)
    except OSError as exc:
        raise TreeError(f"無法列出目錄（{reason(exc)}）") from None
    with entries:
        for entry in entries:
            if not prefix and entry.name in skip:
                continue
            walk.tree.entries += 1
            if walk.tree.entries > walk.limits.max_entries:
                raise TreeError("目錄的條目超過上限")
            _visit(walk, dir_fd, entry.name, prefix, depth)


def _visit(walk: _Walk, dir_fd: int, name: str, prefix: str, depth: int) -> None:
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TreeError(f"無法讀取條目（{reason(exc)}）") from None
    tree = walk.tree
    relative = f"{prefix}{name}"
    tree.newest_mtime = max(tree.newest_mtime, info.st_mtime)
    if stat.S_ISREG(info.st_mode):
        if walk.restore_access:
            _grant(dir_fd, name, info.st_mode, _OWNER_READ)
        tree.files.append(relative)
    elif stat.S_ISDIR(info.st_mode):
        if depth + 1 > walk.limits.max_depth:
            raise TreeError("目錄的深度超過上限")
        if walk.restore_access:
            _grant(dir_fd, name, info.st_mode, PRIVATE_DIR)
        tree.directories.append(relative)
        with opened(open_child(name, dir_fd)) as child:
            _list(walk, child, f"{relative}/", depth + 1, frozenset())
    else:
        tree.others.append(relative)


_OWNER_READ = 0o400


def _grant(dir_fd: int, name: str, mode: int, needed: int) -> None:
    """補上擁有者缺少的權限位元（呼叫端剛以 lstat 確認類型，不是 symlink）。"""
    current = stat.S_IMODE(mode)
    if current & needed == needed:
        return
    nofollow = os.chmod in os.supports_follow_symlinks
    try:
        os.chmod(name, current | needed, dir_fd=dir_fd, follow_symlinks=not nofollow)
    except OSError as exc:
        raise TreeError(f"無法恢復權限（{reason(exc)}）") from None


def unlink_at(root_fd: int, relative: str) -> None:
    """刪除一個條目（檔案、symlink 本身或特殊檔）；不存在也算成功。"""
    parent, name = open_parent(root_fd, relative)
    with opened(parent):
        try:
            os.unlink(name, dir_fd=parent)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise TreeError(f"無法刪除檔案（{reason(exc)}）") from None


def remove_empty_directories(root_fd: int, directories: list[str]) -> None:
    """由深到淺刪除空的目錄；不是空的就留著（呼叫端另外判斷是否還有檔案）。"""
    for relative in sorted(directories, key=lambda item: item.count("/"), reverse=True):
        parent, name = open_parent(root_fd, relative)
        with opened(parent):
            try:
                os.rmdir(name, dir_fd=parent)
            except FileNotFoundError:
                continue
            except OSError as exc:
                if exc.errno in (errno.ENOTEMPTY, errno.EEXIST):
                    continue
                raise TreeError(f"無法刪除目錄（{reason(exc)}）") from None


def remove_tree(parent_fd: int, name: str, limits: TreeLimits) -> None:
    """刪除 parent 底下的整個目錄（不跟隨 symlink）；不存在也算成功。"""
    try:
        root = os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TreeError(f"無法開啟目錄（{reason(exc)}）") from None
    with opened(root):
        tree = list_tree(root, limits)
        for relative in (*tree.files, *tree.others):
            unlink_at(root, relative)
        remove_empty_directories(root, tree.directories)
    try:
        os.rmdir(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TreeError(f"無法刪除目錄（{reason(exc)}）") from None
    fsync_directory(parent_fd)


def fsync_directory(fd: int) -> None:
    try:
        os.fsync(fd)
    except OSError as exc:
        raise TreeError(f"無法同步目錄（{reason(exc)}）") from None
