"""runner 與 guard 交換的檔案（policy、status）的原子寫入與刪除（docs/DECISIONS.md §15.3）。

以目錄的 fd 操作（目錄本身不可是 symlink），暫存檔以 O_EXCL|O_NOFOLLOW 建立、0400、寫完 fsync，
再以 os.replace 換上：讀的一方只會看到完整的舊檔或新檔，每次寫入都是新的 inode。
錯誤一律轉成 AtomicWriteError，訊息只有錯誤的種類（OSError 的訊息含路徑）。
"""

import errno
import os
from pathlib import Path
from uuid import uuid4

_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_READ_ONLY = 0o400
TEMP_PREFIX = ".tmp-"


class AtomicWriteError(Exception):
    """寫入或刪除失敗。訊息不含路徑或內容。"""


def write_atomic(directory: Path, name: str, content: bytes) -> None:
    _check_name(name)
    directory_fd = _open_directory(directory)
    temp = f"{TEMP_PREFIX}{uuid4().hex}"
    try:
        _write_new(directory_fd, temp, content)
        os.replace(temp, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        _discard(directory_fd, temp)
        raise AtomicWriteError(f"無法寫入（{reason(exc)}）") from None
    finally:
        os.close(directory_fd)


def remove_file(directory: Path, name: str) -> None:
    """刪除檔案；不存在也算成功。"""
    _check_name(name)
    directory_fd = _open_directory(directory)
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AtomicWriteError(f"無法刪除（{reason(exc)}）") from None
    finally:
        os.close(directory_fd)


def reason(exc: OSError) -> str:
    """只回報錯誤的種類（例如 EACCES、ENOSPC）。"""
    return errno.errorcode.get(exc.errno or 0, type(exc).__name__)


def _check_name(name: str) -> None:
    if not name or name.startswith(".") or "/" in name or "\x00" in name:
        raise AtomicWriteError("檔名只能是目錄中的一般名稱")


def _open_directory(directory: Path) -> int:
    try:
        return os.open(directory, _DIRECTORY)
    except OSError as exc:
        raise AtomicWriteError(f"無法開啟目錄（{reason(exc)}）") from None


def _write_new(directory_fd: int, name: str, content: bytes) -> None:
    descriptor = os.open(name, _NEW_FILE, _READ_ONLY, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, _READ_ONLY)
        view = memoryview(content)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _discard(directory_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory_fd)
    except OSError:
        return
