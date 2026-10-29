"""worker 讀 runner 收集好的輸出（docs/DECISIONS.md §14.5、§16.5）：runs volume 唯讀掛載。

- 只讀 manifest.json 列出的檔案，大小與 sha256 必須相符（runner 在容器刪除之後收集，之後不再改）。
- 以 dir fd 加 O_NOFOLLOW 開啟，只接受一般檔案：工具建立的 symlink 不會被跟隨。
- 讀不到、不符或超過上限都回傳 None（呼叫端當成沒有輸出），原因記在 log（不含路徑）。
輸出一律是不可信的資料：這裡只負責取得 bytes，解析在各引擎的 parser。
"""

import hashlib
import json
import logging
import os
import stat
from pathlib import Path
from uuid import UUID

MANIFEST_FILE = "manifest.json"
OUTPUT_DIR = "out"
MAX_MANIFEST_BYTES = 1024 * 1024
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK

logger = logging.getLogger(__name__)


class _UnusableError(Exception):
    """輸出不能用（訊息只有原因）。"""


class ArtifactReader:
    def __init__(self, runs_dir: Path) -> None:
        self._runs = runs_dir

    def read(self, run_id: UUID, name: str, *, max_bytes: int) -> bytes | None:
        if not name or name in {".", ".."} or "/" in name or "\x00" in name:
            raise ValueError("檔名只能是 out/ 中的一般名稱")
        try:
            run_fd = os.open(self._runs / str(run_id), _DIRECTORY)
        except OSError as exc:
            logger.warning("run %s 的工作目錄讀不到（%s）", run_id, type(exc).__name__)
            return None
        try:
            return self._read(run_fd, name, max_bytes)
        except (_UnusableError, OSError) as exc:
            logger.warning("run %s 的輸出 %s 不能用（%s）", run_id, name, _reason(exc))
            return None
        finally:
            os.close(run_fd)

    def _read(self, run_fd: int, name: str, max_bytes: int) -> bytes | None:
        entry = _listed(_read_file(run_fd, MANIFEST_FILE, MAX_MANIFEST_BYTES), name)
        if entry is None:
            return None
        size, digest = entry
        if size > max_bytes:
            raise _UnusableError("超過上限")
        out_fd = os.open(OUTPUT_DIR, _DIRECTORY, dir_fd=run_fd)
        try:
            content = _read_file(out_fd, name, size)
        finally:
            os.close(out_fd)
        if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
            raise _UnusableError("和 manifest 不符")
        return content


def _listed(raw: bytes, name: str) -> tuple[int, str] | None:
    """manifest 中這個檔案的大小與 sha256；沒有列出時回 None。"""
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise _UnusableError("manifest 不是 JSON") from None
    files = document.get("files") if isinstance(document, dict) else None
    if not isinstance(files, list):
        raise _UnusableError("manifest 格式不符")
    for item in files:
        if not isinstance(item, dict) or item.get("path") != name:
            continue
        size, digest = item.get("size"), item.get("sha256")
        if type(size) is not int or size < 0 or not isinstance(digest, str):
            raise _UnusableError("manifest 格式不符")
        return size, digest
    return None


def _read_file(directory_fd: int, name: str, limit: int) -> bytes:
    descriptor = os.open(name, _FILE, dir_fd=directory_fd)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _UnusableError("不是一般檔案")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining > 0 and (chunk := os.read(descriptor, min(remaining, 64 * 1024))):
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
    finally:
        os.close(descriptor)
    if len(content) > limit:
        raise _UnusableError("超過上限")
    return content


def _reason(exc: Exception) -> str:
    return str(exc) if isinstance(exc, _UnusableError) else type(exc).__name__
