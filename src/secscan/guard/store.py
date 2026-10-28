"""guard 讀取 policy 檔（docs/DECISIONS.md §15.3）。

每個請求 stat 一次（不跟隨 symlink），inode、mtime 或 size 變了才重讀；只接受一般檔案，開檔時
O_NOFOLLOW，開檔之後再確認是同一個 inode。解析的結果（含損毀）依 run 快取，數量有上限。
guard 以 asyncio 單執行緒執行，policy 在 tmpfs 上、很小：同步讀取即可。
"""

import os
import stat
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import UUID

from secscan.guard.domain.policy import (
    MAX_POLICY_BYTES,
    CompiledPolicy,
    Policy,
    PolicyError,
    compile_policy,
    decode_policy,
    policy_file_name,
)

DEFAULT_MAX_CACHED = 256
_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class ReplacedError(PolicyError):
    """stat 與開檔之間檔案被換掉（runner 每次寫入都是新的 inode）。"""


class Decode(Protocol):
    def __call__(self, raw: bytes, *, run_id: UUID) -> Policy: ...


@dataclass(frozen=True, slots=True)
class _Entry:
    key: tuple[int, int, int, int]
    result: CompiledPolicy | str  # 字串是損毀的原因


class PolicyStore:
    def __init__(
        self,
        directory: Path,
        *,
        decode: Decode = decode_policy,
        max_cached: int = DEFAULT_MAX_CACHED,
    ) -> None:
        self._directory = directory
        self._decode = decode
        self._max_cached = max_cached
        self._cache: OrderedDict[UUID, _Entry] = OrderedDict()

    @property
    def cached(self) -> int:
        return len(self._cache)

    def load(self, run_id: UUID) -> CompiledPolicy | None:
        """run 的 policy；檔案不存在時 None，損毀或不是一般檔案時拋 PolicyError。"""
        path = self._directory / policy_file_name(run_id)
        try:
            entry = self._lookup(path, run_id)
        except ReplacedError:
            # runner 續約（os.replace）剛好落在 stat 與開檔之間：再讀一次（審查建議）。
            entry = self._lookup(path, run_id)
        if entry is None:
            return None
        if isinstance(entry.result, str):
            raise PolicyError(entry.result)
        return entry.result

    def _lookup(self, path: Path, run_id: UUID) -> _Entry | None:
        try:
            info = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            self._cache.pop(run_id, None)
            return None
        except OSError:
            raise PolicyError("讀不到 policy") from None
        key = _key(info)
        entry = self._cache.get(run_id)
        if entry is None or entry.key != key:
            entry = _Entry(key, self._read(path, run_id, info))
            self._remember(run_id, entry)
        else:
            self._cache.move_to_end(run_id)
        return entry

    def _read(self, path: Path, run_id: UUID, info: os.stat_result) -> CompiledPolicy | str:
        if not stat.S_ISREG(info.st_mode):
            return "policy 必須是一般檔案"
        if info.st_size > MAX_POLICY_BYTES:
            return "policy 超過大小上限"
        try:
            raw = _read_regular(path, info)
        except ReplacedError:
            raise
        except PolicyError as exc:
            return str(exc)
        try:
            return compile_policy(self._decode(raw, run_id=run_id))
        except PolicyError as exc:
            return str(exc)

    def _remember(self, run_id: UUID, entry: _Entry) -> None:
        self._cache[run_id] = entry
        self._cache.move_to_end(run_id)
        while len(self._cache) > self._max_cached:
            self._cache.popitem(last=False)


def _key(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)


def _read_regular(path: Path, expected: os.stat_result) -> bytes:
    try:
        descriptor = os.open(path, _OPEN)
    except OSError:
        raise PolicyError("讀不到 policy") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or _key(info) != _key(expected):
            raise ReplacedError("policy 必須是一般檔案（讀取時被換掉）")
        chunks: list[bytes] = []
        remaining = MAX_POLICY_BYTES + 1
        while remaining > 0 and (chunk := os.read(descriptor, remaining)):
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        raise PolicyError("讀不到 policy") from None
    finally:
        os.close(descriptor)
