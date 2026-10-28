"""runner 這一側的 guard 通道（docs/DECISIONS.md §15.3）：寫 policy、讀 status，不經網路。

- policy 目錄（guard_policies volume）：runner 讀寫、guard 唯讀。寫入是原子的
  （secscan.guard.files），寫不出去就是 guard 不可用（GuardUnavailableError）。
- status 目錄（guard_status volume）：guard 寫、runner 唯讀。新鮮、版本相符、listen 等於 runner
  設定的 proxy、enforcing 為 true，才算可用。
"""

import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from secscan.guard.domain.policy import POLICY_SUFFIX, Policy, encode_policy, policy_file_name
from secscan.guard.domain.status import (
    MAX_STATUS_BYTES,
    STATUS_FILE_NAME,
    StatusError,
    StatusIssue,
    decode_status,
    status_issue,
)
from secscan.guard.files import TEMP_PREFIX, AtomicWriteError, remove_file, write_atomic

_PROBE_PREFIX = ".probe-"
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class GuardUnavailableError(Exception):
    """policy 寫不出去或刪不掉：不能保證流量受控。訊息不含路徑。"""


@dataclass(frozen=True, slots=True)
class GuardHealth:
    boot_id: UUID | None
    issue: StatusIssue | None

    @property
    def available(self) -> bool:
        return self.issue is None


class GuardChannel:
    def __init__(
        self,
        policies_dir: Path,
        status_dir: Path,
        *,
        listen: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._policies = policies_dir
        self._status = status_dir
        self._listen = listen
        self._clock = clock

    def health(self) -> GuardHealth:
        try:
            raw = _read_small(self._status / STATUS_FILE_NAME)
        except FileNotFoundError:
            return GuardHealth(boot_id=None, issue=StatusIssue.MISSING)
        except OSError:
            return GuardHealth(boot_id=None, issue=StatusIssue.INVALID)
        try:
            status = decode_status(raw)
        except StatusError:
            return GuardHealth(boot_id=None, issue=StatusIssue.INVALID)
        issue = status_issue(status, now=self._clock(), listen=self._listen)
        return GuardHealth(boot_id=status.boot_id, issue=issue)

    def writable(self) -> bool:
        """policy 目錄能建立與刪除檔案（權限錯了要在認領之前發現）。"""
        probe = self._policies / f"{_PROBE_PREFIX}{uuid4().hex}"
        try:
            os.close(os.open(probe, _NEW_FILE, 0o400))
            probe.unlink()
        except OSError:
            return False
        return True

    def write(self, policy: Policy) -> None:
        try:
            write_atomic(self._policies, policy_file_name(policy.run_id), encode_policy(policy))
        except AtomicWriteError as exc:
            raise GuardUnavailableError(f"無法寫入 guard 的 policy（{exc}）") from None

    def remove(self, run_id: UUID) -> None:
        try:
            remove_file(self._policies, policy_file_name(run_id))
        except AtomicWriteError as exc:
            raise GuardUnavailableError(f"無法刪除 guard 的 policy（{exc}）") from None

    def sweep(self) -> int:
        """刪除上一個 runner 留下的 policy 與暫存檔（呼叫端先確認沒有其他存活的 runner）。"""
        removed = 0
        for entry in self._policies.iterdir():
            info = entry.lstat()
            leftover = entry.name.endswith(POLICY_SUFFIX) or entry.name.startswith(TEMP_PREFIX)
            if leftover and not stat.S_ISDIR(info.st_mode):
                entry.unlink()
                removed += 1
        return removed


def _read_small(path: Path) -> bytes:
    descriptor = os.open(path, _READ)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("status 不是一般檔案")
        return os.read(descriptor, MAX_STATUS_BYTES + 1)
    finally:
        os.close(descriptor)
