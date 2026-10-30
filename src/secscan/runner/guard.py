"""runner 這一側的 guard 通道（docs/DECISIONS.md §15.3）：寫 policy、讀 status，不經網路。

- policy 目錄（guard_policies volume）：runner 讀寫、guard 唯讀。寫入是原子的
  （secscan.guard.files），寫不出去就是 guard 不可用（GuardUnavailableError）。
- status 目錄（guard_status volume）：guard 寫、runner 唯讀。新鮮、版本相符、listen 等於 runner
  設定的 proxy、enforcing 為 true，才算可用。
- telemetry 目錄（guard_telemetry volume，§16.3）：guard 寫、runner 唯讀。runner 讀 summary 得知
  run 是否用盡預算與實際的轉送數；讀不出來或格式不符時拋 GuardUnavailableError。
- 對帳與啟動時的清理（§17.2、§17.4）：讀回留下的 policy 改成 blocked、列出留下 policy 的 run、
  刪除過期的暫存檔。
"""

import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from secscan.guard.domain.policy import (
    MAX_POLICY_BYTES,
    POLICY_SUFFIX,
    Policy,
    PolicyError,
    PolicyState,
    decode_policy,
    encode_policy,
    policy_file_name,
)
from secscan.guard.domain.status import (
    MAX_STATUS_BYTES,
    STATUS_FILE_NAME,
    StatusError,
    StatusIssue,
    decode_status,
    status_issue,
)
from secscan.guard.domain.telemetry import (
    MAX_SUMMARY_BYTES,
    RunSummary,
    TelemetryError,
    decode_summary,
    summary_file_name,
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
        telemetry_dir: Path,
        listen: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._policies = policies_dir
        self._status = status_dir
        self._telemetry = telemetry_dir
        self._listen = listen
        self._clock = clock

    def health(self) -> GuardHealth:
        try:
            raw = _read_small(self._status / STATUS_FILE_NAME, MAX_STATUS_BYTES)
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

    def summary(self, run_id: UUID) -> RunSummary | None:
        """guard 為這個 run 寫的 summary；guard 還沒轉送或拒絕過任何請求時不存在（None）。"""
        try:
            raw = _read_small(self._telemetry / summary_file_name(run_id), MAX_SUMMARY_BYTES)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise GuardUnavailableError(
                f"讀不到 run 的 telemetry（{type(exc).__name__}）"
            ) from None
        try:
            return decode_summary(raw, run_id=run_id)
        except TelemetryError as exc:
            raise GuardUnavailableError(f"run 的 telemetry 格式不符（{exc}）") from None

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

    def block(self, run_id: UUID) -> bool:
        """把留下的 policy 改成 blocked（對帳用；已是 blocked 就不再寫）。不存在回 False。

        讀不出來、不是一般檔案、超過大小或格式不符：拋 GuardUnavailableError，不動那個檔案
        （guard 讀到這種檔案本來就會拒絕；對帳仍會刪除容器，§17.1）。
        """
        try:
            raw = _read_small(self._policies / policy_file_name(run_id), MAX_POLICY_BYTES)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise GuardUnavailableError(f"讀不到 guard 的 policy（{type(exc).__name__}）") from None
        try:
            policy = decode_policy(raw, run_id=run_id)
        except PolicyError as exc:
            raise GuardUnavailableError(f"guard 的 policy 格式不符（{exc}）") from None
        if policy.state is not PolicyState.BLOCKED:
            self.write(policy.blocked())
        return True

    def policy_runs(self) -> frozenset[UUID]:
        """policy 目錄中留下 policy 的 run（檔名是標準格式的 `<run_id>.json`，不是目錄）。"""
        runs = set()
        for entry in self._policies.iterdir():
            stem, suffix = entry.name[: -len(POLICY_SUFFIX)], entry.name[-len(POLICY_SUFFIX) :]
            run_id = _run_id(stem) if suffix == POLICY_SUFFIX else None
            if run_id is not None and not stat.S_ISDIR(entry.lstat().st_mode):
                runs.add(run_id)
        return frozenset(runs)

    def sweep_temporary(self, *, older_than: float) -> int:
        """刪除超過 older_than 秒沒有更新的暫存檔（可能是另一個 runner 正在寫的，所以不全刪）。"""
        removed = 0
        cutoff = self._clock() - older_than
        for entry in self._policies.iterdir():
            info = entry.lstat()
            if (
                entry.name.startswith(TEMP_PREFIX)
                and not stat.S_ISDIR(info.st_mode)
                and info.st_mtime < cutoff
            ):
                entry.unlink()
                removed += 1
        return removed

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


def _run_id(text: str) -> UUID | None:
    try:
        run_id = UUID(text)
    except ValueError:
        return None
    return run_id if str(run_id) == text else None


def _read_small(path: Path, limit: int) -> bytes:
    """讀一個不跟隨 symlink 的一般檔案，最多 limit + 1 bytes（超過的由解析拒絕）。"""
    descriptor = os.open(path, _READ)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("不是一般檔案")
        return os.read(descriptor, limit + 1)
    finally:
        os.close(descriptor)
