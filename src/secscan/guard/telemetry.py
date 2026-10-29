"""guard 的 telemetry 記錄與預算的計數（docs/DECISIONS.md §16）。

- 放行之前先保留名額（reserve），轉送時才確定（forwarded）；被拒絕就釋放（release）。
- 轉送時先原子寫入 summary，再附加一行：中途失敗時磁碟上最多多算一個（對預算是保守的方向），
  記憶體中的名額釋放、例外交給 addon 拒絕這個請求（沒有紀錄的流量不放行）。
- 拒絕只計數，由定期的 flush 寫進 summary（最多落後一個 flush 的間隔）。
- guard 重啟時由既有的 summary 接續計數：重啟不會讓 run 重新拿到整份預算。summary 讀不出來或
  屬於別的 scan 時 fail closed（拋出例外，addon 拒絕）。
- prune 刪掉超過保留期限的檔案，以及沒有保留中名額、已經閒置的計數。

guard 以 asyncio 單執行緒執行，這裡的方法之間沒有 await：計數與寫入不會交錯。
"""

import os
import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

from secscan.guard.domain.budget import RunLedger
from secscan.guard.domain.policy import Policy
from secscan.guard.domain.requests import Reason
from secscan.guard.domain.telemetry import (
    ForwardedRequest,
    RunSummary,
    TelemetryError,
    UpstreamResponse,
    decode_summary,
    encode_line,
    encode_summary,
    summary_file_name,
    telemetry_file_name,
)
from secscan.guard.files import AtomicWriteError, reason, remove_file, write_atomic

TELEMETRY_RETENTION_SECONDS = 6 * 3600
_APPEND = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_LINES_MODE = 0o600
_FILE_NAME = re.compile(
    r"(?P<run>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"(?:\.jsonl|\.summary\.json)"
)


class TelemetryWriteError(Exception):
    """telemetry 寫不出來或讀不回來。訊息不含路徑或內容。"""


@dataclass(slots=True)
class _RunRecord:
    """一個 run 在記憶體中的計數（guard 內部、單執行緒；不對外）。"""

    scan_id: UUID
    ledger: RunLedger
    maximum: int
    touched: float
    denied: Counter[str] = field(default_factory=Counter)
    first_at: float | None = None
    last_at: float | None = None
    dirty: bool = False


class TelemetryRecorder:
    def __init__(
        self, directory: Path, *, boot_id: UUID, clock: Callable[[], float] = time.time
    ) -> None:
        self._directory = directory
        self._boot_id = boot_id
        self._clock = clock
        self._runs: dict[UUID, _RunRecord] = {}

    @property
    def runs(self) -> int:
        return len(self._runs)

    def reserve(self, policy: Policy) -> bool:
        """保留一個名額；已經用到上限時回 False（並讓 summary 反映 exhausted）。"""
        record = self._record(policy)
        if not record.ledger.reserve(maximum=record.maximum):
            record.dirty = True
            return False
        return True

    def pending(self, policy: Policy) -> int:
        """保留中、還沒轉送的名額數（第一次看到這個 run 時同 reserve 由 summary 接續）。"""
        return self._record(policy).ledger.pending

    def release(self, run_id: UUID) -> None:
        self._runs[run_id].ledger.release()

    def forwarded(
        self, run_id: UUID, *, method: str, path: str, authenticated: bool, at: float
    ) -> int:
        """確定轉送：寫入 summary 與一行，回傳這個請求的序號。失敗時釋放名額並拋出例外。"""
        record = self._runs[run_id]
        sequence = record.ledger.forwarded + 1
        try:
            line = encode_line(
                ForwardedRequest(
                    sequence=sequence,
                    at=at,
                    method=method,
                    path=path,
                    authenticated=authenticated,
                )
            )
        except TelemetryError:
            record.ledger.release()
            raise TelemetryWriteError("轉送的請求無法記錄") from None
        record.ledger.commit()
        first_at, last_at = record.first_at, record.last_at
        record.first_at = at if first_at is None else first_at
        record.last_at = at
        try:
            self._write_summary(run_id, record)
            self._append(run_id, line)
        except TelemetryWriteError:
            self._uncommit(record, first_at, last_at)
            raise
        return sequence

    def response(self, run_id: UUID, *, sequence: int, status: int, at: float) -> None:
        if run_id not in self._runs:
            raise TelemetryWriteError("不明的 run")
        try:
            line = encode_line(UpstreamResponse(sequence=sequence, at=at, status=status))
        except TelemetryError:
            raise TelemetryWriteError("回應無法記錄") from None
        self._append(run_id, line)

    def denied(self, policy: Policy, reason: Reason) -> None:
        record = self._record(policy)
        record.denied[reason.value] += 1
        record.dirty = True

    def flush(self) -> None:
        """把拒絕的計數寫進 summary；全部都試過之後才回報失敗。"""
        failed = 0
        for run_id, record in self._runs.items():
            if not record.dirty:
                continue
            try:
                self._write_summary(run_id, record)
            except TelemetryWriteError:
                failed += 1
        if failed:
            raise TelemetryWriteError(f"{failed} 個 summary 寫不出來")

    def prune(self, *, max_age: float = TELEMETRY_RETENTION_SECONDS) -> int:
        """刪掉超過 max_age 沒有更新的檔案；回傳刪掉的檔案數。其他名稱的檔案不動。"""
        cutoff = self._clock() - max_age
        for run_id in [
            run_id
            for run_id, record in self._runs.items()
            if record.ledger.pending == 0 and record.touched < cutoff
        ]:
            del self._runs[run_id]
        try:
            entries = list(os.scandir(self._directory))
        except OSError as exc:
            raise TelemetryWriteError(f"無法列出目錄（{reason(exc)}）") from None
        removed = failed = 0
        for entry in entries:
            match = _FILE_NAME.fullmatch(entry.name)
            if match is None or UUID(match["run"]) in self._runs or _modified(entry) >= cutoff:
                continue
            try:
                remove_file(self._directory, entry.name)
            except AtomicWriteError:
                failed += 1
            else:
                removed += 1
        if failed:
            raise TelemetryWriteError(f"{failed} 個過期的檔案刪不掉")
        return removed

    # --- 內部 ---------------------------------------------------------------------------------

    def _record(self, policy: Policy) -> _RunRecord:
        record = self._runs.get(policy.run_id)
        if record is None:
            record = self._resume(policy)
            self._runs[policy.run_id] = record
        elif record.scan_id != policy.scan_id:
            raise TelemetryWriteError("run 的 scan 與之前不同")
        record.maximum = policy.budget.max_requests
        record.touched = self._clock()
        return record

    def _resume(self, policy: Policy) -> _RunRecord:
        maximum = policy.budget.max_requests
        try:
            raw = (self._directory / summary_file_name(policy.run_id)).read_bytes()
        except FileNotFoundError:
            return _RunRecord(policy.scan_id, RunLedger(), maximum, self._clock())
        except OSError as exc:
            raise TelemetryWriteError(f"summary 讀不出來（{reason(exc)}）") from None
        try:
            summary = decode_summary(raw, run_id=policy.run_id)
        except TelemetryError:
            raise TelemetryWriteError("summary 損毀") from None
        if summary.scan_id != policy.scan_id:
            raise TelemetryWriteError("summary 屬於別的 scan")
        return _RunRecord(
            scan_id=summary.scan_id,
            ledger=RunLedger(forwarded=summary.forwarded),
            maximum=maximum,
            touched=self._clock(),
            denied=Counter(summary.denied),
            first_at=summary.first_at,
            last_at=summary.last_at,
        )

    def _uncommit(self, record: _RunRecord, first_at: float | None, last_at: float | None) -> None:
        """summary 或那一行沒寫成：記憶體回到轉送之前（磁碟上的 summary 最多多算一個）。"""
        record.ledger.uncommit()
        record.first_at, record.last_at = first_at, last_at
        record.dirty = True

    def _write_summary(self, run_id: UUID, record: _RunRecord) -> None:
        summary = RunSummary(
            run_id=run_id,
            scan_id=record.scan_id,
            boot_id=self._boot_id,
            forwarded=record.ledger.forwarded,
            denied=dict(record.denied),
            exhausted=record.ledger.exhausted(maximum=record.maximum),
            first_at=record.first_at,
            last_at=record.last_at,
        )
        try:
            write_atomic(self._directory, summary_file_name(run_id), encode_summary(summary))
        except AtomicWriteError as exc:
            raise TelemetryWriteError(f"summary 寫不出來：{exc}") from None
        record.dirty = False

    def _append(self, run_id: UUID, line: bytes) -> None:
        try:
            descriptor = os.open(
                self._directory / telemetry_file_name(run_id), _APPEND, _LINES_MODE
            )
        except OSError as exc:
            raise TelemetryWriteError(f"telemetry 寫不出來（{reason(exc)}）") from None
        try:
            view = memoryview(line)
            while view:
                view = view[os.write(descriptor, view) :]
        except OSError as exc:
            raise TelemetryWriteError(f"telemetry 寫不出來（{reason(exc)}）") from None
        finally:
            os.close(descriptor)


def _modified(entry: os.DirEntry[str]) -> float:
    try:
        return entry.stat(follow_symlinks=False).st_mtime
    except OSError:
        return float("inf")
