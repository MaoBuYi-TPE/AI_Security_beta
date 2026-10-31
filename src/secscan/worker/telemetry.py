"""worker 讀 guard 的 telemetry（docs/DECISIONS.md §16.6）：guard_telemetry volume 唯讀掛載。

每個轉送的請求與上游的回應各一行（guard 寫的 jsonl），嚴格解析，回應依序號配對到請求。讀不到、
格式不符（含最後一行沒有換行、對不到請求或重複的回應）、不是一般檔案或超過上限都回傳 None，原因記在
log（不含路徑）：這個 run 的 coverage 就不算有量測依據。沒有檔案也是 None，由呼叫端依 guard 記下的
轉送數判斷是不是根本沒有流量。
summary（§20.3）以同樣的方式讀：轉送數、各原因的拒絕數、是否用盡預算與時間，寫進 result_details。
"""

import logging
import os
import stat
from pathlib import Path
from uuid import UUID

from secscan.grants.domain.matching import ScopeRules
from secscan.grants.domain.scope import MAX_REQUESTS
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.guard.domain.telemetry import (
    MAX_SUMMARY_BYTES,
    MAX_TELEMETRY_LINE_BYTES,
    ForwardedRequest,
    RunSummary,
    TelemetryError,
    TelemetryRecord,
    UpstreamResponse,
    decode_line,
    decode_summary,
    summary_file_name,
    telemetry_file_name,
)
from secscan.scans.domain.coverage import Exchange
from secscan.worker.evidence import EvidenceState, TelemetryEvidence, verify_telemetry

# 每個轉送的請求最多兩行（請求與回應）。
DEFAULT_MAX_BYTES = MAX_REQUESTS * 2 * MAX_TELEMETRY_LINE_BYTES
_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_CHUNK = 64 * 1024

logger = logging.getLogger(__name__)


class TelemetryReader:
    def __init__(self, directory: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self._directory = directory
        self._max_bytes = max_bytes

    def evidence(
        self,
        run_id: UUID,
        *,
        scan_id: UUID,
        policy_version: GuardPolicyVersion,
        requests_sent: int | None,
        rules: ScopeRules,
    ) -> TelemetryEvidence:
        """只讀一次；parser 和 coverage 共用這份結果，錯誤不能化為可信零流量。"""
        summary = None
        exchanges = None
        read_failure: tuple[EvidenceState, str] | None = None
        try:
            summary_raw = self._optional_read(summary_file_name(run_id), MAX_SUMMARY_BYTES)
            if summary_raw is not None:
                summary = decode_summary(summary_raw, run_id=run_id)
            raw = self._optional_read(telemetry_file_name(run_id), self._max_bytes)
            if raw is not None:
                if raw and not raw.endswith(b"\n"):
                    raise TelemetryError("telemetry 最後一行不完整")
                exchanges = _paired(
                    [decode_line(line) for line in raw.splitlines(keepends=True)],
                    contiguous=policy_version is GuardPolicyVersion.ENCODED_PARAMS,
                )
        except (TelemetryError, RecursionError):
            read_failure = EvidenceState.INCONSISTENT, "telemetry_invalid"
        except (OSError, ValueError):
            read_failure = EvidenceState.MISSING, "telemetry_unreadable"
        # 即使 JSONL 讀取失敗，也先核對已解析的 summary；不能保存別的 scan 的用量。
        result = verify_telemetry(
            run_id=run_id,
            scan_id=scan_id,
            policy_version=policy_version,
            requests_sent=requests_sent,
            rules=rules,
            summary=summary,
            exchanges=exchanges,
        )
        if result.state is not EvidenceState.INCONSISTENT and read_failure is not None:
            result = TelemetryEvidence(read_failure[0], summary, exchanges, read_failure[1])
        if result.problem is not None:
            logger.warning("run %s 的 telemetry 無法驗證（%s）", run_id, result.problem)
        return result

    def _optional_read(self, name: str, maximum: int) -> bytes | None:
        try:
            return self._read(name, maximum)
        except FileNotFoundError:
            return None

    def summary(self, run_id: UUID) -> RunSummary | None:
        """guard 為這個 run 寫的 summary；沒有、讀不到或格式不符是 None。"""
        try:
            raw = self._read(summary_file_name(run_id), MAX_SUMMARY_BYTES)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            logger.warning("run %s 的 summary 讀不到（%s）", run_id, type(exc).__name__)
            return None
        try:
            return decode_summary(raw, run_id=run_id)
        except TelemetryError as exc:
            logger.warning("run %s 的 summary 格式不符（%s）", run_id, type(exc).__name__)
            return None

    def exchanges(self, run_id: UUID) -> tuple[Exchange, ...] | None:
        """轉送的請求（依序）與它們的上游 status（沒有回應是 None）。"""
        try:
            raw = self._read(telemetry_file_name(run_id), self._max_bytes)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            logger.warning("run %s 的 telemetry 讀不到（%s）", run_id, type(exc).__name__)
            return None
        if raw and not raw.endswith(b"\n"):
            logger.warning("run %s 的 telemetry 最後一行不完整", run_id)
            return None
        try:
            records = [decode_line(line) for line in raw.splitlines(keepends=True)]
            return _paired(records, contiguous=False)
        except (TelemetryError, RecursionError) as exc:
            logger.warning("run %s 的 telemetry 格式不符（%s）", run_id, type(exc).__name__)
            return None

    def _read(self, name: str, max_bytes: int) -> bytes:
        descriptor = os.open(self._directory / name, _OPEN)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("不是一般檔案")
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, _CHUNK):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("超過上限")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        return b"".join(chunks)


def _paired(records: list[TelemetryRecord], *, contiguous: bool) -> tuple[Exchange, ...]:
    requests = [record for record in records if isinstance(record, ForwardedRequest)]
    statuses: dict[int, int] = {}
    known = {request.sequence for request in requests}
    sequences = [request.sequence for request in requests]
    if sequences != sorted(known):
        raise TelemetryError("請求序號重複或倒序")
    if contiguous and sequences != list(range(1, len(requests) + 1)):
        raise TelemetryError("實驗版請求序號不完整")
    for record in records:
        if isinstance(record, UpstreamResponse):
            if record.sequence not in known or record.sequence in statuses:
                raise TelemetryError("回應對不到請求，或重複")
            statuses[record.sequence] = record.status
    return tuple(
        Exchange(
            method=request.method,
            path=request.path,
            authenticated=request.authenticated,
            status=statuses.get(request.sequence),
        )
        for request in requests
    )
