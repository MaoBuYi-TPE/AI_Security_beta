"""run 的用量、preflight 的結果與 coverage（docs/DECISIONS.md §16.4 至 §16.6）。

runner 與 worker 在 run 結束之前（終止的 run 不能再改）以持有的 lease 寫入；寫入都經 fencing，
lease 失效時拋 LeaseLostError。剩下的預算在 prepare 時由之前的 run 的用量算出。
在呼叫端的 transaction 中執行（ScanQueue 每個操作一個短 transaction）。
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from uuid import UUID

from sqlalchemy import ColumnElement, func, insert, select, update
from sqlalchemy.orm import Session

from secscan.auth_profiles.domain.preflight import Preflight
from secscan.auth_profiles.repository import AuthProfileRepository
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.coverage import FrozenOperation
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.model import EventType, Lease
from secscan.scans.domain.preflight import PreflightResult
from secscan.scans.leases import LeaseLostError, holds
from secscan.scans.models import (
    RunCoverageModel,
    ScanEventModel,
    ScanModel,
    ScannerRunModel,
    ScanOperationModel,
)
from secscan.scans.progress import now
from secscan.specs.repository import ApiSpecRepository


@dataclass(frozen=True, slots=True)
class RunUsage:
    """run 用掉的預算：guard 的 telemetry 記下的轉送與拒絕數，以及容器啟動到停止的秒數。
    轉送數不明（telemetry 遺失）時是 None：之後的 run 以分到的數量扣除。
    """

    requests_sent: int | None
    requests_denied: int | None
    traffic_seconds: int


@dataclass(frozen=True, slots=True)
class SpecInputs:
    """交給工具的規格的原料（docs/DECISIONS.md §18.6）：上傳時正規化的文件、base path，以及 scan
    建立時凍結為 eligible 的 (method, 含 base path 的 path)。過濾由 runner 在 transaction 之外進行。
    """

    document: bytes = field(repr=False)
    base_path: str
    eligible: frozenset[tuple[str, str]]


@dataclass(frozen=True, slots=True)
class CoverageInputs:
    """worker 對應 coverage 需要的：guard 記下的轉送數（None 是不明或沒有容器）與範圍內的
    operation。
    """

    requests_sent: int | None
    operations: tuple[FrozenOperation, ...]
    # 已經記錄過（worker 在轉成 succeeded 之前中斷、退回 collected 之後重試）。
    recorded: bool = False


class RunRecords:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._profiles = AuthProfileRepository(session)

    # --- 預算 ---------------------------------------------------------------------------------

    def remaining(
        self, scan_id: UUID, run_id: UUID, *, max_requests: int, max_duration_seconds: int
    ) -> tuple[int, int]:
        """scan 的上限減去同一個 scan 之前的容器 run 用掉的（請求數、秒數）。

        轉送數不明的 run 以分到的數量計算（保守）；秒數不明的以開始到結束（或現在）的時間計算。
        """
        elapsed = func.ceil(
            func.extract(
                "epoch",
                func.coalesce(ScannerRunModel.finished_at, func.clock_timestamp())
                - ScannerRunModel.started_at,
            )
        )
        sent = func.coalesce(ScannerRunModel.requests_sent, ScannerRunModel.requests_allotted)
        seconds = func.coalesce(ScannerRunModel.traffic_seconds, elapsed)
        used_requests, used_seconds = self._session.execute(
            select(func.coalesce(func.sum(sent), 0), func.coalesce(func.sum(seconds), 0)).where(
                ScannerRunModel.scan_id == scan_id,
                ScannerRunModel.id != run_id,
                ScannerRunModel.container_name.is_not(None),
            )
        ).one()
        return (
            max(0, max_requests - int(used_requests)),
            max(0, max_duration_seconds - int(used_seconds)),
        )

    def allot(self, run_id: UUID, requests: int) -> None:
        """容器版的 run 開始時分到的請求數（in-process 的 fake 不送流量、不佔預算）。"""
        self._session.execute(
            update(ScannerRunModel)
            .where(ScannerRunModel.id == run_id)
            .values(requests_allotted=requests)
            .execution_options(synchronize_session=False)
        )

    def record_usage(
        self, lease: Lease, usage: RunUsage, *, container_removed: bool = False
    ) -> None:
        """container_removed：runner 已確認容器刪除，一併記下時間（已記下的不覆寫；§17.2）。"""
        values: dict[str, object] = {
            "requests_sent": usage.requests_sent,
            "requests_denied": usage.requests_denied,
            "traffic_seconds": usage.traffic_seconds,
        }
        if container_removed:
            values["container_removed_at"] = func.coalesce(
                ScannerRunModel.container_removed_at, now()
            )
        self._fenced_update(lease, values, problem="lease 已過期或不屬於這個 runner")

    # --- 解析 ---------------------------------------------------------------------------------

    def parse_attempts(self, run_id: UUID, scan_id: UUID) -> int:
        """這個 run 轉到 normalizing 的次數（事件不可修改，計數不會被改小；§17.6）。"""
        count = self._session.scalar(
            select(func.count())
            .select_from(ScanEventModel)
            .where(
                ScanEventModel.scan_id == scan_id,
                ScanEventModel.scanner_run_id == run_id,
                ScanEventModel.event_type == EventType.RUN_STATUS.value,
                ScanEventModel.payload["status"].astext == RunStatus.NORMALIZING.value,
            )
        )
        return int(count or 0)

    # --- preflight ----------------------------------------------------------------------------

    def preflight(self, profile_id: UUID | None, version: int | None) -> Preflight | None:
        if profile_id is None or version is None:
            return None
        return self._profiles.preflight(profile_id, version=version)

    def bound_preflight(self, lease: Lease) -> Preflight | None:
        """scan 綁定的 auth profile 版本的 preflight 定義；沒有綁定時是 None。"""
        row = self._session.execute(
            select(ScanModel.auth_profile_id, ScanModel.auth_profile_version).where(
                ScanModel.id == lease.scan_id
            )
        ).first()
        return None if row is None else self.preflight(*row)

    def record_preflight(self, lease: Lease, result: PreflightResult) -> None:
        self._fenced_update(
            lease,
            {"preflight_result": result.value},
            ScannerRunModel.engine == Engine.PREFLIGHT.value,
            problem="lease 已過期、不屬於這個 worker，或不是 preflight 的 run",
        )

    # --- coverage -----------------------------------------------------------------------------

    def spec_inputs(self, scan_id: UUID, spec_id: UUID) -> SpecInputs | None:
        """文件與 operation 都不可變（trigger）：不另外加鎖。規格不見了（不應發生）是 None。"""
        stored = ApiSpecRepository(self._session).stored_document(spec_id)
        if stored is None:
            return None
        rows = self._session.execute(
            select(ScanOperationModel.method, ScanOperationModel.path).where(
                ScanOperationModel.scan_id == scan_id,
                ScanOperationModel.ineligible_reason.is_(None),
            )
        )
        document, base_path = stored
        return SpecInputs(
            document=document,
            base_path=base_path,
            eligible=frozenset((row.method, row.path) for row in rows),
        )

    def coverage_inputs(self, lease: Lease) -> CoverageInputs:
        sent, recorded = self._session.execute(
            select(ScannerRunModel.requests_sent, ScannerRunModel.coverage_recorded).where(
                ScannerRunModel.id == lease.run_id
            )
        ).one()
        rows = self._session.execute(
            select(ScanOperationModel.ordinal, ScanOperationModel.method, ScanOperationModel.path)
            .where(
                ScanOperationModel.scan_id == lease.scan_id,
                ScanOperationModel.ineligible_reason.is_(None),
            )
            .order_by(ScanOperationModel.ordinal)
        )
        return CoverageInputs(
            requests_sent=sent,
            operations=tuple(FrozenOperation(row.ordinal, row.method, row.path) for row in rows),
            recorded=recorded,
        )

    def record_coverage(self, lease: Lease, observed: Mapping[int, bool]) -> None:
        """寫入這個 run 涵蓋的 operation，並標記已量測（只能一次）。"""
        self._fenced_update(
            lease,
            {"coverage_recorded": True},
            ScannerRunModel.coverage_recorded.is_(False),
            problem="lease 已過期、不屬於這個 worker，或已經記錄過 coverage",
        )
        if observed:
            self._session.execute(
                insert(RunCoverageModel),
                [
                    {
                        "scanner_run_id": lease.run_id,
                        "scan_id": lease.scan_id,
                        "ordinal": ordinal,
                        "authenticated": authenticated,
                    }
                    for ordinal, authenticated in sorted(observed.items())
                ],
            )

    def _fenced_update(
        self,
        lease: Lease,
        values: Mapping[str, object],
        *conditions: ColumnElement[bool],
        problem: str,
    ) -> None:
        updated = self._session.execute(
            update(ScannerRunModel)
            .where(*holds(lease), *conditions)
            .values(**values)
            .returning(ScannerRunModel.id)
            .execution_options(synchronize_session=False)
        ).scalar()
        if updated is None:
            raise LeaseLostError(problem)
