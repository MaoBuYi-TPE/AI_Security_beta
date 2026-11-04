"""finding 的業務規則（docs/DECISIONS.md §25.7、§25.9）。

- FindingLinker（worker）：一個 run 的觀察入庫之後，在一個 transaction 中連結到 finding。冪等：
  只處理還沒有連結的觀察；寫入之後、run 結束之前中斷，退回 collected 之後重試只會補上沒連結的。
  鎖序固定（run → finding 依 fingerprint），兩個 run 同時連結也不會死鎖。
- FindingService（API）：先以 scan 的權限檢查（其他 project 的 scan 與不存在的一樣 404），再列出這個
  scan 的 finding。finding 的明細與來源追溯（T20）以 finding 的 target 檢查權限（PROJECT_READ），
  每個請求都重新檢查；as_of 是快照（finding 的連結數），大於目前的連結數時 422。
"""

from http import HTTPStatus
from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from secscan.api_keys.domain import Principal
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.pagination import Page, PageRequest
from secscan.findings.domain.linking import merge, plan_links
from secscan.findings.domain.model import Finding, FindingFilters
from secscan.findings.domain.provenance import (
    FindingDetail,
    FindingHead,
    ScanAppearance,
    Snapshot,
    TracedObservation,
)
from secscan.findings.domain.taxonomy import Taxonomy, load_taxonomy, mapping_identity
from secscan.findings.provenance import ProvenanceRepository
from secscan.findings.records import FindingRecords
from secscan.findings.repository import FindingRepository
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.model import Lease
from secscan.scans.service import ScanService
from secscan.targets.domain import LabNetwork
from secscan.targets.service import TargetService


class FindingLinker:
    def __init__(
        self, sessions: sessionmaker[Session], *, taxonomy: Taxonomy | None = None
    ) -> None:
        # taxonomy 與對應表在建立時載入：檔案被改動時 worker 啟動就失敗，不是每個 run 才失敗。
        self._sessions = sessions
        self._taxonomy = taxonomy if taxonomy is not None else load_taxonomy()
        self._mapping = mapping_identity()

    def link(self, lease: Lease) -> int:
        """連結這個 run 還沒有連結的觀察，回傳連結的數量。lease 失效時拋 LeaseLostError。"""
        with self._sessions.begin() as session:
            records = FindingRecords(session)
            details = records.lock_run(lease)
            observations = records.unlinked(lease)
            if not observations:
                return 0
            # 這個引擎沒有佐證成員（例如 ZAP）：不必查同一次 scan 的錨點觀察。
            anchors = (
                self._taxonomy.anchor_members if self._taxonomy.corroborates(lease.engine) else {}
            )
            context = records.context(lease, details, anchors)
            drafts = plan_links(context, observations, self._taxonomy)
            inserted = records.insert_findings(drafts, lease, self._mapping)
            existing = records.lock_findings(
                context.target_id,
                [draft.fingerprint for draft in drafts if draft.fingerprint not in inserted],
            )
            # 新的 finding 從序號 1 開始；既有的接在鎖住時的連結數之後（§26.4）。
            targets = {fingerprint: (finding_id, 0) for fingerprint, finding_id in inserted.items()}
            for draft in drafts:
                if draft.fingerprint in existing:
                    locked = existing[draft.fingerprint]
                    records.update_finding(
                        locked.id, merge(locked.aggregate, draft), lease, links=len(draft.links)
                    )
                    targets[draft.fingerprint] = (locked.id, locked.linked)
            records.insert_links(drafts, targets, self._mapping[1])
            return len(observations)


class FindingService:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._scans = ScanService(session, lab=lab)
        self._targets = TargetService(session, lab=lab)
        self._findings = FindingRepository(session)
        self._provenance = ProvenanceRepository(session)

    def for_scan(
        self, principal: Principal, scan_id: UUID, filters: FindingFilters, page: PageRequest
    ) -> Page[Finding]:
        self._scans.get(principal, scan_id)
        return self._findings.for_scan(scan_id, filters, page, load_taxonomy().related)

    def detail(self, principal: Principal, finding_id: UUID, as_of: int | None) -> FindingDetail:
        head, snapshot = self._snapshot(principal, finding_id, as_of)
        return FindingDetail(
            finding=head.finding,
            fingerprint=head.fingerprint,
            taxonomy_sha256=head.taxonomy_sha256,
            as_of=snapshot.as_of,
            seen=self._provenance.seen(snapshot),
            engines=self._provenance.engines(snapshot),
            recent_scans=self._provenance.recent_scans(snapshot),
        )

    def scans(
        self, principal: Principal, finding_id: UUID, page: PageRequest, as_of: int | None
    ) -> tuple[Page[ScanAppearance], int]:
        _, snapshot = self._snapshot(principal, finding_id, as_of)
        return self._provenance.scans(snapshot, page), snapshot.as_of

    def observations(
        self,
        principal: Principal,
        finding_id: UUID,
        page: PageRequest,
        *,
        as_of: int | None,
        scan_id: UUID | None,
        engine: Engine | None,
    ) -> tuple[Page[TracedObservation], int]:
        _, snapshot = self._snapshot(principal, finding_id, as_of)
        traced = self._provenance.observations(snapshot, page, scan_id=scan_id, engine=engine)
        return traced, snapshot.as_of

    def _snapshot(
        self, principal: Principal, finding_id: UUID, as_of: int | None
    ) -> tuple[FindingHead, Snapshot]:
        """先取 finding 再以它的 target 檢查權限：其他 project 與不存在的一樣 404（SEC-16）。
        as_of 的檢查在權限之後（不洩漏其他 project 的 finding 是否存在與它的連結數）。
        """
        head = self._provenance.head(finding_id)
        if head is None:
            raise not_found_error()
        self._targets.get(principal, head.finding.target_id)
        linked = head.observations_linked
        if linked < 1:
            # linker 在同一個 transaction 建立 finding 與連結：沒有連結的 finding 不應存在。
            raise not_found_error()
        if as_of is not None and as_of > linked:
            raise AppError(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                code=ErrorCode.INVALID_REQUEST,
                message="as_of 不可大於目前的連結數（以明細或第一頁回傳的值翻頁）。",
            )
        return head, Snapshot(head.finding.id, as_of if as_of is not None else linked)
