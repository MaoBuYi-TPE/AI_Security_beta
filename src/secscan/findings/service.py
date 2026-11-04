"""finding 的業務規則（docs/DECISIONS.md §25.7、§25.9）。

- FindingLinker（worker）：一個 run 的觀察入庫之後，在一個 transaction 中連結到 finding。冪等：
  只處理還沒有連結的觀察；寫入之後、run 結束之前中斷，退回 collected 之後重試只會補上沒連結的。
  鎖序固定（run → finding 依 fingerprint），兩個 run 同時連結也不會死鎖。
- FindingService（API）：先以 scan 的權限檢查（其他 project 的 scan 與不存在的一樣 404），再列出這個
  scan 的 finding。
"""

from uuid import UUID

from sqlalchemy.orm import Session, sessionmaker

from secscan.api_keys.domain import Principal
from secscan.core.pagination import Page, PageRequest
from secscan.findings.domain.linking import merge, plan_links
from secscan.findings.domain.model import Finding, FindingFilters
from secscan.findings.domain.taxonomy import Taxonomy, load_taxonomy, mapping_identity
from secscan.findings.records import FindingRecords
from secscan.findings.repository import FindingRepository
from secscan.scans.domain.model import Lease
from secscan.scans.service import ScanService
from secscan.targets.domain import LabNetwork


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
            finding_ids = records.insert_findings(drafts, lease, self._mapping)
            existing = records.lock_findings(
                context.target_id,
                [draft.fingerprint for draft in drafts if draft.fingerprint not in finding_ids],
            )
            for draft in drafts:
                if draft.fingerprint in existing:
                    finding_id, aggregate = existing[draft.fingerprint]
                    records.update_finding(finding_id, merge(aggregate, draft), lease)
                    finding_ids[draft.fingerprint] = finding_id
            records.insert_links(drafts, finding_ids, self._mapping[1])
            return len(observations)


class FindingService:
    def __init__(self, session: Session, *, lab: LabNetwork) -> None:
        self._scans = ScanService(session, lab=lab)
        self._findings = FindingRepository(session)

    def for_scan(
        self, principal: Principal, scan_id: UUID, filters: FindingFilters, page: PageRequest
    ) -> Page[Finding]:
        self._scans.get(principal, scan_id)
        return self._findings.for_scan(scan_id, filters, page, load_taxonomy().related)
