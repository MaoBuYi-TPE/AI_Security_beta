"""resolved 之後再次觀察到同一個問題時自動重開（T21；docs/DECISIONS.md §28.3）。

在 FindingLinker 的 transaction 中執行：run 已以 lease 鎖住、既有的 finding 已依 fingerprint 的
順序以 FOR NO KEY UPDATE 鎖住，連結已寫入。四項都成立才重開（domain 的 should_reopen）：
R1 resolved、R2 這次有連結、R3 scan 比 resolve 時看到的都新、R4 run 凍結的 mapping 等於 finding 的。
failed／timed_out run 的陽性觀察也算有效再現（不完整只影響「沒觀察到」的負面結論）。

重開時：finding 版本 +1（trigger 清除 watermark）→ 系統事件（actor 是 system，引用 run 與 scan，
附觀察 id 與連結序號範圍）→ audit `finding.reopen`（actor 為 NULL）。不會自動 resolve 或關閉。
"""

from collections.abc import Mapping, Sequence

from sqlalchemy.orm import Session

from secscan.audit.service import AuditTrail
from secscan.findings.domain.linking import FindingDraft
from secscan.findings.domain.model import LifecycleState
from secscan.findings.domain.triage import (
    REOPEN_OBSERVATIONS_MAX,
    SYSTEM_REOPEN_REASON,
    ActorKind,
    NewTriageEvent,
    ReopenFacts,
    TriageReasonCode,
    TriageStatus,
    should_reopen,
)
from secscan.findings.records import LockedFinding, RunScan
from secscan.findings.triage_records import TriageRecords
from secscan.scans.domain.model import Lease


class AutoReopener:
    def __init__(self, session: Session) -> None:
        self._records = TriageRecords(session)
        self._audit = AuditTrail(session)

    def reopen(
        self,
        lease: Lease,
        scan: RunScan,
        mapping: tuple[str, str],
        drafts: Sequence[FindingDraft],
        locked: Mapping[str, LockedFinding],
    ) -> int:
        """依 draft 的順序（fingerprint 排序）檢查已鎖住的 finding；回傳重開的數量。"""
        reopened = 0
        for draft in drafts:
            item = locked.get(draft.fingerprint)
            if item is None:
                continue
            facts = ReopenFacts(
                lifecycle=item.status.lifecycle,
                resolved_scan_position=item.resolved_scan_position,
                run_scan_position=scan.queue_position,
                run_mapping=mapping,
                finding_mapping=item.mapping,
                new_links=len(draft.links),
            )
            if should_reopen(facts):
                self._reopen(lease, scan, draft, item)
                reopened += 1
        return reopened

    def _reopen(
        self, lease: Lease, scan: RunScan, draft: FindingDraft, item: LockedFinding
    ) -> None:
        previous = item.status
        planned = TriageStatus(previous.triage, LifecycleState.REOPENED, previous.version + 1)
        links = {"first": item.linked + 1, "last": item.linked + len(draft.links)}
        observation_ids = [
            str(link.observation_id) for link in draft.links[:REOPEN_OBSERVATIONS_MAX]
        ]
        self._records.apply(item.id, planned)
        self._records.append(
            NewTriageEvent(
                finding_id=item.id,
                target_id=draft.inputs.target_id,
                sequence=planned.version,
                actor_kind=ActorKind.SYSTEM,
                actor_key_id=None,
                request_id=None,
                previous=previous,
                current=planned,
                reason_code=TriageReasonCode.AUTO_REOPEN,
                reason=SYSTEM_REOPEN_REASON,
                evidence={"observation_ids": list(observation_ids), "links": dict(links)},
                run_id=lease.run_id,
                scan_id=lease.scan_id,
            )
        )
        self._audit.record(
            action="finding.reopen",
            object_type="finding",
            object_id=item.id,
            actor_key_id=None,
            project_id=scan.project_id,
            request_id=None,
            changes={
                "version": planned.version,
                "lifecycle": {"from": previous.lifecycle.value, "to": planned.lifecycle.value},
                "run_id": str(lease.run_id),
                "scan_id": str(lease.scan_id),
                "links": dict(links),
            },
        )
