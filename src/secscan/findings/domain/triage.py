"""人工 triage 與生命週期的轉換規則（T21；docs/DECISIONS.md §28）。純函式，不依賴 DB。

- resolved 一律是人工判定：只有人工的 PATCH 能轉成 resolved（還要通過 triage 模組的證據門檻）；
  系統只會做一件事：resolved 之後又觀察到同一個問題時自動重開（R1 至 R4）。
- 一次只改一個欄位：確認（triage）與修補（lifecycle）分兩次送出，各留一筆事件。
- reopened 保留「曾經修補過」的歷史：任何狀態都不能回到 open。
- DB 的 findings_guard 以同樣的規則再檢查一次（migration v0017）。
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from secscan.core.json_types import JsonObject
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.security.blob_cipher import max_sealed_blob_bytes

# 人工理由的長度上限（DB 的 CHECK 相同）。
REASON_MAX_LENGTH = 2000
# 事件的 evidence（JSONB）與人工複測摘錄的大小上限（DB 的 CHECK 相同）。
EVIDENCE_MAX_BYTES = 32768
REQUEST_EXCERPT_MAX_BYTES = 4096
RESPONSE_EXCERPT_MAX_BYTES = 8192
# 系統重開事件附上的觀察 id 數量上限。
REOPEN_OBSERVATIONS_MAX = 20
SYSTEM_REOPEN_REASON = (
    "resolve 之後，較新的 scan 以相同的 fingerprint 與 mapping 再次觀察到這個問題"
)


class ResolutionBasis(StrEnum):
    """resolved 的依據（使用者 2026-11-07 的雙軌）；由人選擇，平台只檢查條件是否成立。"""

    RESCAN_NOT_OBSERVED = "rescan_not_observed"
    MANUAL_RETEST = "manual_retest"


class EvidenceProvenance(StrEnum):
    """證據由誰產生：平台的比較快照，或操作者提交的聲明（平台只做一致性檢查）。"""

    PLATFORM_COMPARISON = "platform_comparison"
    OPERATOR_SUPPLIED = "operator_supplied"


PROVENANCE_OF_BASIS = {
    ResolutionBasis.RESCAN_NOT_OBSERVED: EvidenceProvenance.PLATFORM_COMPARISON,
    ResolutionBasis.MANUAL_RETEST: EvidenceProvenance.OPERATOR_SUPPLIED,
}
# API 與報告的固定說明：resolved 一律是人工判定，平台不驗證修補（docs/DECISIONS.md §28.1）。
RESOLUTION_NOTICES = {
    ResolutionBasis.RESCAN_NOT_OBSERVED: (
        "人工判定：依據是平台複掃未觀察到（三層覆蓋皆成立）；未觀察到不等於已修補，"
        "平台不提供自動修補驗證。"
    ),
    ResolutionBasis.MANUAL_RETEST: (
        "人工判定：依據是操作者提供的人工複測證據，平台只做一致性檢查，未驗證其真實性；"
        "平台不提供自動修補驗證。"
    ),
}


class ActorKind(StrEnum):
    KEY = "key"
    SYSTEM = "system"


class TriageReasonCode(StrEnum):
    MANUAL = "manual"
    AUTO_REOPEN = "auto_reopen_new_observation"


class TransitionProblem(StrEnum):
    """人工轉換不成立的原因：前兩項是請求本身的問題（422），其餘是狀態衝突（409）。"""

    NO_CHANGE = "no_change"
    MULTIPLE_CHANGES = "multiple_changes"
    TRIAGE_WHILE_RESOLVED = "triage_change_while_resolved"
    REOPEN_TO_OPEN = "cannot_return_to_open"
    NOT_CONFIRMED = "resolve_requires_confirmed"
    NOT_RESOLVED = "reopen_requires_resolved"


REQUEST_PROBLEMS = frozenset({TransitionProblem.NO_CHANGE, TransitionProblem.MULTIPLE_CHANGES})


class TransitionError(ValueError):
    def __init__(self, problem: TransitionProblem) -> None:
        super().__init__(problem.value)
        self.problem = problem


@dataclass(frozen=True, slots=True)
class TriageStatus:
    triage: TriageState
    lifecycle: LifecycleState
    version: int


@dataclass(frozen=True, slots=True)
class RequestedChange:
    """PATCH 要求的目標值；None 代表不改這個欄位。"""

    triage: TriageState | None = None
    lifecycle: LifecycleState | None = None


def plan_manual(current: TriageStatus, change: RequestedChange) -> TriageStatus:
    """人工轉換後的狀態（版本 +1）；不成立時拋 TransitionError。不檢查證據（triage 模組負責）。"""
    triage = change.triage if change.triage != current.triage else None
    lifecycle = change.lifecycle if change.lifecycle != current.lifecycle else None
    if triage is not None and lifecycle is not None:
        raise TransitionError(TransitionProblem.MULTIPLE_CHANGES)
    if triage is not None:
        if current.lifecycle is LifecycleState.RESOLVED:
            raise TransitionError(TransitionProblem.TRIAGE_WHILE_RESOLVED)
        return TriageStatus(triage, current.lifecycle, current.version + 1)
    if lifecycle is None:
        raise TransitionError(TransitionProblem.NO_CHANGE)
    _check_lifecycle(current, lifecycle)
    return TriageStatus(current.triage, lifecycle, current.version + 1)


def _check_lifecycle(current: TriageStatus, target: LifecycleState) -> None:
    if target is LifecycleState.OPEN:
        raise TransitionError(TransitionProblem.REOPEN_TO_OPEN)
    if target is LifecycleState.REOPENED:
        if current.lifecycle is not LifecycleState.RESOLVED:
            raise TransitionError(TransitionProblem.NOT_RESOLVED)
        return
    if current.triage is not TriageState.CONFIRMED:
        raise TransitionError(TransitionProblem.NOT_CONFIRMED)


def resolves(current: TriageStatus, planned: TriageStatus) -> bool:
    return (
        planned.lifecycle is LifecycleState.RESOLVED
        and current.lifecycle is not LifecycleState.RESOLVED
    )


@dataclass(frozen=True, slots=True)
class ReopenFacts:
    """linker 鎖住 finding 之後看到的事實（R1 至 R4）。"""

    lifecycle: LifecycleState
    resolved_scan_position: int | None
    run_scan_position: int
    run_mapping: tuple[str, str] | None
    finding_mapping: tuple[str, str]
    new_links: int


def should_reopen(facts: ReopenFacts) -> bool:
    """R1 resolved、R2 這次有連結（同 fingerprint）、R3 scan 比 resolve 時看到的都新、
    R4 mapping 相同。

    R3 不成立只可能是程式錯誤（resolve 時 target 沒有進行中的 scan，結束的 run 也不能再寫連結）：
    保守地不重開，不拋例外（會讓解析重試）。R4 不成立時不重開，由 resolution_review 標示。
    """
    return (
        facts.lifecycle is LifecycleState.RESOLVED
        and facts.new_links > 0
        and facts.resolved_scan_position is not None
        and facts.run_scan_position > facts.resolved_scan_position
        and facts.run_mapping is not None
        and facts.run_mapping == facts.finding_mapping
    )


class ReviewReason(StrEnum):
    """resolved 之後平台無法自動判斷是否復發、需要人工確認的原因（不算已修補）。"""

    OBSERVED_AFTER_RESOLUTION = "observed_after_resolution_mapping_differs"
    MAPPING_CHANGED = "mapping_changed_since_resolution"


def review_reasons(
    lifecycle: LifecycleState,
    *,
    observations_linked: int,
    resolved_link_count: int | None,
    later_mapping_differs: bool,
) -> tuple[ReviewReason, ...]:
    if lifecycle is not LifecycleState.RESOLVED or resolved_link_count is None:
        return ()
    reasons: list[ReviewReason] = []
    if observations_linked > resolved_link_count:
        reasons.append(ReviewReason.OBSERVED_AFTER_RESOLUTION)
    if later_mapping_differs:
        reasons.append(ReviewReason.MAPPING_CHANGED)
    return tuple(reasons)


class ExcerptKind(StrEnum):
    REQUEST = "request"
    RESPONSE = "response"


# 摘錄以 CONTENT_ENCRYPTION_KEYS 加密保存（docs/DECISIONS.md §30.4）：context 綁定 finding、事件與
# 種類。context 最長 73 個字元（sequence 是 bigint），密文的上限以 80 計算。
EXCERPT_CONTEXT_MAX_LENGTH = 80
EXCERPT_MAX_BYTES: Mapping[ExcerptKind, int] = MappingProxyType(
    {
        ExcerptKind.REQUEST: REQUEST_EXCERPT_MAX_BYTES,
        ExcerptKind.RESPONSE: RESPONSE_EXCERPT_MAX_BYTES,
    }
)
MAX_SEALED_EXCERPT_BYTES: Mapping[ExcerptKind, int] = MappingProxyType(
    {
        kind: max_sealed_blob_bytes(context_length=EXCERPT_CONTEXT_MAX_LENGTH, max_bytes=limit)
        for kind, limit in EXCERPT_MAX_BYTES.items()
    }
)


def excerpt_context(finding_id: UUID, sequence: int, kind: ExcerptKind) -> str:
    return f"excerpt:{finding_id}:{sequence}:{kind.value}"


@dataclass(frozen=True, slots=True)
class SealedExcerpt:
    """DB 中的一段摘錄：密文（清除之後是 None）與期限。"""

    kind: ExcerptKind
    token: bytes | None
    expires_at: datetime
    purged_at: datetime | None


@dataclass(frozen=True, slots=True)
class Excerpt:
    """API 顯示的一段摘錄：解密並核對過雜湊與長度；清除之後 content 是 None（tombstone）。"""

    kind: ExcerptKind
    content: str | None
    expires_at: datetime
    purged_at: datetime | None


@dataclass(frozen=True, slots=True)
class NewTriageEvent:
    """要寫入的事件；sequence 必須等於 finding 更新後的 triage_version（DB 的事件鏈檢查）。"""

    finding_id: UUID
    target_id: UUID
    sequence: int
    actor_kind: ActorKind
    actor_key_id: UUID | None
    request_id: str | None
    previous: TriageStatus
    current: TriageStatus
    reason_code: TriageReasonCode
    reason: str
    evidence: JsonObject
    comparison_id: UUID | None = None
    basis: ResolutionBasis | None = None
    run_id: UUID | None = None
    scan_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class TriageEvent:
    """不可修改的事件（triage-events API 的一項）；excerpts 只有 operator/admin 看得到。"""

    sequence: int
    actor_kind: ActorKind
    actor_key_id: UUID | None
    actor_name: str | None
    actor_role: str | None
    request_id: str | None
    previous_triage: TriageState
    triage: TriageState
    previous_lifecycle: LifecycleState
    lifecycle: LifecycleState
    reason_code: TriageReasonCode
    reason: str
    comparison_id: UUID | None
    basis: ResolutionBasis | None
    run_id: UUID | None
    scan_id: UUID | None
    evidence: JsonObject
    created_at: datetime
    # DB 讀出的密文（records 填入）與解密後給 API 的內容（service 填入）；都是 None 表示呼叫者
    # 沒有寫入權限（viewer）。
    sealed_excerpts: tuple[SealedExcerpt, ...] | None = None
    excerpts: tuple[Excerpt, ...] | None = None

    @property
    def provenance(self) -> EvidenceProvenance | None:
        return PROVENANCE_OF_BASIS[self.basis] if self.basis is not None else None


@dataclass(frozen=True, slots=True)
class Resolution:
    """目前 resolved 的依據（最後一次轉成 resolved 的事件）；resolved 一律是人工判定。"""

    basis: ResolutionBasis
    comparison_id: UUID
    decided_at: datetime
    decided_by_role: str | None
    decided_by_name: str | None
    event_sequence: int
    attestation: JsonObject | None

    @property
    def provenance(self) -> EvidenceProvenance:
        return PROVENANCE_OF_BASIS[self.basis]
