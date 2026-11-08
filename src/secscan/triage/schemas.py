"""triage 的請求與回應 schema（docs/API_CONTRACT.md；docs/DECISIONS.md §28）。

- 請求一律 extra="forbid"：client 不能填寫 provenance、platform_checks、actor 等平台欄位。
- attestation 是操作者聲明：平台只做一致性檢查，不驗證真實性；回應以 evidence_provenance 標示。
- 摘錄內容只在 triage-events 回給 operator/admin；viewer 只看到 metadata 與雜湊。
"""

from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from secscan.core.json_types import JsonObject
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import (
    REASON_MAX_LENGTH,
    REQUEST_EXCERPT_MAX_BYTES,
    RESPONSE_EXCERPT_MAX_BYTES,
    ActorKind,
    EvidenceProvenance,
    ExcerptKind,
    ResolutionBasis,
    TriageEvent,
    TriageReasonCode,
)
from secscan.triage.domain.attestation import (
    PERFORMED_BY_MAX_LENGTH,
    PROCEDURE_MAX_LENGTH,
    ROLE_MAX_LENGTH,
    Attestation,
)
from secscan.triage.service import MAX_CITED_OBSERVATIONS, TriageCommand

MAX_VERSION = 2**63 - 1


class AttestationIn(BaseModel):
    """人工複測聲明。request_excerpt 是 HTTP/1.1 形式的原始請求；不要貼上憑證。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: Literal["manual_retest"]
    performed_at: AwareDatetime
    performed_by: str = Field(min_length=1, max_length=PERFORMED_BY_MAX_LENGTH)
    procedure: str = Field(min_length=1, max_length=PROCEDURE_MAX_LENGTH)
    result: str = Field(min_length=1, max_length=32, description="只接受 not_reproduced")
    auth_role: str = Field(min_length=1, max_length=ROLE_MAX_LENGTH)
    request_excerpt: str = Field(min_length=1, max_length=REQUEST_EXCERPT_MAX_BYTES)
    response_excerpt: str = Field(min_length=1, max_length=RESPONSE_EXCERPT_MAX_BYTES)

    def to_domain(self) -> Attestation:
        return Attestation(
            performed_at=self.performed_at,
            performed_by=self.performed_by,
            procedure=self.procedure,
            result=self.result,
            auth_role=self.auth_role,
            request_excerpt=self.request_excerpt,
            response_excerpt=self.response_excerpt,
        )


class TriageChangeIn(BaseModel):
    """一次只改 triage_state 或 lifecycle_state 其中一個；resolve 必須附上依據與比較快照。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: int = Field(ge=0, le=MAX_VERSION)
    reason: str = Field(min_length=1, max_length=REASON_MAX_LENGTH)
    triage_state: TriageState | None = None
    lifecycle_state: LifecycleState | None = None
    basis: ResolutionBasis | None = None
    comparison_id: UUID | None = None
    attestation: AttestationIn | None = None
    observation_ids: list[UUID] = Field(default_factory=list, max_length=MAX_CITED_OBSERVATIONS)

    def to_command(self) -> TriageCommand:
        return TriageCommand(
            expected_version=self.expected_version,
            reason=self.reason,
            triage=self.triage_state,
            lifecycle=self.lifecycle_state,
            basis=self.basis,
            comparison_id=self.comparison_id,
            attestation=self.attestation.to_domain() if self.attestation is not None else None,
            observation_ids=tuple(self.observation_ids),
        )


class ExcerptOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: ExcerptKind
    content: str


class TriageEventOut(BaseModel):
    """一筆不可修改的事件；evidence 是寫入當時的白名單鍵（不含摘錄內容）。"""

    model_config = ConfigDict(frozen=True)

    sequence: int
    actor_kind: ActorKind
    actor_key_id: UUID | None
    actor_name: str | None
    actor_role: str | None
    request_id: str | None
    previous_triage_state: TriageState
    triage_state: TriageState
    previous_lifecycle_state: LifecycleState
    lifecycle_state: LifecycleState
    reason_code: TriageReasonCode
    reason: str
    comparison_id: UUID | None
    basis: ResolutionBasis | None
    evidence_provenance: EvidenceProvenance | None
    run_id: UUID | None
    scan_id: UUID | None
    evidence: JsonObject
    created_at: datetime
    # null：呼叫者沒有寫入權限（viewer），只看得到 evidence 中的雜湊與長度。
    excerpts: list[ExcerptOut] | None

    @classmethod
    def of(cls, event: TriageEvent) -> Self:
        return cls(
            sequence=event.sequence,
            actor_kind=event.actor_kind,
            actor_key_id=event.actor_key_id,
            actor_name=event.actor_name,
            actor_role=event.actor_role,
            request_id=event.request_id,
            previous_triage_state=event.previous_triage,
            triage_state=event.triage,
            previous_lifecycle_state=event.previous_lifecycle,
            lifecycle_state=event.lifecycle,
            reason_code=event.reason_code,
            reason=event.reason,
            comparison_id=event.comparison_id,
            basis=event.basis,
            evidence_provenance=event.provenance,
            run_id=event.run_id,
            scan_id=event.scan_id,
            evidence=event.evidence,
            created_at=event.created_at,
            excerpts=(
                [ExcerptOut(kind=kind, content=content) for kind, content in event.excerpts]
                if event.excerpts is not None
                else None
            ),
        )
