"""人工 triage 的業務規則（T21；docs/DECISIONS.md §28）。

PATCH 的順序：
1. 以 finding 的 project 授權：其他 project 與不存在的一樣 404，角色不足 403（先讀再寫，比照
   comparisons）。
2. 請求的形狀：resolve 必須有 basis 與 comparison_id；manual_retest 必須有 attestation，其他情況
   不能帶（422）。
3. 以 FOR NO KEY UPDATE 鎖住 finding，核對 expected_version（409 VERSION_CONFLICT），再以 domain
   規則規劃轉換（409／422）。
4. resolve 時檢查證據：引用的比較快照（其他 project 404、不同 target 422）、target 沒有進行中的
   scan（409 TARGET_BUSY；DB 的 trigger 也會擋）、雙軌的平台條件與人工複測聲明的一致性檢查。所有
   不符的原因一次列在 422 RESOLUTION_EVIDENCE_INSUFFICIENT 的訊息中（固定的代碼，不回顯輸入）。
5. 寫入：finding（版本 +1）→ 事件 → 摘錄 → audit，全在同一個 transaction；任何一步失敗都整筆回滾。

resolved 一律是人工判定：這裡不會因為比較快照的分類而自動改任何狀態，比較快照也不被修改。
"""

from dataclasses import dataclass
from http import HTTPStatus
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secscan.api_keys.access import authorize
from secscan.api_keys.domain import AccessDecision, Permission, Principal, decide
from secscan.api_keys.repository import ApiKeyRepository
from secscan.audit.service import AuditTrail
from secscan.comparisons.repository import ComparisonRepository
from secscan.core.errors import AppError, ErrorCode, not_found_error
from secscan.core.json_types import JsonObject, JsonValue
from secscan.core.pagination import Page, PageRequest
from secscan.core.text import require_multiline_text
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import (
    PROVENANCE_OF_BASIS,
    REASON_MAX_LENGTH,
    REQUEST_PROBLEMS,
    ActorKind,
    NewTriageEvent,
    RequestedChange,
    ResolutionBasis,
    TransitionError,
    TriageEvent,
    TriageReasonCode,
    TriageStatus,
    plan_manual,
    resolves,
)
from secscan.findings.triage_records import LockedTriage, TriageRecords
from secscan.security.redaction import redact_text
from secscan.triage.domain.attestation import (
    CHECKS_VERSION,
    PLATFORM_CHECKS,
    Attestation,
    AttestationError,
    CheckedAttestation,
)
from secscan.triage.domain.attestation import check_attestation as check_consistency
from secscan.triage.domain.evidence import CitedComparison, ComparisonRow, evidence_problems
from secscan.triage.repository import FindingFacts, TriageQueries

TARGET_BUSY_CONSTRAINT = "findings_resolve_target_busy"
MAX_CITED_OBSERVATIONS = 20


@dataclass(frozen=True, slots=True)
class TriageCommand:
    expected_version: int
    reason: str
    triage: TriageState | None = None
    lifecycle: LifecycleState | None = None
    basis: ResolutionBasis | None = None
    comparison_id: UUID | None = None
    attestation: Attestation | None = None
    observation_ids: tuple[UUID, ...] = ()


@dataclass(frozen=True, slots=True)
class _Resolution:
    comparison_id: UUID
    basis: ResolutionBasis
    evidence: JsonObject
    checked: CheckedAttestation | None


class TriageService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._queries = TriageQueries(session)
        self._records = TriageRecords(session)
        self._comparisons = ComparisonRepository(session)
        self._audit = AuditTrail(session)

    def change(
        self,
        principal: Principal,
        finding_id: UUID,
        command: TriageCommand,
        *,
        request_id: str | None,
    ) -> None:
        facts = self._authorized(principal, finding_id, Permission.PROJECT_WRITE)
        self._require_active_key(principal)
        reason = _reason(command.reason)
        _check_shape(command)
        if len(set(command.observation_ids)) != self._queries.linked_observations(
            finding_id, list(set(command.observation_ids))
        ):
            raise _invalid("observation_ids 必須是連結到這個 finding 的觀察。")
        locked = self._records.lock(finding_id)
        if locked is None:
            raise not_found_error()
        if locked.status.version != command.expected_version:
            raise AppError(
                status_code=HTTPStatus.CONFLICT,
                code=ErrorCode.VERSION_CONFLICT,
                message="finding 的 triage 已被修改；請重新讀取 triage_version 後再送出。",
            )
        planned = _plan(locked.status, command)
        resolution = None
        if resolves(locked.status, planned):
            resolution = self._resolution(principal, finding_id, facts, command)
        self._write(
            principal, facts.project_id, locked, planned, command, reason, resolution, request_id
        )

    def events(
        self, principal: Principal, finding_id: UUID, page: PageRequest
    ) -> Page[TriageEvent]:
        """事件由舊到新；摘錄內容只給能寫入這個 project 的角色（人工摘錄只有樣式遮罩）。"""
        facts = self._authorized(principal, finding_id, Permission.PROJECT_READ)
        writer = (
            decide(principal, Permission.PROJECT_WRITE, facts.project_id) is AccessDecision.ALLOWED
        )
        return self._records.events(finding_id, page, with_excerpts=writer)

    def _require_active_key(self, principal: Principal) -> None:
        """以 FOR SHARE 鎖住呼叫者的 key 並重新確認沒有被撤銷：撤銷（FOR UPDATE）要等這個
        transaction，不會在撤銷之後才提交人工判定（比照 runner，docs/DECISIONS.md §13.5）。"""
        key = ApiKeyRepository(self._session).lock_shared(principal.key_id)
        if key is None or key.revoked_at is not None:
            raise AppError(
                status_code=HTTPStatus.UNAUTHORIZED,
                code=ErrorCode.UNAUTHENTICATED,
                message="API key 已撤銷。",
            )

    def _authorized(
        self, principal: Principal, finding_id: UUID, permission: Permission
    ) -> FindingFacts:
        facts = self._queries.finding(finding_id)
        if facts is None:
            raise not_found_error()
        authorize(principal, Permission.PROJECT_READ, facts.project_id)
        authorize(principal, permission, facts.project_id)
        return facts

    def _resolution(
        self,
        principal: Principal,
        finding_id: UUID,
        facts: FindingFacts,
        command: TriageCommand,
    ) -> _Resolution:
        if command.comparison_id is None or command.basis is None:
            raise _invalid("resolve 必須帶 basis 與 comparison_id。")
        comparison = self._comparisons.get(command.comparison_id)
        if comparison is None:
            raise not_found_error()
        authorize(principal, Permission.PROJECT_READ, comparison.project_id)
        if comparison.target_id != facts.target_id:
            raise AppError(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                code=ErrorCode.TARGET_MISMATCH,
                message="引用的比較快照屬於其他 target。",
            )
        if self._queries.target_busy(facts.target_id):
            raise _target_busy()
        found = self._comparisons.row(comparison.id, finding_id)
        row = (
            ComparisonRow(
                found.classification, found.reasons, found.manual_review_required, found.evidence
            )
            if found is not None
            else None
        )
        cited = CitedComparison(comparison.algorithm_version, comparison.comparability, row)
        observed_after = self._queries.observed_after(finding_id, comparison.current_scan_id)
        problems: list[str] = [
            problem.value
            for problem in evidence_problems(command.basis, cited, observed_after=observed_after)
        ]
        checked = None
        if command.basis is ResolutionBasis.MANUAL_RETEST and command.attestation is not None:
            try:
                checked = check_consistency(
                    command.attestation,
                    facts.location,
                    facts.target,
                    now=self._queries.now(),
                    last_observed_at=self._queries.last_observed_at(finding_id),
                )
            except AttestationError as error:
                problems.extend(problem.value for problem in error.problems)
        if problems:
            raise AppError(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                code=ErrorCode.RESOLUTION_EVIDENCE_INSUFFICIENT,
                message="證據不足，不能標成 resolved：" + ", ".join(problems),
            )
        evidence: JsonObject = {}
        if row is not None:
            evidence = {"classification": row.classification.value, "reasons": list(row.reasons)}
        if checked is not None:
            evidence["attestation"] = checked.evidence()
        return _Resolution(comparison.id, command.basis, evidence, checked)

    def _write(
        self,
        principal: Principal,
        project_id: UUID,
        locked: LockedTriage,
        planned: TriageStatus,
        command: TriageCommand,
        reason: str,
        resolution: _Resolution | None,
        request_id: str | None,
    ) -> None:
        evidence: JsonObject = dict(resolution.evidence) if resolution is not None else {}
        if command.observation_ids:
            evidence["observation_ids"] = [
                str(item) for item in dict.fromkeys(command.observation_ids)
            ]
        try:
            self._records.apply(locked.id, planned)
        except IntegrityError as error:
            if _constraint(error) == TARGET_BUSY_CONSTRAINT:
                raise _target_busy() from None
            raise
        self._records.append(
            NewTriageEvent(
                finding_id=locked.id,
                target_id=locked.target_id,
                sequence=planned.version,
                actor_kind=ActorKind.KEY,
                actor_key_id=principal.key_id,
                request_id=request_id,
                previous=locked.status,
                current=planned,
                reason_code=TriageReasonCode.MANUAL,
                reason=reason,
                evidence=evidence,
                comparison_id=resolution.comparison_id if resolution is not None else None,
                basis=resolution.basis if resolution is not None else None,
            )
        )
        if resolution is not None and resolution.checked is not None:
            self._records.append_excerpts(
                locked.id,
                planned.version,
                resolution.checked.request_excerpt,
                resolution.checked.response_excerpt,
            )
        self._audit.record(
            action="finding.triage",
            object_type="finding",
            object_id=locked.id,
            actor_key_id=principal.key_id,
            project_id=project_id,
            request_id=request_id,
            changes=_audit_changes(locked.status, planned, reason, resolution),
        )


def _reason(value: str) -> str:
    """遮罩之後再檢查長度（遮罩可能變長）：超過時回 422，不讓 DB 的 CHECK 變成 500。"""
    try:
        require_multiline_text(value, field="reason", max_length=REASON_MAX_LENGTH)
    except ValueError as error:
        raise _invalid(str(error)) from None
    masked = redact_text(value)
    if len(masked) > REASON_MAX_LENGTH:
        raise _invalid(f"reason 遮罩之後超過 {REASON_MAX_LENGTH} 個字元。")
    return masked


def _check_shape(command: TriageCommand) -> None:
    if len(command.observation_ids) > MAX_CITED_OBSERVATIONS:
        raise _invalid(f"observation_ids 最多 {MAX_CITED_OBSERVATIONS} 個。")
    if command.lifecycle is LifecycleState.RESOLVED:
        if command.basis is None or command.comparison_id is None:
            raise _invalid("resolve 必須帶 basis 與 comparison_id。")
        manual = command.basis is ResolutionBasis.MANUAL_RETEST
        if manual != (command.attestation is not None):
            raise _invalid("attestation 只用於 manual_retest，而且 manual_retest 必須附上。")
        return
    if command.basis is not None or command.comparison_id is not None:
        raise _invalid("basis 與 comparison_id 只用於轉成 resolved。")
    if command.attestation is not None:
        raise _invalid("attestation 只用於以 manual_retest 轉成 resolved。")


def _plan(current: TriageStatus, command: TriageCommand) -> TriageStatus:
    try:
        return plan_manual(current, RequestedChange(command.triage, command.lifecycle))
    except TransitionError as error:
        if error.problem in REQUEST_PROBLEMS:
            raise _invalid(f"不合法的 triage 請求：{error.problem.value}") from None
        raise AppError(
            status_code=HTTPStatus.CONFLICT,
            code=ErrorCode.INVALID_STATE_TRANSITION,
            message=f"目前的狀態不允許這個轉換：{error.problem.value}",
        ) from None


def _audit_changes(
    previous: TriageStatus,
    planned: TriageStatus,
    reason: str,
    resolution: _Resolution | None,
) -> dict[str, JsonValue]:
    """audit 只放版本、前後狀態、依據與雜湊，不放摘錄內容；鍵名避開遮罩規則（例如 role）。"""
    field = "triage" if previous.triage != planned.triage else "lifecycle"
    before = previous.triage if field == "triage" else previous.lifecycle
    after = planned.triage if field == "triage" else planned.lifecycle
    changes: dict[str, JsonValue] = {
        "version": planned.version,
        field: {"from": before.value, "to": after.value},
        "reason": reason,
    }
    if resolution is None:
        return changes
    changes["basis"] = resolution.basis.value
    changes["evidence_provenance"] = PROVENANCE_OF_BASIS[resolution.basis].value
    changes["comparison_id"] = str(resolution.comparison_id)
    checked = resolution.checked
    if checked is not None:
        changes["checks_version"] = CHECKS_VERSION
        changes["platform_checks"] = list(PLATFORM_CHECKS)
        changes["performed_at"] = checked.performed_at.isoformat()
        changes["performed_by"] = checked.performed_by
        changes["request_excerpt_sha256"] = checked.request_sha256
        changes["response_excerpt_sha256"] = checked.response_sha256
    return changes


def _constraint(error: IntegrityError) -> str | None:
    diag = getattr(error.orig, "diag", None)
    name = getattr(diag, "constraint_name", None)
    return name if isinstance(name, str) else None


def _invalid(message: str) -> AppError:
    return AppError(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY, code=ErrorCode.INVALID_REQUEST, message=message
    )


def _target_busy() -> AppError:
    return AppError(
        status_code=HTTPStatus.CONFLICT,
        code=ErrorCode.TARGET_BUSY,
        message="target 有進行中的 scan；請等它結束後再判定 resolved。",
    )
