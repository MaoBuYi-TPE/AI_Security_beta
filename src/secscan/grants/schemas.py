"""scope grant 的請求與回應 schema（docs/API_CONTRACT.md §4、§14）。

清單與每個項目在讀進 domain 之前就限制數量與長度；格式與規則由 domain 檢查（錯誤訊息說明原因）。
status、version 與核准、撤銷的欄位都不能由 client 指定。
"""

from datetime import datetime
from typing import Annotated, Self
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
)

from secscan.core.text import require_text
from secscan.grants.domain.lifecycle import DECISION_NOTE_MAX_LENGTH, GrantState, ScopeGrant
from secscan.grants.domain.scope import (
    AUTHORIZATION_REFERENCE_MAX_LENGTH,
    MAX_ALLOWED_IPS,
    MAX_ALLOWED_ORIGINS,
    MAX_ALLOWED_PATHS,
    MAX_EXCLUDED_PATHS,
    PATH_MAX_LENGTH,
    GrantRequest,
    HttpMethod,
)
from secscan.targets.domain import ORIGIN_MAX_LENGTH

IPV4_TEXT_MAX_LENGTH = len("255.255.255.255")
METHOD_TEXT_MAX_LENGTH = max(len(method.value) for method in HttpMethod)

OriginText = Annotated[StrictStr, Field(max_length=ORIGIN_MAX_LENGTH)]
IpText = Annotated[StrictStr, Field(max_length=IPV4_TEXT_MAX_LENGTH)]
PathText = Annotated[StrictStr, Field(max_length=PATH_MAX_LENGTH)]
MethodText = Annotated[StrictStr, Field(max_length=METHOD_TEXT_MAX_LENGTH)]


class BudgetIn(BaseModel):
    """預算；省略的項目使用上限（2 req/s、5,000 次、1,500 秒）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requests_per_second: StrictInt | None = None
    max_requests: StrictInt | None = None
    max_duration_seconds: StrictInt | None = None


class ScopeGrantCreate(BaseModel):
    """申請 scope grant（target 的新版本），核准前不能用來掃描。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_origins: list[OriginText] = Field(min_length=1, max_length=MAX_ALLOWED_ORIGINS)
    allowed_ips: list[IpText] = Field(min_length=1, max_length=MAX_ALLOWED_IPS)
    allowed_paths: list[PathText] = Field(default_factory=list, max_length=MAX_ALLOWED_PATHS)
    allow_all_paths: StrictBool = False
    excluded_paths: list[PathText] = Field(default_factory=list, max_length=MAX_EXCLUDED_PATHS)
    allowed_methods: list[MethodText] = Field(min_length=1, max_length=len(HttpMethod))
    budget: BudgetIn = Field(default_factory=BudgetIn)
    authorization_reference: StrictStr = Field(
        min_length=1, max_length=AUTHORIZATION_REFERENCE_MAX_LENGTH
    )
    valid_from: AwareDatetime | None = None
    valid_until: AwareDatetime

    @field_validator("authorization_reference")
    @classmethod
    def _reference_is_text(cls, value: str) -> str:
        require_text(
            value, field="authorization_reference", max_length=AUTHORIZATION_REFERENCE_MAX_LENGTH
        )
        return value

    def to_request(self) -> GrantRequest:
        return GrantRequest(
            origins=tuple(self.allowed_origins),
            ips=tuple(self.allowed_ips),
            paths=tuple(self.allowed_paths),
            allow_all_paths=self.allow_all_paths,
            excluded_paths=tuple(self.excluded_paths),
            methods=tuple(self.allowed_methods),
            authorization_reference=self.authorization_reference,
            valid_until=self.valid_until,
            valid_from=self.valid_from,
            requests_per_second=self.budget.requests_per_second,
            max_requests=self.budget.max_requests,
            max_duration_seconds=self.budget.max_duration_seconds,
        )


class GrantDecision(BaseModel):
    """核准：note 寫下核對了什麼（資產、origin 與 IP 的對應、隔離網路、副作用）。"""

    model_config = ConfigDict(extra="forbid", frozen=True)

    note: StrictStr = Field(min_length=1, max_length=DECISION_NOTE_MAX_LENGTH)

    @field_validator("note")
    @classmethod
    def _note_is_text(cls, value: str) -> str:
        require_text(value, field="note", max_length=DECISION_NOTE_MAX_LENGTH)
        return value


class GrantRevocation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reason: StrictStr = Field(min_length=1, max_length=DECISION_NOTE_MAX_LENGTH)

    @field_validator("reason")
    @classmethod
    def _reason_is_text(cls, value: str) -> str:
        require_text(value, field="reason", max_length=DECISION_NOTE_MAX_LENGTH)
        return value


class BudgetOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    requests_per_second: int
    max_requests: int
    max_duration_seconds: int


class ScopeGrantOut(BaseModel):
    """grant 的內容；status 是讀取當下推導出的狀態（過期不需要改 DB）。"""

    model_config = ConfigDict(frozen=True)

    id: UUID
    target_id: UUID
    project_id: UUID
    version: int
    status: GrantState
    allowed_origins: list[str]
    allowed_ips: list[str]
    allowed_paths: list[str]
    allow_all_paths: bool
    excluded_paths: list[str]
    allowed_methods: list[str]
    budget: BudgetOut
    authorization_reference: str
    valid_from: datetime
    valid_until: datetime
    requested_by_key_id: UUID
    created_at: datetime
    approved_by_key_id: UUID | None
    approved_at: datetime | None
    approval_note: str | None
    revoked_by_key_id: UUID | None
    revoked_at: datetime | None
    revocation_reason: str | None

    @classmethod
    def of(cls, grant: ScopeGrant, *, now: datetime) -> Self:
        scope, budget = grant.scope, grant.budget
        return cls(
            id=grant.id,
            target_id=grant.target_id,
            project_id=grant.project_id,
            version=grant.version,
            status=grant.state_at(now),
            allowed_origins=[str(origin) for origin in scope.origins],
            allowed_ips=[str(address) for address in scope.ips],
            allowed_paths=list(scope.paths),
            allow_all_paths=scope.allow_all_paths,
            excluded_paths=list(scope.excluded_paths),
            allowed_methods=[method.value for method in scope.methods],
            budget=BudgetOut(
                requests_per_second=budget.requests_per_second,
                max_requests=budget.max_requests,
                max_duration_seconds=budget.max_duration_seconds,
            ),
            authorization_reference=grant.authorization_reference,
            valid_from=grant.window.valid_from,
            valid_until=grant.window.valid_until,
            requested_by_key_id=grant.requested_by_key_id,
            created_at=grant.created_at,
            approved_by_key_id=grant.approved_by_key_id,
            approved_at=grant.approved_at,
            approval_note=grant.approval_note,
            revoked_by_key_id=grant.revoked_by_key_id,
            revoked_at=grant.revoked_at,
            revocation_reason=grant.revocation_reason,
        )
