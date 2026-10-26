"""scan 的 service 測試共用：在 db_session 的交易中準備 target、核准的 grant、規格與 profile。

規格與 grant 的範圍刻意讓每一種判斷都出現（docs/DECISIONS.md §13.1 的凍結 operation）：
- 在範圍內：GET /me、GET /users/v1、GET /users/v1/{username}
- PATH_EXCLUDED：GET /users/v1/_debug
- METHOD_NOT_AUTHORIZED：POST /users/v1、DELETE /users/v1/{username}
- PATH_NOT_AUTHORIZED：GET /books/v1
"""

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal
from secscan.auth_profiles.domain.credentials import AuthType, SecretValue
from secscan.auth_profiles.domain.model import AuthProfile, PreflightInput, ProfileInput
from secscan.auth_profiles.service import AuthProfileService
from secscan.grants.domain.lifecycle import ScopeGrant
from secscan.grants.service import ScopeGrantService
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.model import Scan
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.service import ScanService
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import ApiSpec, SpecUpload
from secscan.specs.service import ApiSpecService
from secscan.targets.domain import Target, TargetKind
from secscan.targets.service import TargetService
from tests.integration.api_support import VAMPI_ME
from tests.integration.scope_support import LAB, Members, grant_request, members
from tests.secret_support import shared_cipher

# 以真實的時間為準：grant 的核准時間是 DB 的 now()，必須早於 valid_until。
NOW = datetime.now(UTC).replace(microsecond=0)
# 每個測試的 profile 都以這個 canary 當 secret：回應、事件、audit 中都不可以出現。
CANARY_SECRET = "canary-target-secret-0001"
ELIGIBLE = 3
INELIGIBLE = 4
SCAN_PATHS = ("/users/v1", "/users/v1/{username}", "/me")
EXCLUDED = ("/users/v1/_debug",)


def _spec_document() -> bytes:
    def operation(name: str) -> dict[str, object]:
        return {"operationId": name, "responses": {"200": {"description": "ok"}}}

    paths = {
        "/users/v1": {"get": operation("listUsers"), "post": operation("register")},
        "/users/v1/{username}": {
            "get": operation("getUser"),
            "delete": operation("deleteUser"),
        },
        "/users/v1/_debug": {"get": operation("debug")},
        "/books/v1": {"get": operation("listBooks")},
        "/me": {"get": operation("me")},
    }
    document = {"openapi": "3.0.3", "info": {"title": "lab", "version": "1"}, "paths": paths}
    return json.dumps(document).encode()


SPEC_DOCUMENT = _spec_document()


def clock_at(moment: datetime) -> Callable[[], datetime]:
    return lambda: moment


DEFAULT_CLOCK = clock_at(NOW + timedelta(minutes=1))


@dataclass(frozen=True)
class ScanWorld:
    """一個可以掃描的 target：核准的 grant、規格與 bearer profile（preflight 是 GET /me）。"""

    team: Members
    target: Target
    grant: ScopeGrant
    spec: ApiSpec
    profile: AuthProfile

    @property
    def operator(self) -> Principal:
        return self.team.operator_a

    def request(self, **overrides: object) -> ScanRequest:
        fields: dict[str, object] = {
            "target_id": self.target.id,
            "scope_grant_id": self.grant.id,
            "api_spec_id": self.spec.id,
            "auth_profile_id": self.profile.id,
            "profile": ScanProfile.API_ACTIVE_LAB,
            "engines": (Engine.FAKE,),
            "budget": BudgetRequest(),
        }
        fields.update(overrides)
        return ScanRequest(**fields)  # type: ignore[arg-type]


def new_key() -> str:
    return str(uuid4())


def make_target(
    session: Session,
    principal: Principal,
    project_id: UUID,
    *,
    kind: TargetKind = TargetKind.API,
) -> Target:
    host = f"lab-{uuid4().hex[:8]}"
    return TargetService(session, lab=LAB).create(
        principal,
        project_id,
        name=host,
        kind=kind,
        base_url=f"http://{host}:5000",
        request_id=None,
    )


def approved_grant(
    session: Session, team: Members, target: Target, **overrides: object
) -> ScopeGrant:
    fields: dict[str, object] = {
        "origins": (str(target.origin),),
        "paths": SCAN_PATHS,
        "excluded_paths": EXCLUDED,
    }
    fields.update(overrides)
    grants = ScopeGrantService(session, lab=LAB)
    grant = grants.request(
        team.admin, target.id, grant_request(NOW, **fields), now=NOW, request_id=None
    )
    return grants.approve(team.admin, grant.id, note="已核對 lab", now=NOW, request_id=None)


def upload_spec(session: Session, team: Members, target: Target) -> ApiSpec:
    upload = SpecUpload(spec_format=SpecFormat.JSON, content=SPEC_DOCUMENT)
    return ApiSpecService(session).upload(team.admin, target.id, upload, request_id=None)


def create_profile(
    session: Session,
    team: Members,
    target: Target,
    *,
    role_label: str = "standard_user",
    preflight: PreflightInput = VAMPI_ME,
    secret: str = CANARY_SECRET,
) -> AuthProfile:
    request = ProfileInput(
        name=f"profile {role_label}",
        role_label=role_label,
        type=AuthType.BEARER,
        header_name=None,
        secret=SecretValue(secret),
        preflight=preflight,
    )
    return AuthProfileService(session, cipher=shared_cipher()).create(
        team.admin, target.id, request, request_id=None
    )


def scan_world(session: Session, team: Members | None = None) -> ScanWorld:
    team = team if team is not None else members(session, NOW)
    target = make_target(session, team.admin, team.project_a)
    return ScanWorld(
        team=team,
        target=target,
        grant=approved_grant(session, team, target),
        spec=upload_spec(session, team, target),
        profile=create_profile(session, team, target),
    )


def create_scan(
    session: Session,
    world: ScanWorld,
    request: ScanRequest | None = None,
    *,
    principal: Principal | None = None,
    key: str | None = None,
    clock: Callable[[], datetime] = DEFAULT_CLOCK,
) -> Scan:
    return ScanService(session, lab=LAB).create(
        principal if principal is not None else world.operator,
        request if request is not None else world.request(),
        idempotency_key=key if key is not None else new_key(),
        clock=clock,
        request_id="req-scan-test",
    )


def with_budget(request: ScanRequest, **budget: int | None) -> ScanRequest:
    return replace(request, budget=BudgetRequest(**budget))
