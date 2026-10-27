"""API 整合測試的資料準備：直接用 service 建立 project 與 key 並 commit，不經 HTTP。"""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Engine, Row, text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import IssuedApiKey, Principal, Role
from secscan.api_keys.service import ApiKeyService
from secscan.auth_profiles.domain.credentials import AuthType, SecretValue
from secscan.auth_profiles.domain.model import AuthProfile, PreflightInput, ProfileInput
from secscan.auth_profiles.service import AuthProfileService
from secscan.core.config import DEFAULT_LAB_CIDR
from secscan.grants.domain.lifecycle import ScopeGrant
from secscan.grants.domain.scope import GrantRequest
from secscan.grants.service import ScopeGrantService
from secscan.projects.domain import Project
from secscan.projects.service import ProjectService
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.model import Scan
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.service import ScanService
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import ApiSpec, SpecUpload
from secscan.specs.service import ApiSpecService
from secscan.targets.domain import LabNetwork, Target, TargetKind
from secscan.targets.service import TargetService
from tests.secret_support import shared_cipher

MINIMAL_SPEC = (
    b'{"openapi": "3.0.3", "info": {"title": "t", "version": "1"},'
    b' "paths": {"/items/{id}": {"get": {"operationId": "getItem"}}}}'
)
# 測試 profile 預設的 secret（測試洩漏時改用 canary）。
DEFAULT_SECRET = "t1"
# 可以掃描的 grant 範圍：MINIMAL_SPEC 的 GET /items/{id} 與 profile 的 preflight GET /me。
SCANNABLE_PATHS = ("/items/{id}", "/me")
# 與 API（create_app 的預設設定）相同的 lab 網段。
LAB = LabNetwork(DEFAULT_LAB_CIDR)
LAB_IP = "10.89.7.20"
# VAmPI 的 GET /me（tests/fixtures/openapi/vampi-openapi3.yml）：
# 回應是 {"data": {...}, "status": ...}。
VAMPI_ME = PreflightInput(
    method="GET",
    path="/me",
    expected_status=200,
    expected_json={"/data/username": "name1", "/status": "success"},
)


@dataclass(frozen=True)
class Caller:
    """持有一把平台 key 的呼叫者；key 不出現在 repr。"""

    principal: Principal
    key: str = field(repr=False)

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.key}"}


@dataclass(frozen=True)
class Scannable:
    """可以建立 scan 的 target：核准的 grant、規格與 bearer profile。"""

    target: Target
    grant: ScopeGrant
    spec: ApiSpec
    profile: AuthProfile

    def request(self, **overrides: object) -> ScanRequest:
        fields: dict[str, object] = {
            "target_id": self.target.id,
            "scope_grant_id": self.grant.id,
            "api_spec_id": self.spec.id,
            "auth_profile_id": self.profile.id,
            "profile": ScanProfile.API_ACTIVE_LAB,
            "engines": (ScanEngine.FAKE,),
            "budget": BudgetRequest(),
        }
        fields.update(overrides)
        return ScanRequest(**fields)  # type: ignore[arg-type]


@dataclass(frozen=True)
class World:
    """一位 admin、兩個 project（A、B），以及 A 的 viewer 與 operator。"""

    admin: Caller
    project_a: Project
    project_b: Project
    viewer_a: Caller
    operator_a: Caller


def unique_name(label: str) -> str:
    return f"{label}-{uuid4().hex[:8]}"


class Seeder:
    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    @contextmanager
    def _session(self) -> Iterator[Session]:
        with Session(self._engine, expire_on_commit=False) as session, session.begin():
            yield session

    def admin(self) -> Caller:
        with self._session() as session:
            issued = ApiKeyService(session).issue_admin_key(
                name="test-admin", expires_at=None, now=datetime.now(UTC)
            )
        return _caller(issued)

    def project(self, admin: Caller) -> Project:
        with self._session() as session:
            return ProjectService(session).create(
                admin.principal, name=unique_name("lab"), request_id=None
            )

    def member(self, admin: Caller, project_id: UUID, role: Role) -> Caller:
        with self._session() as session:
            issued = ApiKeyService(session).issue_project_key(
                admin.principal,
                project_id,
                name=unique_name(role.value),
                role=role,
                expires_at=None,
                now=datetime.now(UTC),
                request_id=None,
            )
        return _caller(issued)

    def world(self) -> World:
        admin = self.admin()
        project_a, project_b = self.project(admin), self.project(admin)
        return World(
            admin=admin,
            project_a=project_a,
            project_b=project_b,
            viewer_a=self.member(admin, project_a.id, Role.VIEWER),
            operator_a=self.member(admin, project_a.id, Role.OPERATOR),
        )

    def target(
        self,
        caller: Caller,
        project_id: UUID,
        base_url: str | None = None,
        *,
        kind: TargetKind = TargetKind.API,
    ) -> Target:
        with self._session() as session:
            return TargetService(session, lab=LAB).create(
                caller.principal,
                project_id,
                name=unique_name("target"),
                kind=kind,
                base_url=base_url or f"http://{unique_name('lab')}:5000",
                request_id=None,
            )

    def grant(self, caller: Caller, target: Target, **overrides: object) -> ScopeGrant:
        with self._session() as session:
            return ScopeGrantService(session, lab=LAB).request(
                caller.principal,
                target.id,
                lab_grant_request(target, **overrides),
                now=datetime.now(UTC),
                request_id=None,
            )

    def approve(self, admin: Caller, grant: ScopeGrant) -> ScopeGrant:
        with self._session() as session:
            return ScopeGrantService(session, lab=LAB).approve(
                admin.principal, grant.id, note="已核對 lab", now=datetime.now(UTC), request_id=None
            )

    def spec(self, caller: Caller, target: Target, content: bytes = MINIMAL_SPEC) -> ApiSpec:
        """以 JSON 上傳一份規格（預設是只有一個 GET 的最小文件）。"""
        with self._session() as session:
            return ApiSpecService(session).upload(
                caller.principal,
                target.id,
                SpecUpload(spec_format=SpecFormat.JSON, content=content),
                request_id=None,
            )

    def auth_profile(
        self,
        caller: Caller,
        target: Target,
        *,
        role_label: str = "standard_user",
        value: str = "t1",
    ) -> AuthProfile:
        """以 bearer 建立一個認證設定（preflight 是 VAmPI 的 GET /me），secret 以測試的金鑰加密。"""
        with self._session() as session:
            return AuthProfileService(session, cipher=shared_cipher()).create(
                caller.principal,
                target.id,
                ProfileInput(
                    name=unique_name("profile"),
                    role_label=role_label,
                    type=AuthType.BEARER,
                    header_name=None,
                    secret=SecretValue(value),
                    preflight=VAMPI_ME,
                ),
                request_id=None,
            )

    def scannable(self, world: "World", *, secret: str = DEFAULT_SECRET) -> Scannable:
        """A 的 operator 建立 target、規格與 profile；admin 核准 grant。"""
        target = self.target(world.operator_a, world.project_a.id)
        grant = self.grant(world.operator_a, target, paths=SCANNABLE_PATHS)
        return Scannable(
            target=target,
            grant=self.approve(world.admin, grant),
            spec=self.spec(world.operator_a, target),
            profile=self.auth_profile(world.operator_a, target, value=secret),
        )

    def scan(
        self, caller: Caller, scannable: Scannable, *, key: str | None = None, **overrides: object
    ) -> Scan:
        """以 service 建立 scan（預設是 fake 引擎、api_active_lab）並 commit。"""
        with self._session() as session:
            return ScanService(session, lab=LAB).create(
                caller.principal,
                scannable.request(**overrides),
                idempotency_key=key if key is not None else uuid4().hex,
                clock=lambda: datetime.now(UTC),
                request_id=None,
            )

    def query(self, statement: str, **params: object) -> Sequence[Row[Any]]:
        """以應用程式角色直接查詢（測試用：查證 DB 實際存了什麼）。"""
        with self._session() as session:
            return session.execute(text(statement), params).all()

    def execute(self, statement: str, **params: object) -> None:
        """以應用程式角色直接修改並 commit（測試用：模擬過期等不易經 API 產生的狀態）。"""
        with self._session() as session:
            session.execute(text(statement), params)


def lab_grant_request(target: Target, **overrides: object) -> GrantRequest:
    """target 的申請內容：預設只允許 GET /users/v1、lab 內的一個 IP，期限 7 天。"""
    fields: dict[str, object] = {
        "origins": (str(target.origin),),
        "ips": (LAB_IP,),
        "paths": ("/users/v1",),
        "allow_all_paths": False,
        "excluded_paths": (),
        "methods": ("GET",),
        "authorization_reference": "LAB-ASSET-001",
        "valid_until": datetime.now(UTC) + timedelta(days=7),
    }
    fields.update(overrides)
    return GrantRequest(**fields)  # type: ignore[arg-type]


def _caller(issued: IssuedApiKey) -> Caller:
    return Caller(principal=Principal.of(issued.key), key=issued.value)
