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
from secscan.core.config import DEFAULT_LAB_CIDR
from secscan.grants.domain.lifecycle import ScopeGrant
from secscan.grants.domain.scope import GrantRequest
from secscan.grants.service import ScopeGrantService
from secscan.projects.domain import Project
from secscan.projects.service import ProjectService
from secscan.specs.domain.documents import SpecFormat
from secscan.specs.domain.model import ApiSpec, SpecUpload
from secscan.specs.service import ApiSpecService
from secscan.targets.domain import LabNetwork, Target, TargetKind
from secscan.targets.service import TargetService

MINIMAL_SPEC = (
    b'{"openapi": "3.0.3", "info": {"title": "t", "version": "1"},'
    b' "paths": {"/items/{id}": {"get": {"operationId": "getItem"}}}}'
)
# 與 API（create_app 的預設設定）相同的 lab 網段。
LAB = LabNetwork(DEFAULT_LAB_CIDR)
LAB_IP = "10.89.7.20"


@dataclass(frozen=True)
class Caller:
    """持有一把平台 key 的呼叫者；key 不出現在 repr。"""

    principal: Principal
    key: str = field(repr=False)

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.key}"}


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

    def target(self, caller: Caller, project_id: UUID, base_url: str | None = None) -> Target:
        with self._session() as session:
            return TargetService(session, lab=LAB).create(
                caller.principal,
                project_id,
                name=unique_name("target"),
                kind=TargetKind.API,
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
