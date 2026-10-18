"""API 整合測試的資料準備：直接用 service 建立 project 與 key 並 commit，不經 HTTP。"""

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Engine, Row, text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import IssuedApiKey, Principal, Role
from secscan.api_keys.service import ApiKeyService
from secscan.projects.domain import Project
from secscan.projects.service import ProjectService


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

    def query(self, statement: str, **params: object) -> Sequence[Row[Any]]:
        """以應用程式角色直接查詢（測試用：查證 DB 實際存了什麼）。"""
        with self._session() as session:
            return session.execute(text(statement), params).all()

    def execute(self, statement: str, **params: object) -> None:
        """以應用程式角色直接修改並 commit（測試用：模擬過期等不易經 API 產生的狀態）。"""
        with self._session() as session:
            session.execute(text(statement), params)


def _caller(issued: IssuedApiKey) -> Caller:
    return Caller(principal=Principal.of(issued.key), key=issued.value)
