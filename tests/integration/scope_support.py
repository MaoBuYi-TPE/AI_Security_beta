"""target 與 grant 的 service 測試共用：在 db_session 的交易中準備 project 與各角色的身分。"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Network
from uuid import UUID, uuid4

import pytest
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal, Role
from secscan.api_keys.service import ApiKeyService
from secscan.core.errors import AppError
from secscan.grants.domain.scope import GrantRequest
from secscan.projects.service import ProjectService
from secscan.targets.domain import LabNetwork

LAB = LabNetwork(IPv4Network("10.89.7.0/24"))
VAMPI = "http://vampi-vuln:5000"


@dataclass(frozen=True)
class Members:
    """一位 admin、兩個 project（A、B），以及 A 的 operator、viewer 與 B 的 operator。"""

    admin: Principal
    project_a: UUID
    project_b: UUID
    operator_a: Principal
    viewer_a: Principal
    operator_b: Principal


def members(session: Session, now: datetime) -> Members:
    keys = ApiKeyService(session)
    admin = Principal.of(keys.issue_admin_key(name="admin", expires_at=None, now=now).key)
    projects = ProjectService(session)
    project_a = projects.create(admin, name=f"lab-a-{uuid4().hex[:8]}", request_id=None).id
    project_b = projects.create(admin, name=f"lab-b-{uuid4().hex[:8]}", request_id=None).id

    def member(project_id: UUID, role: Role) -> Principal:
        issued = keys.issue_project_key(
            admin,
            project_id,
            name=role.value,
            role=role,
            expires_at=None,
            now=now,
            request_id=None,
        )
        return Principal.of(issued.key)

    return Members(
        admin=admin,
        project_a=project_a,
        project_b=project_b,
        operator_a=member(project_a, Role.OPERATOR),
        viewer_a=member(project_a, Role.VIEWER),
        operator_b=member(project_b, Role.OPERATOR),
    )


def grant_request(now: datetime, **overrides: object) -> GrantRequest:
    fields: dict[str, object] = {
        "origins": (VAMPI,),
        "ips": ("10.89.7.20",),
        "paths": ("/users/v1",),
        "allow_all_paths": False,
        "excluded_paths": (),
        "methods": ("GET",),
        "authorization_reference": "LAB-ASSET-001",
        "valid_until": now + timedelta(days=7),
    }
    fields.update(overrides)
    return GrantRequest(**fields)  # type: ignore[arg-type]


def app_error(call: Callable[[], object]) -> AppError:
    with pytest.raises(AppError) as caught:
        call()
    return caught.value


def same_response(first: AppError, second: AppError) -> bool:
    """對外看起來完全相同的錯誤（狀態碼、錯誤碼、訊息、header）。"""
    return (first.status_code, first.code, first.message, first.headers) == (
        second.status_code,
        second.code,
        second.message,
        second.headers,
    )
