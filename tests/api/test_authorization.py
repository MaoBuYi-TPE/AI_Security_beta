"""權限規則經依賴與錯誤處理串到 HTTP 回應（docs/DECISIONS.md §9.2）。

T05 還沒有 operator 可寫的端點（T06 起才有 target 等資源），所以用測試專用的小 app 驗證
PROJECT_WRITE：viewer 403、operator 允許、其他 project 一律 404。不連 DB：current_principal
以 dependency override 換成固定的呼叫者。
"""

import logging
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secscan.api_keys.access import authorize
from secscan.api_keys.dependencies import CurrentPrincipal, current_principal
from secscan.api_keys.domain import Permission, Principal, Role
from secscan.core.errors import register_error_handlers
from secscan.core.request_id import REQUEST_ID_HEADER, RequestIdMiddleware

OWN = UUID("00000000-0000-4000-8000-0000000000a1")
OTHER = UUID("00000000-0000-4000-8000-0000000000b2")


def _client(caller: Principal) -> TestClient:
    app = FastAPI()
    app.add_middleware(RequestIdMiddleware)
    register_error_handlers(app)

    @app.post("/projects/{project_id}/things", status_code=201)
    def create_thing(project_id: UUID, principal: CurrentPrincipal) -> dict[str, str]:
        authorize(principal, Permission.PROJECT_WRITE, project_id)
        return {"status": "created"}

    app.dependency_overrides[current_principal] = lambda: caller
    return TestClient(app)


def _caller(role: Role) -> Principal:
    return Principal(
        key_id=uuid4(), role=role, project_id=None if role is Role.PLATFORM_ADMIN else OWN
    )


@pytest.mark.parametrize(
    ("role", "project_id", "status", "code"),
    [
        (Role.VIEWER, OWN, 403, "ROLE_NOT_ALLOWED"),
        (Role.VIEWER, OTHER, 404, "RESOURCE_NOT_FOUND"),
        (Role.OPERATOR, OWN, 201, None),
        (Role.OPERATOR, OTHER, 404, "RESOURCE_NOT_FOUND"),
        (Role.PLATFORM_ADMIN, OTHER, 201, None),
    ],
)
def test_project_write_permission(
    role: Role, project_id: UUID, status: int, code: str | None
) -> None:
    with _client(_caller(role)) as client:
        response = client.post(f"/projects/{project_id}/things")

    assert response.status_code == status
    body = response.json()
    if code is None:
        assert body == {"status": "created"}
    else:
        assert body["error"]["code"] == code


def test_viewer_write_attempt_on_other_project_looks_like_missing_route() -> None:
    with _client(_caller(Role.VIEWER)) as client:
        hidden = client.post(f"/projects/{OTHER}/things").json()["error"]
        missing = client.post("/no-such-route").json()["error"]

    hidden.pop("request_id")
    missing.pop("request_id")
    assert hidden == missing


def test_denials_are_logged_with_who_what_and_request_id(caplog: pytest.LogCaptureFixture) -> None:
    """被拒絕的存取要留下伺服器端紀錄（例如有人逐一試其他 project 的 UUID），但不記 body。"""
    caller = _caller(Role.VIEWER)

    with caplog.at_level(logging.INFO, logger="secscan.api_keys.access"), _client(caller) as client:
        hidden = client.post(f"/projects/{OTHER}/things")
        forbidden = client.post(f"/projects/{OWN}/things")

    lines = [record.getMessage() for record in caplog.records]
    for response, decision, project_id in (
        (hidden, "not_found", OTHER),
        (forbidden, "forbidden", OWN),
    ):
        assert any(
            f"decision={decision}" in line
            and f"key_id={caller.key_id}" in line
            and "role=viewer permission=project:write" in line
            and f"project_id={project_id}" in line
            and f"request_id={response.headers[REQUEST_ID_HEADER]}" in line
            for line in lines
        ), lines


def test_allowed_access_is_not_logged(caplog: pytest.LogCaptureFixture) -> None:
    with (
        caplog.at_level(logging.INFO, logger="secscan.api_keys.access"),
        _client(_caller(Role.OPERATOR)) as client,
    ):
        client.post(f"/projects/{OWN}/things")

    assert caplog.records == []
