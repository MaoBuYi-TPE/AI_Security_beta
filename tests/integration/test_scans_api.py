"""scan 的 API（docs/API_CONTRACT.md §17、docs/DECISIONS.md §13）。

建立、Idempotency-Key、查詢、事件輪詢與取消。需要 runner 的情境（取消執行中的 scan、完整走一輪）
用自己的資料庫與 API（queue_client）：runner 會認領任何排隊中的 fake run。
"""

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.api_keys.domain import Role
from secscan.audit.service import AuditTrail
from secscan.main import create_app
from secscan.runner.fake import FakeRunner
from secscan.scanners.domain.fake import FakeScript
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.queue import ScanQueue
from secscan.targets.domain import TargetKind
from tests.integration.api_support import LAB, Caller, Scannable, Seeder, World
from tests.integration.database import ProvisionedDatabase

pytestmark = pytest.mark.integration

SCANS = "/api/v1/scans"
TARGET_SECRET = "canary-target-secret-0002"


def _body(scannable: Scannable, **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "target_id": str(scannable.target.id),
        "scope_grant_id": str(scannable.grant.id),
        "api_spec_id": str(scannable.spec.id),
        # 預設是匿名的 scan；綁定 auth profile 時最前面多一個 preflight 的 run（§16.5）。
        "auth_profile_id": None,
        "profile": "api_active_lab",
        "engines": ["fake"],
    }
    body.update(overrides)
    return body


def _headers(caller: Caller, key: str | None = None) -> dict[str, str]:
    headers = dict(caller.headers)
    if key is not None:
        headers["Idempotency-Key"] = key
    return headers


def _create(
    client: TestClient,
    caller: Caller,
    scannable: Scannable,
    *,
    key: str | None = None,
    **body: object,
) -> Any:
    return client.post(
        SCANS,
        json=_body(scannable, **body),
        headers=_headers(caller, key if key is not None else str(uuid4())),
    )


@pytest.fixture
def scannable(seed: Seeder, world: World) -> Scannable:
    return seed.scannable(world)


# --- 建立 ----------------------------------------------------------------------------------


def test_creating_a_scan_returns_202_with_the_full_scan(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    response = _create(
        api_client, world.operator_a, scannable, auth_profile_id=str(scannable.profile.id)
    )

    assert response.status_code == 202
    body = response.json()
    assert (body["success"], body["error"], body["meta"]) == (True, None, None)
    scan = body["data"]
    assert UUID(scan["id"])
    assert scan["project_id"] == str(world.project_a.id)
    assert scan["target_id"] == str(scannable.target.id)
    assert scan["target_origin"] == str(scannable.target.origin)
    assert scan["status"] == "queued"
    assert scan["profile"] == "api_active_lab"
    assert scan["scope_grant"] == {"id": str(scannable.grant.id), "version": 1}
    assert scan["api_spec"] == {"id": str(scannable.spec.id), "version": 1}
    assert scan["auth"] == {
        "profile_id": str(scannable.profile.id),
        "version": 1,
        "role_label": "standard_user",
        "preflight": None,  # preflight 的 run 還在排隊（§16.5）
    }
    assert scan["auth_role"] == "standard_user"
    assert scan["budget"] == {
        "requests_per_second": 2,
        "max_requests": 5_000,
        "max_duration_seconds": 1_500,
    }
    preflight, run = scan["engines"]
    assert [(item["engine"], item["sequence"]) for item in (preflight, run)] == [
        ("preflight", 1),  # 綁定 auth profile（§16.5）
        ("fake", 2),
    ]
    assert {key: run[key] for key in ("status", "error_code")} == {
        "status": "queued",
        "error_code": None,
    }
    assert (run["started_at"], run["finished_at"]) == (None, None)
    assert scan["coverage"] == {
        "eligible_operations": 1,
        "ineligible_operations": 0,
        "observed_operations": None,
        "authenticated_operations": None,
        "coverage_measured": False,
        "limitations": ["TRAFFIC_TELEMETRY_UNAVAILABLE", "AUTHENTICATION_NOT_VERIFIED"],
    }
    assert scan["budget_usage"] == {
        "requests_sent": 0,
        "requests_denied": 0,
        "traffic_duration_seconds": 0,
    }
    assert (scan["fixture"], scan["results_complete"]) == (True, False)
    assert (scan["cancel_requested_at"], scan["finished_at"]) == (None, None)
    assert scan["created_by_key_id"] == str(world.operator_a.principal.key_id)


def test_an_anonymous_scan_reports_the_anonymous_role(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    response = _create(api_client, world.operator_a, scannable, auth_profile_id=None)

    assert response.status_code == 202
    assert (response.json()["data"]["auth"], response.json()["data"]["auth_role"]) == (
        None,
        "anonymous",
    )


def test_a_web_scan_has_no_operation_counts(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target = seed.target(world.operator_a, world.project_a.id, kind=TargetKind.WEB)
    grant = seed.approve(world.admin, seed.grant(world.operator_a, target))
    body = {
        "target_id": str(target.id),
        "scope_grant_id": str(grant.id),
        "profile": "web_active_lab",
        "engines": ["fake"],
    }

    response = api_client.post(SCANS, json=body, headers=_headers(world.operator_a, str(uuid4())))

    assert response.status_code == 202
    scan = response.json()["data"]
    assert (scan["api_spec"], scan["auth"], scan["auth_role"]) == (None, None, "anonymous")
    assert scan["coverage"] == {
        "eligible_operations": None,
        "ineligible_operations": None,
        "observed_operations": None,
        "authenticated_operations": None,
        "coverage_measured": False,
        "limitations": ["NO_API_SPEC", "TRAFFIC_TELEMETRY_UNAVAILABLE"],
    }


def test_replaying_the_same_key_returns_the_same_scan(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    key = str(uuid4())
    first = _create(api_client, world.operator_a, scannable, key=key)
    # 加上雙引號的寫法（Structured Field 的 String）是同一個 key。
    again = _create(api_client, world.operator_a, scannable, key=f'"{key}"')

    assert (first.status_code, again.status_code) == (202, 202)
    assert again.json()["data"] == first.json()["data"]


def test_replaying_a_finished_scan_returns_200(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    key = str(uuid4())
    scan_id = _create(api_client, world.operator_a, scannable, key=key).json()["data"]["id"]
    api_client.post(f"{SCANS}/{scan_id}/cancel", headers=world.operator_a.headers)

    again = _create(api_client, world.operator_a, scannable, key=key)

    assert again.status_code == 200
    assert (again.json()["data"]["id"], again.json()["data"]["status"]) == (scan_id, "cancelled")


def test_the_same_key_with_other_content_is_a_409(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    key = str(uuid4())
    _create(api_client, world.operator_a, scannable, key=key)

    response = _create(
        api_client, world.operator_a, scannable, key=key, budget={"max_requests": 10}
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


@pytest.mark.parametrize(
    "key",
    [None, b"short", b"canary-key-with spaces-0001", "canary-key-0001-é".encode()],
    ids=["missing", "short", "space", "non-ascii"],
)
def test_a_missing_or_malformed_key_is_a_400(
    api_client: TestClient, world: World, scannable: Scannable, key: bytes | None
) -> None:
    headers = [(b"Authorization", world.operator_a.headers["Authorization"].encode())]
    if key is not None:
        headers.append((b"Idempotency-Key", key))

    response = api_client.post(SCANS, json=_body(scannable), headers=headers)

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert "canary" not in response.text


def test_a_repeated_key_header_is_a_400(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    key = str(uuid4())
    headers = [
        ("Authorization", world.operator_a.headers["Authorization"]),
        ("Idempotency-Key", key),
        ("Idempotency-Key", key),
    ]

    response = api_client.post(SCANS, json=_body(scannable), headers=headers)

    assert response.status_code == 400


def test_schema_errors_come_before_the_key(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    """未知的引擎是 schema 的錯誤（422），比 Idempotency-Key（400）先判斷。"""
    response = api_client.post(
        SCANS, json=_body(scannable, engines=["burp"]), headers=world.operator_a.headers
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_an_engine_without_an_adapter_is_a_422(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    response = _create(api_client, world.operator_a, scannable, engines=["nuclei"])

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "ENGINE_UNSUPPORTED"


def test_a_second_scan_of_a_busy_target_is_a_409(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    _create(api_client, world.operator_a, scannable)

    response = _create(api_client, world.operator_a, scannable)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "TARGET_BUSY"


def test_viewers_cannot_create_or_cancel_scans(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    created = _create(api_client, world.viewer_a, scannable)
    scan_id = _create(api_client, world.operator_a, scannable).json()["data"]["id"]
    cancelled = api_client.post(f"{SCANS}/{scan_id}/cancel", headers=world.viewer_a.headers)

    assert (created.status_code, cancelled.status_code) == (403, 403)
    assert created.json()["error"]["code"] == "ROLE_NOT_ALLOWED"


def test_a_failure_while_creating_leaves_nothing_behind(
    api_client: TestClient,
    seed: Seeder,
    world: World,
    scannable: Scannable,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan、run、operation 與事件已經寫入之後才失敗：同一個 transaction 全部回滾。"""

    def broken_audit(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("audit 寫入失敗")

    monkeypatch.setattr(AuditTrail, "record", broken_audit)
    key = str(uuid4())

    with pytest.raises(RuntimeError, match="audit"):
        _create(api_client, world.operator_a, scannable, key=key)

    assert seed.query("SELECT id FROM scans WHERE idempotency_key = :key", key=key) == []
    assert seed.query("SELECT id FROM scans WHERE target_id = :id", id=scannable.target.id) == []


# --- 查詢 ----------------------------------------------------------------------------------


def test_a_scan_reads_the_same_as_it_was_created(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    created = _create(api_client, world.operator_a, scannable).json()["data"]

    for caller in (world.operator_a, world.viewer_a, world.admin):
        response = api_client.get(f"{SCANS}/{created['id']}", headers=caller.headers)
        assert response.status_code == 200
        assert response.json()["data"] == created


def test_other_projects_cannot_tell_a_scan_exists(
    api_client: TestClient, seed: Seeder, world: World, scannable: Scannable
) -> None:
    """SEC-16：讀取、看事件、取消別人的 scan，回應與不存在的 id、不存在的路徑完全相同。"""
    scan_id = _create(api_client, world.operator_a, scannable).json()["data"]["id"]
    outsider = seed.member(world.admin, world.project_b.id, Role.OPERATOR)

    def error(method: str, path: str) -> dict[str, str]:
        response = api_client.request(method, path, headers=outsider.headers)
        assert response.status_code == 404
        detail: dict[str, str] = response.json()["error"]
        detail.pop("request_id")
        return detail

    missing = error("GET", "/api/v1/no-such-route")
    for method, path in [
        ("GET", f"{SCANS}/{scan_id}"),
        ("GET", f"{SCANS}/{uuid4()}"),
        ("GET", f"{SCANS}/{scan_id}/events"),
        ("POST", f"{SCANS}/{scan_id}/cancel"),
    ]:
        assert error(method, path) == missing
    listed = api_client.get(
        SCANS, params={"target_id": str(scannable.target.id)}, headers=outsider.headers
    )
    assert (listed.json()["data"], listed.json()["meta"]["total"]) == ([], 0)


def test_creating_with_resources_of_another_project_looks_missing(
    api_client: TestClient, seed: Seeder, world: World, scannable: Scannable
) -> None:
    outsider = seed.member(world.admin, world.project_b.id, Role.OPERATOR)

    response = _create(api_client, outsider, scannable)

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


def test_scans_are_listed_with_filters_and_a_total(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    first = _create(api_client, world.operator_a, scannable).json()["data"]
    api_client.post(f"{SCANS}/{first['id']}/cancel", headers=world.operator_a.headers)
    second = _create(api_client, world.operator_a, scannable).json()["data"]
    target = {"target_id": str(scannable.target.id)}

    listed = api_client.get(SCANS, params=target, headers=world.viewer_a.headers)
    queued = api_client.get(
        SCANS, params={**target, "status": "queued"}, headers=world.viewer_a.headers
    )
    paged = api_client.get(
        SCANS, params={**target, "limit": 1, "page": 2}, headers=world.viewer_a.headers
    )

    assert [scan["id"] for scan in listed.json()["data"]] == [second["id"], first["id"]]
    assert listed.json()["meta"] == {"page": 1, "limit": 25, "total": 2}
    assert [scan["id"] for scan in queued.json()["data"]] == [second["id"]]
    assert [scan["id"] for scan in paged.json()["data"]] == [first["id"]]


@pytest.mark.parametrize(
    "params",
    [
        {"status": "paused"},
        {"target_id": "not-a-uuid"},
        {"created_after": "2026-10-26T08:00:00"},
        # 換算成 UTC 會超出 datetime 的範圍：原本是 500（安全審查發現）
        {"created_after": "9999-12-31T23:00:00-05:00"},
        {"created_before": "0001-01-01T00:30:00+05:00"},
        {"limit": 101},
    ],
    ids=["status", "target", "naive-time", "beyond-max", "before-min", "limit"],
)
def test_invalid_list_filters_are_a_422(
    api_client: TestClient, world: World, params: dict[str, str | int]
) -> None:
    response = api_client.get(SCANS, params=params, headers=world.viewer_a.headers)

    assert response.status_code == 422


# --- 事件與取消 ----------------------------------------------------------------------------


def test_cancelling_a_queued_scan_returns_200_and_is_recorded_once(
    api_client: TestClient, world: World, scannable: Scannable
) -> None:
    scan_id = _create(api_client, world.operator_a, scannable).json()["data"]["id"]

    first = api_client.post(f"{SCANS}/{scan_id}/cancel", headers=world.operator_a.headers)
    again = api_client.post(f"{SCANS}/{scan_id}/cancel", headers=world.operator_a.headers)
    events = api_client.get(f"{SCANS}/{scan_id}/events", headers=world.viewer_a.headers)

    assert (first.status_code, again.status_code) == (200, 200)
    assert first.json()["data"]["status"] == "cancelled"
    assert again.json()["data"] == first.json()["data"]
    assert [event["type"] for event in events.json()["data"]] == [
        "scan.created",
        "scan.cancel_requested",
        "run.status",
        "scan.status",
    ]
    assert events.json()["meta"] is None


@pytest.mark.parametrize(
    "params",
    [{"after_sequence": -1}, {"limit": 0}, {"limit": 101}, {"after_sequence": "x"}],
)
def test_invalid_event_queries_are_a_422(
    api_client: TestClient, world: World, scannable: Scannable, params: dict[str, str | int]
) -> None:
    scan_id = _create(api_client, world.operator_a, scannable).json()["data"]["id"]

    response = api_client.get(
        f"{SCANS}/{scan_id}/events", params=params, headers=world.viewer_a.headers
    )

    assert response.status_code == 422


def test_the_post_documents_the_idempotency_key_header(api_client: TestClient) -> None:
    schema = cast(FastAPI, api_client.app).openapi()

    [parameter] = schema["paths"][SCANS]["post"]["parameters"]
    assert (parameter["name"], parameter["in"], parameter["required"]) == (
        "Idempotency-Key",
        "header",
        True,
    )
    assert set(schema["paths"][SCANS]["post"]["responses"]) >= {"200", "202"}
    # 文件的 pattern 和伺服器的規則一致：引號要成對（安全審查發現）。
    pattern = re.compile(parameter["schema"]["pattern"])
    key = str(uuid4())
    for accepted in (key, f'"{key}"'):
        assert pattern.fullmatch(accepted)
    for rejected in (f'"{key}', f'{key}"', "short"):
        assert pattern.fullmatch(rejected) is None


# --- 用自己的資料庫走完整的流程（runner 會認領任何排隊中的 fake run）--------------------------


@pytest.fixture
def queue_client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as client:
        yield client


def _queue(engine: Engine) -> ScanQueue:
    return ScanQueue(
        sessionmaker(engine, expire_on_commit=False), lab=LAB, clock=lambda: datetime.now(UTC)
    )


def test_a_scan_runs_to_completion_and_its_events_can_be_polled(
    queue_client: TestClient, queue_engine: Engine, queue_seed: Seeder
) -> None:
    world = queue_seed.world()
    scannable = queue_seed.scannable(world)
    scan_id = _create(queue_client, world.operator_a, scannable).json()["data"]["id"]

    FakeRunner(_queue(queue_engine), owner="api-test", script=FakeScript()).run_once()

    scan = queue_client.get(f"{SCANS}/{scan_id}", headers=world.viewer_a.headers).json()["data"]
    assert (scan["status"], scan["results_complete"], scan["fixture"]) == ("completed", True, True)
    assert scan["engines"][0]["status"] == "succeeded"
    assert scan["finished_at"] is not None
    head = queue_client.get(
        f"{SCANS}/{scan_id}/events", params={"limit": 5}, headers=world.viewer_a.headers
    ).json()["data"]
    rest = queue_client.get(
        f"{SCANS}/{scan_id}/events",
        params={"after_sequence": head[-1]["sequence"]},
        headers=world.viewer_a.headers,
    ).json()["data"]
    sequences = [event["sequence"] for event in head + rest]
    assert sequences == list(range(1, 13))
    assert rest[-1]["type"] == "scan.status"
    assert rest[-1]["payload"] == {"status": "completed", "previous_status": "normalizing"}


def test_cancelling_a_running_scan_returns_202_until_the_runner_confirms(
    queue_client: TestClient, queue_engine: Engine, queue_seed: Seeder
) -> None:
    world = queue_seed.world()
    scannable = queue_seed.scannable(world)
    scan_id = _create(queue_client, world.operator_a, scannable).json()["data"]["id"]
    queue = _queue(queue_engine)
    lease = queue.claim("api-test", frozenset({ScanEngine.FAKE}))
    assert lease is not None
    queue.prepare(lease)

    cancelling = queue_client.post(f"{SCANS}/{scan_id}/cancel", headers=world.operator_a.headers)

    assert cancelling.status_code == 202
    assert cancelling.json()["data"]["status"] == "cancelling"
    assert cancelling.json()["data"]["engines"][0]["status"] == "running"
    assert queue.heartbeat(lease).cancel_requested is True
    queue.advance(lease, RunStatus.CANCELLING)
    queue.advance(lease, RunStatus.CANCELLED)
    done = queue_client.get(f"{SCANS}/{scan_id}", headers=world.operator_a.headers)
    assert done.json()["data"]["status"] == "cancelled"


def test_no_secret_or_key_appears_in_scan_responses(
    queue_client: TestClient, queue_engine: Engine, queue_seed: Seeder
) -> None:
    world = queue_seed.world()
    scannable = queue_seed.scannable(world, secret=TARGET_SECRET)
    key = f"canary-idempotency-{uuid4().hex}"
    created = _create(queue_client, world.operator_a, scannable, key=key)
    scan_id = created.json()["data"]["id"]
    FakeRunner(_queue(queue_engine), owner="api-test", script=FakeScript()).run_once()

    responses = [
        created,
        queue_client.get(f"{SCANS}/{scan_id}", headers=world.operator_a.headers),
        queue_client.get(SCANS, headers=world.operator_a.headers),
        queue_client.get(f"{SCANS}/{scan_id}/events", headers=world.operator_a.headers),
        queue_client.get(
            f"/api/v1/projects/{world.project_a.id}/audit-events", headers=world.admin.headers
        ),
    ]
    for response in responses:
        assert response.status_code in (200, 202)
        for canary in (key, world.operator_a.key, TARGET_SECRET):
            assert canary not in response.text
    stored = queue_seed.query(
        "SELECT count(*) AS n FROM scan_events WHERE scan_id = :id AND payload::text LIKE :canary",
        id=scan_id,
        canary=f"%{key}%",
    )
    assert stored[0].n == 0


def test_an_authenticated_scan_reports_its_preflight(
    queue_client: TestClient, queue_engine: Engine, queue_seed: Seeder
) -> None:
    """in-process 的 runner 不送流量：preflight 是 not_executed，認證沒有被證明（§16.5）。"""
    world = queue_seed.world()
    scannable = queue_seed.scannable(world)
    scan_id = _create(
        queue_client, world.operator_a, scannable, auth_profile_id=str(scannable.profile.id)
    ).json()["data"]["id"]

    FakeRunner(_queue(queue_engine), owner="api-test", script=FakeScript()).drain()

    scan = queue_client.get(f"{SCANS}/{scan_id}", headers=world.viewer_a.headers).json()["data"]
    assert scan["status"] == "completed"
    assert [(run["engine"], run["status"]) for run in scan["engines"]] == [
        ("preflight", "succeeded"),
        ("fake", "succeeded"),
    ]
    assert scan["auth"]["preflight"] == "not_executed"
    assert scan["coverage"]["limitations"] == [
        "TRAFFIC_TELEMETRY_UNAVAILABLE",
        "AUTHENTICATION_NOT_VERIFIED",
    ]
    assert scan["budget_usage"]["requests_sent"] == 0
