"""引擎子預算（T31；docs/DECISIONS.md §29）：API、Idempotency-Key 與佇列的配額。

- BUDGET-01：沒有 engine_budgets 時，配額和之前相同（剩下的全部）。
- BUDGET-02、BUDGET-10：有指定時，每個 run 的配額取較小值；guard 的請求數上限與容器的時間上限
  都等於分到的配額。
- BUDGET-03：ZAP 沒用完的份額不轉給 Nuclei。
- BUDGET-04：建立時的檢查不合 → 422 INVALID_REQUEST，不寫入任何東西。
- BUDGET-05：同一個 key、不同的子預算 → 409；順序不同 → 同一個 scan。
- BUDGET-07：API 列出每個 run 的上限。
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, Row
from sqlalchemy.orm import sessionmaker

from secscan.scans.domain.allocation import EngineBudgetRequest
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.catalog import ScanProfile
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus
from secscan.scans.domain.model import Lease, Scan
from secscan.scans.domain.request import BudgetRequest, ScanRequest
from secscan.scans.queue import RunUsage, ScanQueue
from secscan.scans.repository import ScanRepository
from secscan.targets.domain import Target
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.finding_support import web_target

pytestmark = pytest.mark.integration

SCANS = "/api/v1/scans"
OWNER = "runner-budget-1"
IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32
ZAP, NUCLEI = ScanEngine.ZAP, ScanEngine.NUCLEI
TOTAL = {"requests_per_second": 2, "max_requests": 1_200, "max_duration_seconds": 600}
SPLIT = [
    {"engine": "zap", "max_requests": 760, "max_duration_seconds": 380},
    {"engine": "nuclei", "max_requests": 440, "max_duration_seconds": 220},
]


def _now() -> datetime:
    return datetime.now(UTC)


def _body(target: Target, grant_id: UUID, **overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "target_id": str(target.id),
        "scope_grant_id": str(grant_id),
        "profile": "web_active_lab",
        "engines": ["zap", "nuclei"],
        "budget": TOTAL,
        "engine_budgets": SPLIT,
    }
    body.update(overrides)
    return body


def _post(client: TestClient, world: World, body: dict[str, object], key: str | None = None) -> Any:
    headers = {**world.operator_a.headers, "Idempotency-Key": key or str(uuid4())}
    return client.post(SCANS, json=body, headers=headers)


def _scan_count(seed: Seeder, target: Target) -> int:
    [row] = seed.query("SELECT count(*) AS n FROM scans WHERE target_id = :id", id=target.id)
    return int(row.n)


def _caps(seed: Seeder, scan_id: UUID) -> list[tuple[str, int | None, int | None]]:
    rows = seed.query(
        "SELECT engine, budget_max_requests, budget_max_duration_seconds FROM scanner_runs "
        "WHERE scan_id = :id ORDER BY sequence",
        id=scan_id,
    )
    return [(row.engine, row.budget_max_requests, row.budget_max_duration_seconds) for row in rows]


# --- API：建立、檢查與顯示（BUDGET-04、BUDGET-07）-----------------------------------------


def test_engine_budgets_are_frozen_on_each_run_and_shown(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(seed, world)

    response = _post(api_client, world, _body(target, grant_id))

    assert response.status_code == 202
    data = response.json()["data"]
    assert [(run["engine"], run["budget"]) for run in data["engines"]] == [
        ("zap", {"max_requests": 760, "max_duration_seconds": 380}),
        ("nuclei", {"max_requests": 440, "max_duration_seconds": 220}),
    ]
    assert data["budget"]["max_requests"] == 1_200
    assert _caps(seed, UUID(data["id"])) == [("zap", 760, 380), ("nuclei", 440, 220)]


def test_the_audit_record_keeps_the_allocation(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(seed, world)
    scan_id = _post(api_client, world, _body(target, grant_id)).json()["data"]["id"]

    [row] = seed.query(
        "SELECT redacted_changes FROM audit_events WHERE action = 'scan.create' "
        "AND object_id = :id",
        id=UUID(scan_id),
    )

    assert row.redacted_changes["engine_budgets"] == {
        "zap": {"max_requests": 760, "max_duration_seconds": 380},
        "nuclei": {"max_requests": 440, "max_duration_seconds": 220},
    }


def test_without_engine_budgets_no_run_has_a_cap(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(seed, world)
    body = _body(target, grant_id)
    del body["engine_budgets"]

    response = _post(api_client, world, body)

    assert response.status_code == 202
    assert [run["budget"] for run in response.json()["data"]["engines"]] == [None, None]
    assert _caps(seed, UUID(response.json()["data"]["id"])) == [
        ("zap", None, None),
        ("nuclei", None, None),
    ]


def _share(engine: str, requests: int, seconds: int) -> dict[str, object]:
    return {"engine": engine, "max_requests": requests, "max_duration_seconds": seconds}


@pytest.mark.parametrize(
    ("overrides", "problem"),
    [
        ({"engines": ["zap"], "engine_budgets": SPLIT[:1]}, "兩個以上"),
        ({"engine_budgets": SPLIT[:1]}, "每個引擎"),
        ({"engine_budgets": [SPLIT[0], SPLIT[0]]}, "重複"),
        ({"engine_budgets": [*SPLIT, _share("fake", 1, 1)]}, "每個引擎"),
        ({"engine_budgets": [SPLIT[0], _share("nuclei", 441, 220)]}, "合計"),
        ({"engine_budgets": [SPLIT[0], _share("nuclei", 440, 221)]}, "合計"),
        ({"engine_budgets": [_share("zap", 760, 119), SPLIT[1]]}, "zap"),
        ({"engine_budgets": [_share("zap", 239, 380), SPLIT[1]]}, "zap"),
        ({"engine_budgets": [SPLIT[0], _share("nuclei", 440, 59)]}, "nuclei"),
        ({"engine_budgets": [SPLIT[0], _share("nuclei", 0, 220)]}, "max_requests"),
        ({"engine_budgets": [SPLIT[0], _share("nuclei", -5, 220)]}, "max_requests"),
    ],
)
def test_an_invalid_allocation_is_rejected_without_writing(
    api_client: TestClient, seed: Seeder, world: World, overrides: dict[str, object], problem: str
) -> None:
    target, grant_id = web_target(seed, world)

    response = _post(api_client, world, _body(target, grant_id, **overrides))

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "INVALID_REQUEST"
    assert problem in error["message"]
    assert _scan_count(seed, target) == 0


@pytest.mark.parametrize(
    "engine_budgets",
    [
        [],
        [{**SPLIT[0], "max_requests": True}, SPLIT[1]],
        [{**SPLIT[0], "max_requests": "760"}, SPLIT[1]],
        [{**SPLIT[0], "extra": 1}, SPLIT[1]],
        [{"engine": "zap", "max_requests": 760}, SPLIT[1]],
        [{**SPLIT[0], "engine": "sqlmap"}, SPLIT[1]],
    ],
)
def test_a_malformed_allocation_is_rejected_by_the_schema(
    api_client: TestClient, seed: Seeder, world: World, engine_budgets: object
) -> None:
    target, grant_id = web_target(seed, world)

    response = _post(api_client, world, _body(target, grant_id, engine_budgets=engine_budgets))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert _scan_count(seed, target) == 0


def test_the_shares_are_checked_against_the_resolved_scan_budget(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    """省略 budget 時用 grant 的值（5,000 次、1,500 秒）：份額依它檢查。"""
    target, grant_id = web_target(seed, world)
    body = _body(
        target,
        grant_id,
        budget={},
        engine_budgets=[_share("zap", 3_000, 900), _share("nuclei", 2_000, 600)],
    )

    response = _post(api_client, world, body)

    assert response.status_code == 202


# --- Idempotency-Key（BUDGET-05）-----------------------------------------------------------


def test_the_same_allocation_in_another_order_replays_the_same_scan(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    target, grant_id = web_target(seed, world)
    key = str(uuid4())
    first = _post(api_client, world, _body(target, grant_id), key)

    again = _post(
        api_client, world, _body(target, grant_id, engine_budgets=list(reversed(SPLIT))), key
    )

    # 還沒結束的 scan 重送仍是 202（contract §17.1）。
    assert (first.status_code, again.status_code) == (202, 202)
    assert again.json()["data"] == first.json()["data"]


@pytest.mark.parametrize(
    "changed",
    [
        [SPLIT[0], _share("nuclei", 400, 220)],
        None,
    ],
)
def test_the_same_key_with_another_allocation_is_a_conflict(
    api_client: TestClient, seed: Seeder, world: World, changed: object
) -> None:
    target, grant_id = web_target(seed, world)
    key = str(uuid4())
    _post(api_client, world, _body(target, grant_id), key)
    body = _body(target, grant_id, engine_budgets=changed)
    if changed is None:
        del body["engine_budgets"]

    response = _post(api_client, world, body, key)

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


# --- 佇列：每個 run 的配額（BUDGET-01、02、03、10）-----------------------------------------


@pytest.fixture
def queue(queue_engine: Engine) -> ScanQueue:
    return ScanQueue(sessionmaker(queue_engine, expire_on_commit=False), lab=LAB, clock=_now)


def _web_scan(
    seed: Seeder, *, split: tuple[EngineBudgetRequest, ...] | None, **budget: int
) -> Scan:
    world = seed.world()
    target, grant_id = web_target(seed, world)
    request = ScanRequest(
        target_id=target.id,
        scope_grant_id=grant_id,
        api_spec_id=None,
        auth_profile_id=None,
        profile=ScanProfile.WEB_ACTIVE_LAB,
        engines=(ZAP, NUCLEI),
        budget=BudgetRequest(**(budget or TOTAL)),
        engine_budgets=split,
    )
    return seed.create_scan(world.operator_a, request)


QUEUE_SPLIT = (
    EngineBudgetRequest(ZAP, max_requests=760, max_duration_seconds=380),
    EngineBudgetRequest(NUCLEI, max_requests=440, max_duration_seconds=220),
)


def _claim(queue: ScanQueue, engine: ScanEngine) -> Lease:
    lease = queue.claim(OWNER, frozenset({engine}))
    assert lease is not None
    assert lease.engine is engine
    return lease


def _allotment(seed: Seeder, run_id: UUID) -> Row[Any]:
    [row] = seed.query(
        "SELECT requests_allotted, seconds_allotted FROM scanner_runs WHERE id = :id", id=run_id
    )
    return row


def _finish_zap(queue: ScanQueue, *, sent: int, seconds: int) -> None:
    """ZAP 開始、guard 記下用量之後結束（被自己的時間上限停止）。"""
    lease = _claim(queue, ZAP)
    queue.prepare_launch(lease, image_ref=IMAGE)
    queue.record_usage(
        lease, RunUsage(requests_sent=sent, requests_denied=0, traffic_seconds=seconds)
    )
    queue.advance(lease, RunStatus.TIMED_OUT, error_code=RunErrorCode.ENGINE_TIMEOUT)


def test_without_a_cap_a_run_is_allotted_all_that_remains(
    queue: ScanQueue, queue_seed: Seeder
) -> None:
    _web_scan(queue_seed, split=None)
    lease = _claim(queue, ZAP)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.max_duration_seconds == 600
    assert launch.egress is not None
    assert launch.egress.budget.max_requests == 1_200
    row = _allotment(queue_seed, lease.run_id)
    assert (row.requests_allotted, row.seconds_allotted) == (1_200, 600)


def test_a_capped_run_is_allotted_its_cap_and_the_guard_enforces_it(
    queue: ScanQueue, queue_seed: Seeder
) -> None:
    _web_scan(queue_seed, split=QUEUE_SPLIT)
    lease = _claim(queue, ZAP)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.max_duration_seconds == 380
    assert launch.egress is not None
    assert launch.egress.budget.max_requests == 760
    assert launch.egress.budget.requests_per_second == 2
    row = _allotment(queue_seed, lease.run_id)
    assert (row.requests_allotted, row.seconds_allotted) == (760, 380)


def test_an_unused_share_is_forfeited_not_passed_on(queue: ScanQueue, queue_seed: Seeder) -> None:
    """ZAP 只用了 100 個請求、50 秒：Nuclei 仍只拿自己的上限，不是剩下的 1,100／550。"""
    _web_scan(queue_seed, split=QUEUE_SPLIT)
    _finish_zap(queue, sent=100, seconds=50)
    lease = _claim(queue, NUCLEI)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.max_duration_seconds == 220
    assert launch.egress is not None
    assert launch.egress.budget.max_requests == 440
    row = _allotment(queue_seed, lease.run_id)
    assert (row.requests_allotted, row.seconds_allotted) == (440, 220)


def test_without_caps_the_next_engine_gets_what_the_first_left(
    queue: ScanQueue, queue_seed: Seeder
) -> None:
    """對照：沒有子預算時，Nuclei 拿到剩下的全部（T12 起的行為不變）。"""
    _web_scan(queue_seed, split=None)
    _finish_zap(queue, sent=100, seconds=50)
    lease = _claim(queue, NUCLEI)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.max_duration_seconds == 550
    row = _allotment(queue_seed, lease.run_id)
    assert (row.requests_allotted, row.seconds_allotted) == (1_100, 550)


def test_the_scan_total_still_binds_a_capped_run(queue: ScanQueue, queue_seed: Seeder) -> None:
    """ZAP 被硬性停止時的清理秒數（400 秒，超過自己的 380）會讓 Nuclei 少拿：200，不是 220。"""
    _web_scan(queue_seed, split=QUEUE_SPLIT)
    _finish_zap(queue, sent=760, seconds=400)
    lease = _claim(queue, NUCLEI)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.max_duration_seconds == 200
    row = _allotment(queue_seed, lease.run_id)
    assert (row.requests_allotted, row.seconds_allotted) == (440, 200)


def test_an_exhausted_total_fails_the_capped_run_before_it_starts(
    queue: ScanQueue, queue_seed: Seeder
) -> None:
    _web_scan(queue_seed, split=QUEUE_SPLIT)
    _finish_zap(queue, sent=760, seconds=600)
    lease = _claim(queue, NUCLEI)

    launch = queue.prepare_launch(lease, image_ref=IMAGE)

    assert launch.progress.run_status is RunStatus.FAILED
    assert launch.egress is None
    [row] = queue_seed.query(
        "SELECT error_code, requests_allotted, seconds_allotted FROM scanner_runs WHERE id = :id",
        id=lease.run_id,
    )
    assert (row.error_code, row.requests_allotted, row.seconds_allotted) == (
        "BUDGET_EXHAUSTED",
        None,
        None,
    )


def test_the_scan_reads_back_the_cap_and_the_allotment(
    queue: ScanQueue, queue_seed: Seeder, queue_engine: Engine
) -> None:
    scan = _web_scan(queue_seed, split=QUEUE_SPLIT)
    lease = _claim(queue, ZAP)
    queue.prepare_launch(lease, image_ref=IMAGE)

    with sessionmaker(queue_engine)() as session:
        stored = ScanRepository(session).get(scan.id)
    assert stored is not None
    [zap, nuclei] = stored.runs

    assert zap.budget is not None
    assert (zap.budget.max_requests, zap.budget.max_duration_seconds) == (760, 380)
    assert (zap.requests_allotted, zap.seconds_allotted) == (760, 380)
    assert nuclei.budget is not None
    assert (nuclei.requests_allotted, nuclei.seconds_allotted) == (None, None)
