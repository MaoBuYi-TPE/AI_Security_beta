"""報告內容與人工複測摘錄的加密與到期清除（CONT-01、RET-01；docs/DECISIONS.md §30.4、§30.5）。

- DB 中只有密文：報告與摘錄的位元組都沒有明文的 canary；下載與 triage-events 解密並核對之後才送出。
- 搬到別的位置（另一段摘錄）的密文解不開：回 500、不送出內容。
- 到期才清除：報告 → content_purged_at、下載回 410、不計入配額、重送 Idempotency-Key 仍回原本的
  metadata；摘錄 → tombstone（content 是 null），事件與「恰好兩段」不變。
到期以 DB 的時鐘判斷：測試以過去的時間產生報告（worker 的 clock）與摘錄（service 的 clock）。
"""

from collections.abc import Iterator
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import ResolutionBasis
from secscan.main import create_app
from secscan.reports import service as report_service
from secscan.triage.domain.attestation import Attestation
from secscan.triage.service import TriageCommand, TriageService
from secscan.worker.retention import ContentRetention
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.report_support import report_worker
from tests.integration.triage_support import Scenario, db_now, eligible, scenario
from tests.secret_support import shared_content_cipher

pytestmark = pytest.mark.integration

CANARY = "canary-sealed-content-4f1b"


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


def _create(
    client: TestClient, scan: object, headers: dict[str, str], key: str | None = None
) -> Any:
    return client.post(
        f"/api/v1/scans/{scan}/reports",
        json={"format": "json"},
        headers={**headers, "Idempotency-Key": key or uuid4().hex},
    )


def _drain(engine: Engine, *, days_ago: int = 0) -> int:
    generated = datetime.now().astimezone() - timedelta(days=days_ago)
    worker = report_worker(
        sessionmaker(engine, expire_on_commit=False), owner="worker-c", clock=lambda: generated
    )
    return worker.drain()


def _purge(engine: Engine) -> tuple[int, int]:
    purged = ContentRetention(sessionmaker(engine, expire_on_commit=False)).purge()
    return purged.reports, purged.excerpts


def _resolve(
    engine: Engine, seed: Seeder, world: World, item: Scenario, *, days_ago: int = 0
) -> None:
    """以 service 人工複測 resolve SQLi（摘錄含 canary；clock 決定摘錄的期限）。"""
    comparison = eligible(engine, item)
    now = db_now(seed)
    proof = Attestation(
        performed_at=now,
        performed_by="operator",
        procedure="複測",
        result="not_reproduced",
        auth_role="anonymous",
        request_excerpt=f"GET /search?q=1 HTTP/1.1\nHost: {item.host}\n",
        response_excerpt=f"HTTP/1.1 200\n\n[{CANARY}]",
    )
    with sessionmaker(engine).begin() as session:
        service = TriageService(
            session, cipher=shared_content_cipher(), clock=lambda: now - timedelta(days=days_ago)
        )
        service.change(
            world.operator_a.principal,
            item.sqli,
            TriageCommand(expected_version=0, reason="確認", triage=TriageState.CONFIRMED),
            request_id=None,
        )
        service.change(
            world.operator_a.principal,
            item.sqli,
            TriageCommand(
                expected_version=1,
                reason="人工複測確認修補後的行為",
                lifecycle=LifecycleState.RESOLVED,
                basis=ResolutionBasis.MANUAL_RETEST,
                comparison_id=comparison,
                attestation=proof,
            ),
            request_id=None,
        )


def _events(client: TestClient, world: World, finding: UUID) -> Any:
    response = client.get(
        f"/api/v1/findings/{finding}/triage-events", headers=world.operator_a.headers
    )
    return response


# --- 只有密文（CONT-01）--------------------------------------------------------------------------


def test_the_database_only_holds_ciphertext(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    _resolve(queue_engine, queue_seed, world, item)
    created = _create(client, item.baseline, world.operator_a.headers).json()["data"]
    assert _drain(queue_engine) == 1

    downloaded = client.get(
        f"/api/v1/reports/{created['id']}/download", headers=world.operator_a.headers
    )
    assert downloaded.status_code == 200
    [content] = queue_seed.query(
        "SELECT content FROM report_contents WHERE report_id = :id", id=created["id"]
    )
    assert bytes(content.content).startswith(b"gAAAAA")
    assert downloaded.content not in bytes(content.content)
    excerpts = queue_seed.query(
        "SELECT sealed_content FROM finding_triage_excerpts WHERE finding_id = :id", id=item.sqli
    )
    assert len(excerpts) == 2
    for row in excerpts:
        assert CANARY.encode() not in bytes(row.sealed_content)
        assert bytes(row.sealed_content).startswith(b"gAAAAA")
    events = _events(client, world, item.sqli).json()["data"]
    response_excerpt = next(e for e in events[1]["excerpts"] if e["kind"] == "response")
    assert CANARY in response_excerpt["content"]
    assert response_excerpt["purged_at"] is None
    assert response_excerpt["expires_at"].endswith("Z")


def test_an_excerpt_moved_to_another_place_is_never_sent(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    _resolve(queue_engine, queue_seed, world, item)
    queue_seed.execute(
        "UPDATE finding_triage_excerpts SET sealed_content = ("
        "SELECT sealed_content FROM finding_triage_excerpts "
        "WHERE finding_id = :id AND kind = 'response') "
        "WHERE finding_id = :id AND kind = 'request'",
        id=item.sqli,
    )

    response = _events(client, world, item.sqli)

    assert response.status_code == 500
    assert CANARY not in response.text
    viewer = client.get(
        f"/api/v1/findings/{item.sqli}/triage-events", headers=world.viewer_a.headers
    )
    assert viewer.status_code == 200
    assert viewer.json()["data"][1]["excerpts"] is None


# --- 到期清除（RET-01）---------------------------------------------------------------------------


def test_reports_are_purged_only_after_they_expire(
    client: TestClient, queue_engine: Engine, world: World, item: Scenario
) -> None:
    headers = world.operator_a.headers
    key = uuid4().hex
    old = _create(client, item.baseline, headers, key).json()["data"]
    assert _drain(queue_engine, days_ago=31) == 1
    fresh = _create(client, item.baseline, headers).json()["data"]
    assert _drain(queue_engine) == 1

    assert _purge(queue_engine) == (1, 0)

    expired = client.get(f"/api/v1/reports/{old['id']}/download", headers=headers)
    assert expired.status_code == 410
    assert expired.json()["error"]["code"] == "REPORT_EXPIRED"
    metadata = client.get(f"/api/v1/reports/{old['id']}", headers=headers).json()["data"]
    assert metadata["status"] == "succeeded"
    assert metadata["sha256"] is not None
    assert metadata["content_purged_at"] is not None
    assert metadata["content_purged_at"] >= metadata["expires_at"]
    kept = client.get(f"/api/v1/reports/{fresh['id']}/download", headers=headers)
    assert kept.status_code == 200
    replay = _create(client, item.baseline, headers, key)
    assert replay.json()["data"]["id"] == old["id"]
    assert replay.json()["data"]["content_purged_at"] is not None
    assert _purge(queue_engine) == (0, 0)


def test_purged_reports_do_not_count_against_the_quota(
    client: TestClient,
    queue_engine: Engine,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(report_service, "MAX_PER_SCAN", 1)
    headers = world.operator_a.headers
    assert _create(client, item.baseline, headers).status_code == 202
    assert _drain(queue_engine, days_ago=31) == 1
    over = _create(client, item.baseline, headers)
    assert over.json()["error"]["code"] == "QUOTA_EXCEEDED"

    _purge(queue_engine)

    assert _create(client, item.baseline, headers).status_code == 202


def test_excerpts_become_tombstones_after_they_expire(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    _resolve(queue_engine, queue_seed, world, item, days_ago=31)

    assert _purge(queue_engine) == (0, 2)

    rows = queue_seed.query(
        "SELECT sealed_content, purged_at, expires_at FROM finding_triage_excerpts "
        "WHERE finding_id = :id",
        id=item.sqli,
    )
    assert len(rows) == 2
    assert all(row.sealed_content is None and row.purged_at >= row.expires_at for row in rows)
    events = _events(client, world, item.sqli).json()["data"]
    assert len(events) == 2
    assert [excerpt["content"] for excerpt in events[1]["excerpts"]] == [None, None]
    assert all(excerpt["purged_at"] for excerpt in events[1]["excerpts"])
    assert events[1]["evidence"]["attestation"]["response_excerpt_sha256"]


def test_unexpired_excerpts_are_kept(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    _resolve(queue_engine, queue_seed, world, item, days_ago=29)

    assert _purge(queue_engine) == (0, 0)

    events = _events(client, world, item.sqli).json()["data"]
    assert all(excerpt["content"] for excerpt in events[1]["excerpts"])
