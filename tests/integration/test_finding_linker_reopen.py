"""T21 自動重開：resolve 之後，較新的 scan 以相同 fingerprint 與 mapping 再觀察到才重開。

R1 至 R4 的組合由 domain 測試涵蓋；這裡走真實的佇列、linker 與 API。
"""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.findings import service as finding_service
from secscan.findings.service import FindingLinker
from secscan.main import create_app
from secscan.scans.domain.lifecycle import RunStatus
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.finding_support import ZAP_CORS, ZAP_SQLI, ZAP_XCTO
from tests.integration.triage_support import (
    CONFIRM,
    Scenario,
    attestation,
    db_now,
    eligible,
    queue,
    resolve_body,
    run_scan,
    scenario,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


@pytest.fixture
def item(client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    """SQLi 已經以人工複測標成 resolved（版本 2）。"""
    built = scenario(queue_engine, queue_seed, world)
    comparison = eligible(queue_engine, built)
    url = f"/api/v1/findings/{built.sqli}/triage"
    assert client.patch(url, json=CONFIRM, headers=world.operator_a.headers).status_code == 200
    body = resolve_body(comparison, attestation(built, db_now(queue_seed)))
    resolved = client.patch(url, json=body, headers=world.operator_a.headers)
    assert resolved.status_code == 200, resolved.text
    return built


def state(seed: Seeder, item: Scenario) -> tuple[str, int, object, object]:
    [row] = seed.query(
        "SELECT lifecycle_state, triage_version, resolved_scan_position, resolved_link_count "
        "FROM findings WHERE id = :id",
        id=item.sqli,
    )
    return (
        row.lifecycle_state,
        row.triage_version,
        row.resolved_scan_position,
        row.resolved_link_count,
    )


@pytest.mark.parametrize("status", [RunStatus.SUCCEEDED, RunStatus.FAILED, RunStatus.TIMED_OUT])
def test_a_newer_positive_observation_reopens_even_from_incomplete_runs(
    queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario, status: RunStatus
) -> None:
    resolved = state(queue_seed, item)
    assert resolved[:2] == ("resolved", 2)
    assert resolved[2] is not None
    scan, lease = run_scan(
        queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_SQLI,), status=status
    )
    assert state(queue_seed, item) == ("reopened", 3, None, None)
    [event] = queue_seed.query(
        "SELECT * FROM finding_triage_events WHERE finding_id = :id AND sequence = 3", id=item.sqli
    )
    assert (event.actor_kind, event.actor_key_id, event.reason_code) == (
        "system",
        None,
        "auto_reopen_new_observation",
    )
    assert (event.run_id, event.scan_id) == (lease.run_id, scan)
    assert (event.previous_lifecycle_state, event.lifecycle_state) == ("resolved", "reopened")
    assert event.triage_state == event.previous_triage_state == "confirmed"
    assert len(event.evidence["observation_ids"]) == 1
    assert event.evidence["links"] == {"first": 2, "last": 2}
    [audit] = queue_seed.query(
        "SELECT actor_key_id, redacted_changes AS changes FROM audit_events "
        "WHERE action = 'finding.reopen' AND object_id = :id",
        id=item.sqli,
    )
    assert audit.actor_key_id is None
    assert audit.changes["lifecycle"] == {"from": "resolved", "to": "reopened"}


def test_a_run_with_a_new_finding_still_reopens_the_resolved_one(
    queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    """同一個 run 也產生全新的 finding（沒有被鎖住的既有 finding）：只重開已 resolved 的那個。"""
    run_scan(queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_XCTO, ZAP_SQLI))
    assert state(queue_seed, item)[:2] == ("reopened", 3)
    [new] = queue_seed.query(
        "SELECT lifecycle_state, triage_version FROM findings "
        "WHERE target_id = :target AND rule_group = 'x-content-type-options-missing'",
        target=item.target.id,
    )
    assert (new.lifecycle_state, new.triage_version) == ("open", 0)


def test_a_scan_without_the_finding_never_reopens_or_closes(
    queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    before = state(queue_seed, item)
    run_scan(queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_CORS,))
    run_scan(
        queue_engine,
        queue_seed,
        world,
        item.target,
        item.grant_id,
        (),
        status=RunStatus.FAILED,
    )
    assert state(queue_seed, item) == before


def test_linker_retries_do_not_reopen_twice(
    queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    _, lease = run_scan(
        queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_SQLI,), link=False
    )
    linker = FindingLinker(sessionmaker(queue_engine, expire_on_commit=False))
    assert linker.link(lease) == 1
    assert linker.link(lease) == 0
    queue(queue_engine).advance(lease, RunStatus.SUCCEEDED)
    [row] = queue_seed.query(
        "SELECT count(*) AS n FROM finding_triage_events WHERE finding_id = :id AND "
        "actor_kind = 'system'",
        id=item.sqli,
    )
    assert row.n == 1


def test_a_different_mapping_does_not_reopen_but_requires_review(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other = ("mapping-next", "f" * 64)
    monkeypatch.setattr(finding_service, "mapping_identity", lambda: other)
    run_scan(queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_SQLI,))
    assert state(queue_seed, item)[:2] == ("resolved", 2)
    detail = client.get(f"/api/v1/findings/{item.sqli}", headers=world.viewer_a.headers).json()
    data = detail["data"]
    assert data["lifecycle_state"] == "resolved"
    assert data["resolution_review_required"] is True
    assert data["resolution_review_reasons"] == [
        "observed_after_resolution_mapping_differs",
        "mapping_changed_since_resolution",
    ]


def test_mapping_change_without_new_observation_is_flagged(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    item: Scenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(finding_service, "mapping_identity", lambda: ("mapping-next", "e" * 64))
    run_scan(queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_CORS,))
    data = client.get(f"/api/v1/findings/{item.sqli}", headers=world.viewer_a.headers).json()
    assert data["data"]["resolution_review_reasons"] == ["mapping_changed_since_resolution"]


def test_a_reopened_finding_can_be_resolved_again_with_new_evidence(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    reopen_scan, _ = run_scan(
        queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_SQLI, ZAP_CORS)
    )
    fixed_scan, _ = run_scan(
        queue_engine, queue_seed, world, item.target, item.grant_id, (ZAP_CORS,)
    )
    again = Scenario(item.target, item.grant_id, reopen_scan, fixed_scan, item.sqli, item.cors)
    comparison = eligible(queue_engine, again)
    body = resolve_body(comparison, attestation(again, db_now(queue_seed)), version=3)
    resolved = client.patch(
        f"/api/v1/findings/{item.sqli}/triage", json=body, headers=world.operator_a.headers
    )
    assert resolved.status_code == 200, resolved.text
    assert state(queue_seed, item)[:2] == ("resolved", 4)
    events = queue_seed.query(
        "SELECT sequence, previous_lifecycle_state, lifecycle_state, actor_kind "
        "FROM finding_triage_events WHERE finding_id = :id ORDER BY sequence",
        id=item.sqli,
    )
    assert [(e.previous_lifecycle_state, e.lifecycle_state, e.actor_kind) for e in events] == [
        ("open", "open", "key"),
        ("open", "resolved", "key"),
        ("resolved", "reopened", "system"),
        ("reopened", "resolved", "key"),
    ]
