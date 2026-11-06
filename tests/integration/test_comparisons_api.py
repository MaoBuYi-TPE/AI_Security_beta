"""T22 比較 API：不可變快照、角色與跨 project 授權、保守差異分類。"""

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.api_keys.domain import Role
from secscan.findings.service import FindingLinker
from secscan.main import create_app
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.domain.observation import ObservationInput
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.finding_support import ZAP_CORS, ZAP_SQLI, parsed_run, web_scan, web_target

pytestmark = pytest.mark.integration
URL = "/api/v1/scan-comparisons"


@pytest.fixture
def client(queue_database: ProvisionedDatabase) -> Iterator[TestClient]:
    with TestClient(create_app(queue_database.app_settings())) as opened:
        yield opened


@pytest.fixture
def world(queue_seed: Seeder) -> World:
    return queue_seed.world()


def pair(
    engine: Engine,
    seed: Seeder,
    world: World,
    before: Sequence[ObservationInput] = (ZAP_SQLI, ZAP_CORS),
    after: Sequence[ObservationInput] = (ZAP_CORS,),
) -> dict[str, str]:
    sessions = sessionmaker(engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    target, grant = web_target(seed, world)
    ids = []
    for observations in (before, after):
        scan = web_scan(seed, world, target, grant, (ScanEngine.ZAP,))
        run = parsed_run(queue, ScanEngine.ZAP, observations)
        FindingLinker(sessions).link(run)
        queue.advance(run, RunStatus.SUCCEEDED)
        ids.append(str(scan))
    return {"baseline_scan_id": ids[0], "current_scan_id": ids[1]}


def test_create_replay_read_and_filtered_pagination(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
) -> None:
    body = pair(queue_engine, queue_seed, world)
    created = client.post(URL, json=body, headers=world.operator_a.headers)
    assert created.status_code == 201, created.text
    data = created.json()["data"]
    assert data["counts"] == {
        "new": 0,
        "persistent": 1,
        "not_observed": 0,
        "inconclusive": 1,
        "not_comparable": 0,
    }
    assert data["algorithm_version"] == 1
    assert "不等於已修補" in data["notice"]
    replay = client.post(URL, json=body, headers=world.operator_a.headers)
    assert replay.status_code == 200
    assert replay.json()["data"] == data
    path = f"{URL}/{data['id']}"
    assert client.get(path, headers=world.viewer_a.headers).json()["data"] == data
    page = client.get(f"{path}/findings?limit=1", headers=world.viewer_a.headers)
    assert page.status_code == 200
    assert page.json()["meta"] == {"page": 1, "limit": 1, "total": 2}
    second = client.get(f"{path}/findings?page=2&limit=1", headers=world.viewer_a.headers)
    assert second.json()["data"][0]["finding_id"] != page.json()["data"][0]["finding_id"]
    filtered = client.get(
        f"{path}/findings?classification=inconclusive", headers=world.viewer_a.headers
    )
    assert filtered.json()["meta"]["total"] == 1
    [item] = filtered.json()["data"]
    assert item["evidence"]["baseline_observed"] is True
    assert item["evidence"]["current_observed"] is False
    assert item["evidence"]["other_scan_coverage"]["sources"][0]["rule_completed"] is False
    assert "path" not in str(item["evidence"])
    [audit] = queue_seed.query(
        "SELECT count(*) AS n FROM audit_events WHERE action = 'scan_comparison.create'"
    )
    assert audit.n == 1


def test_both_scan_ids_are_authorized_before_role_or_comparability(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
) -> None:
    body = pair(queue_engine, queue_seed, world)
    other_world = queue_seed.world()
    other = pair(queue_engine, queue_seed, other_world)
    for caller in (world.viewer_a, world.operator_a):
        for foreign in (other["baseline_scan_id"], str(uuid4())):
            result = client.post(
                URL, json={**body, "current_scan_id": foreign}, headers=caller.headers
            )
            assert result.status_code == 404
    assert client.post(URL, json=body, headers=world.viewer_a.headers).status_code == 403
    created = client.post(URL, json=body, headers=world.admin.headers).json()["data"]
    outsider = queue_seed.member(world.admin, world.project_b.id, Role.OPERATOR)
    for suffix in ("", "/findings"):
        assert (
            client.get(f"{URL}/{created['id']}{suffix}", headers=outsider.headers).status_code
            == 404
        )
        assert (
            client.get(f"{URL}/{uuid4()}{suffix}", headers=world.admin.headers).status_code == 404
        )


def test_invalid_pair_and_nonterminal_scan_have_distinct_errors(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
) -> None:
    body = pair(queue_engine, queue_seed, world)
    same = {**body, "current_scan_id": body["baseline_scan_id"]}
    reversed_pair = {
        "baseline_scan_id": body["current_scan_id"],
        "current_scan_id": body["baseline_scan_id"],
    }
    for value in (same, reversed_pair):
        response = client.post(URL, json=value, headers=world.operator_a.headers)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "INVALID_REQUEST"
    different = pair(queue_engine, queue_seed, world)
    response = client.post(
        URL,
        json={**body, "current_scan_id": different["current_scan_id"]},
        headers=world.operator_a.headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "TARGET_MISMATCH"
    [row] = queue_seed.query(
        "SELECT target_id, scope_grant_id FROM scans WHERE id = :id",
        id=UUID(body["current_scan_id"]),
    )
    # 以既有 target/grant 建立下一次 scan，不執行 runner。
    from secscan.scans.domain.catalog import ScanProfile
    from secscan.scans.domain.request import BudgetRequest, ScanRequest

    queued = queue_seed.create_scan(
        world.operator_a,
        ScanRequest(
            target_id=row.target_id,
            scope_grant_id=row.scope_grant_id,
            api_spec_id=None,
            auth_profile_id=None,
            profile=ScanProfile.WEB_ACTIVE_LAB,
            engines=(ScanEngine.ZAP,),
            budget=BudgetRequest(),
        ),
    )
    response = client.post(
        URL, json={**body, "current_scan_id": str(queued.id)}, headers=world.operator_a.headers
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SCAN_NOT_TERMINAL"


def test_zero_observations_return_an_empty_snapshot_not_a_success_claim(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
) -> None:
    body = pair(queue_engine, queue_seed, world, (), ())
    response = client.post(URL, json=body, headers=world.operator_a.headers)
    assert response.status_code == 201
    data = response.json()["data"]
    assert set(data["counts"].values()) == {0}
    assert "engine_definitions_mismatch_or_unknown" in data["reasons"]
    page = client.get(f"{URL}/{data['id']}/findings", headers=world.viewer_a.headers).json()
    assert page["data"] == []
    assert page["meta"]["total"] == 0


@pytest.mark.parametrize("bound", ["rows", "evidence"])
def test_excessive_inputs_roll_back_instead_of_storing_a_partial_comparison(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    bound: str,
) -> None:
    from secscan.comparisons import observations, repository

    body = pair(queue_engine, queue_seed, world)
    if bound == "rows":
        monkeypatch.setattr(observations, "MAX_COMPARISON_INPUT_ROWS", 1)
    else:
        monkeypatch.setattr(repository, "MAX_EVIDENCE_BYTES", 1)
    response = client.post(URL, json=body, headers=world.operator_a.headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "QUOTA_EXCEEDED"
    assert queue_seed.query("SELECT id FROM scan_comparisons") == []
    assert queue_seed.query("SELECT finding_id FROM scan_comparison_findings") == []


@pytest.mark.parametrize("query", ["limit=101", "page=0", "classification=resolved"])
def test_invalid_pagination_and_classification_are_rejected(
    client: TestClient,
    world: World,
    query: str,
) -> None:
    result = client.get(f"{URL}/{uuid4()}/findings?{query}", headers=world.viewer_a.headers)
    assert result.status_code == 422


def test_client_cannot_submit_its_own_evidence_or_classification(
    client: TestClient,
    world: World,
) -> None:
    response = client.post(
        URL,
        headers=world.operator_a.headers,
        json={
            "baseline_scan_id": str(uuid4()),
            "current_scan_id": str(uuid4()),
            "classification": "not_observed",
            "rule_completed": True,
        },
    )
    assert response.status_code == 422
    assert client.post(URL, json={}).status_code == 401


def test_corroborated_findings_that_change_group_require_manual_review(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
) -> None:
    from tests.integration.finding_support import NUCLEI_XCTO, ZAP_XCTO

    sessions = sessionmaker(queue_engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    target, grant = web_target(queue_seed, world)
    ids = []
    for zap_observations in ((ZAP_XCTO,), ()):
        ids.append(web_scan(queue_seed, world, target, grant, (ScanEngine.ZAP, ScanEngine.NUCLEI)))
        for engine, observations in (
            (ScanEngine.ZAP, zap_observations),
            (ScanEngine.NUCLEI, (NUCLEI_XCTO,)),
        ):
            lease = parsed_run(queue, engine, observations)
            FindingLinker(sessions).link(lease)
            queue.advance(lease, RunStatus.SUCCEEDED)
    response = client.post(
        URL,
        headers=world.operator_a.headers,
        json={
            "baseline_scan_id": str(ids[0]),
            "current_scan_id": str(ids[1]),
        },
    )
    assert response.status_code == 201, response.text
    snapshot = response.json()["data"]
    assert snapshot["manual_review_required"]
    findings = client.get(
        f"{URL}/{snapshot['id']}/findings", headers=world.viewer_a.headers
    ).json()["data"]
    assert len(findings) == 2
    for finding in findings:
        assert finding["classification"] == "inconclusive"
        assert finding["manual_review_required"]
        assert finding["reasons"] == ["reidentified"]
