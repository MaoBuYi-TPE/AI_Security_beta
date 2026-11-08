"""T21 triage API：雙軌的 resolved 證據門檻、權限、稽核，以及比較快照不被覆寫。"""

from collections.abc import Iterator
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.api_keys.domain import Role
from secscan.comparisons.domain.classification import Classification
from secscan.findings.service import FindingLinker
from secscan.main import create_app
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.finding_support import ZAP_SQLI, parsed_run, web_scan
from tests.integration.triage_support import (
    CONFIRM,
    ELIGIBLE_FACTS,
    ELIGIBLE_REASONS,
    PERSISTENT_FACTS,
    Scenario,
    attestation,
    db_now,
    eligible,
    queue,
    resolve_body,
    scenario,
    seal,
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
def item(queue_engine: Engine, queue_seed: Seeder, world: World) -> Scenario:
    return scenario(queue_engine, queue_seed, world)


def patch(client: TestClient, finding: object, body: dict[str, Any], headers: Any) -> Any:
    return client.patch(f"/api/v1/findings/{finding}/triage", json=body, headers=headers)


def confirm(client: TestClient, item: Scenario, world: World) -> None:
    result = patch(client, item.sqli, CONFIRM, world.operator_a.headers)
    assert result.status_code == 200, result.text
    assert result.json()["data"]["triage_version"] == 1


def test_manual_retest_resolves_without_rewriting_the_comparison(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    comparison = eligible(queue_engine, item)
    confirm(client, item, world)
    body = resolve_body(comparison, attestation(item, db_now(queue_seed)))
    resolved = patch(client, item.sqli, body, world.operator_a.headers)
    assert resolved.status_code == 200, resolved.text
    data = resolved.json()["data"]
    assert data["lifecycle_state"] == "resolved"
    assert data["triage_version"] == 2
    assert data["resolution_review_required"] is False
    resolution = data["resolution"]
    assert resolution["basis"] == "manual_retest"
    assert resolution["evidence_provenance"] == "operator_supplied"
    assert resolution["decided_by_role"] == "operator"
    assert "未驗證其真實性" in resolution["notice"]
    assert "平台不提供自動修補驗證" in resolution["notice"]
    attested = resolution["attestation"]
    assert attested["provenance"] == "operator_supplied"
    assert attested["platform_checks"]
    assert "request_excerpt" not in attested
    # 比較快照仍是原本的 inconclusive：人工判定不覆寫平台事實。
    rows = client.get(
        f"/api/v1/scan-comparisons/{comparison}/findings?classification=inconclusive",
        headers=world.viewer_a.headers,
    ).json()["data"]
    assert [row["finding_id"] for row in rows] == [str(item.sqli)]
    events = client.get(
        f"/api/v1/findings/{item.sqli}/triage-events", headers=world.operator_a.headers
    ).json()
    assert events["meta"]["total"] == 2
    first, second = events["data"]
    assert (first["sequence"], first["triage_state"], first["lifecycle_state"]) == (
        1,
        "confirmed",
        "open",
    )
    assert second["basis"] == "manual_retest"
    assert second["evidence_provenance"] == "operator_supplied"
    assert second["actor_kind"] == "key"
    assert {excerpt["kind"] for excerpt in second["excerpts"]} == {"request", "response"}
    viewer = client.get(
        f"/api/v1/findings/{item.sqli}/triage-events", headers=world.viewer_a.headers
    ).json()["data"]
    assert viewer[1]["excerpts"] is None
    assert viewer[1]["evidence"]["attestation"]["request_excerpt_sha256"]
    audits = queue_seed.query(
        "SELECT redacted_changes AS changes FROM audit_events WHERE action = 'finding.triage' "
        "AND object_id = :finding ORDER BY created_at",
        finding=item.sqli,
    )
    assert len(audits) == 2
    changes = audits[1].changes
    assert changes["evidence_provenance"] == "operator_supplied"
    assert changes["lifecycle"] == {"from": "open", "to": "resolved"}
    assert (
        changes["request_excerpt_sha256"]
        == second["evidence"]["attestation"]["request_excerpt_sha256"]
    )
    assert "apple" not in str(changes)
    assert changes["platform_checks"]


def test_rescan_track_needs_a_not_observed_row(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    # algorithm v1 不會產生 not_observed：這裡的列是構造的（走正常的 trigger 封存）。
    rows = {
        item.sqli: (Classification.NOT_OBSERVED, ("coverage_verified",), False, ELIGIBLE_FACTS),
    }
    comparison = seal(queue_engine, item.baseline, item.current, rows)
    confirm(client, item, world)
    body = {
        "expected_version": 1,
        "lifecycle_state": "resolved",
        "reason": "平台複掃三層覆蓋皆成立",
        "basis": "rescan_not_observed",
        "comparison_id": str(comparison),
    }
    resolved = patch(client, item.sqli, body, world.operator_a.headers)
    assert resolved.status_code == 200, resolved.text
    resolution = resolved.json()["data"]["resolution"]
    assert resolution["evidence_provenance"] == "platform_comparison"
    assert resolution["attestation"] is None
    assert "未觀察到不等於已修補" in resolution["notice"]


def evidence_error(result: Any) -> str:
    assert result.status_code == 422, result.text
    error = result.json()["error"]
    assert error["code"] == "RESOLUTION_EVIDENCE_INSUFFICIENT"
    message: str = error["message"]
    return message


def test_insufficient_evidence_is_rejected_with_every_reason(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    comparison = eligible(queue_engine, item)
    confirm(client, item, world)
    now = db_now(queue_seed)
    rescan = resolve_body(comparison, attestation(item, now), basis="rescan_not_observed")
    rescan.pop("attestation")
    assert "not_observed_required" in evidence_error(
        patch(client, item.sqli, rescan, world.operator_a.headers)
    )
    cases = {
        "host_mismatch": attestation(
            item, now, request_excerpt="GET /search?q=1 HTTP/1.1\nHost: other:1\n"
        ),
        "request_line_mismatch": attestation(
            item, now, request_excerpt=f"GET /other?q=1 HTTP/1.1\nHost: {item.host}\n"
        ),
        "parameter_missing": attestation(
            item, now, request_excerpt=f"GET /search HTTP/1.1\nHost: {item.host}\n"
        ),
        "result_not_accepted": attestation(item, now, result="reproduced"),
        "role_mismatch": attestation(item, now, auth_role="admin"),
        "performed_in_future": attestation(item, now + timedelta(hours=1)),
        "performed_before_last_observation": attestation(item, now - timedelta(days=1)),
        "response_status_line_missing": attestation(item, now, response_excerpt="ok"),
    }
    for reason, body in cases.items():
        message = evidence_error(
            patch(client, item.sqli, resolve_body(comparison, body), world.operator_a.headers)
        )
        assert reason in message, (reason, message)
        assert "apple" not in message
    # persistent 的列（CORS）不能以人工複測 resolve。
    patch(client, item.cors, CONFIRM, world.operator_a.headers)
    body = resolve_body(comparison, attestation(item, now))
    message = evidence_error(patch(client, item.cors, body, world.operator_a.headers))
    assert "inconclusive_required" in message
    assert "current_observed" in message
    # 被拒絕的請求不改任何狀態、不留事件。
    [state] = queue_seed.query(
        "SELECT lifecycle_state, triage_version FROM findings WHERE id = :id", id=item.sqli
    )
    assert (state.lifecycle_state, state.triage_version) == ("open", 1)


def test_ineligible_rows_and_manual_review_are_rejected(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    rows = {
        item.sqli: (
            Classification.INCONCLUSIVE,
            (*ELIGIBLE_REASONS, "engine_incomplete"),
            True,
            ELIGIBLE_FACTS,
        ),
    }
    comparison = seal(queue_engine, item.baseline, item.current, rows)
    confirm(client, item, world)
    body = resolve_body(comparison, attestation(item, db_now(queue_seed)))
    message = evidence_error(patch(client, item.sqli, body, world.operator_a.headers))
    assert "manual_review_required" in message
    assert "reasons_not_eligible" in message


def test_request_shape_state_and_version_rules(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    comparison = eligible(queue_engine, item)
    headers = world.operator_a.headers
    attested = attestation(item, db_now(queue_seed))
    # 未確認就 resolve：409。
    unconfirmed = patch(client, item.sqli, resolve_body(comparison, attested, version=0), headers)
    assert unconfirmed.status_code == 409
    assert unconfirmed.json()["error"]["code"] == "INVALID_STATE_TRANSITION"
    confirm(client, item, world)
    # 版本過期：409，重送成功的請求不會產生第二筆事件。
    stale = patch(client, item.sqli, CONFIRM, headers)
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "VERSION_CONFLICT"
    shape_errors: list[dict[str, Any]] = [
        {**resolve_body(comparison, attested), "attestation": None},
        {key: value for key, value in resolve_body(comparison, attested).items() if key != "basis"},
        {
            **CONFIRM,
            "expected_version": 1,
            "triage_state": "false_positive",
            "basis": "manual_retest",
        },
        {**CONFIRM, "expected_version": 1, "triage_state": "confirmed"},
        {
            **CONFIRM,
            "expected_version": 1,
            "triage_state": "false_positive",
            "lifecycle_state": "resolved",
        },
        {**CONFIRM, "expected_version": 1, "reason": "esc\x1b"},
        # 遮罩之後超過 2000 個字元：422，不是 DB 的 CHECK 造成的 500。
        {
            **CONFIRM,
            "expected_version": 1,
            "triage_state": "false_positive",
            "reason": "password=x " * 181,
        },
        {**CONFIRM, "expected_version": 1, "observation_ids": [str(uuid4())]},
        {**resolve_body(comparison, {**attested, "provenance": "platform"})},
        {**resolve_body(comparison, {**attested, "platform_checks": []})},
        {**CONFIRM, "expected_version": 1, "actor_key_id": str(uuid4())},
    ]
    for body in shape_errors:
        result = patch(client, item.sqli, body, headers)
        assert result.status_code == 422, (body, result.text)
    # open → open 是沒有變更（422）；回到 open 的 409 由 domain 測試涵蓋。
    assert (
        patch(
            client,
            item.sqli,
            {**CONFIRM, "expected_version": 1, "lifecycle_state": "open"},
            headers,
        ).status_code
        == 422
    )
    [row] = queue_seed.query(
        "SELECT count(*) AS n FROM finding_triage_events WHERE finding_id = :id", id=item.sqli
    )
    assert row.n == 1


def test_cited_observations_of_the_finding_are_recorded(
    client: TestClient, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    rows = queue_seed.query(
        "SELECT observation_id FROM finding_observations WHERE finding_id = :id "
        "ORDER BY observation_id",
        id=item.sqli,
    )
    cited = [str(row.observation_id) for row in rows]
    assert cited
    # 重複的 id 只記一次，保留第一次出現的順序。
    body = {**CONFIRM, "observation_ids": [*cited, cited[0]]}
    result = patch(client, item.sqli, body, world.operator_a.headers)
    assert result.status_code == 200, result.text
    [event] = queue_seed.query(
        "SELECT evidence FROM finding_triage_events WHERE finding_id = :id", id=item.sqli
    )
    assert event.evidence["observation_ids"] == cited
    # 其他 finding 的觀察不能引用。
    [other] = queue_seed.query(
        "SELECT observation_id FROM finding_observations WHERE finding_id = :id LIMIT 1",
        id=item.cors,
    )
    rejected = patch(
        client,
        item.cors,
        {**CONFIRM, "observation_ids": [cited[0], str(other.observation_id)]},
        world.operator_a.headers,
    )
    assert rejected.status_code == 422, rejected.text


def test_authorization_hides_other_projects_and_requires_a_writer(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    comparison = eligible(queue_engine, item)
    other_world = queue_seed.world()
    other = scenario(queue_engine, queue_seed, other_world)
    other_comparison = eligible(queue_engine, other)
    assert patch(client, item.sqli, CONFIRM, world.viewer_a.headers).status_code == 403
    outsider = queue_seed.member(world.admin, world.project_b.id, Role.OPERATOR)
    missing = client.patch(
        f"/api/v1/findings/{uuid4()}/triage", json=CONFIRM, headers=outsider.headers
    )
    for headers in (outsider.headers, other_world.operator_a.headers):
        for path in ("triage-events",):
            denied = client.get(f"/api/v1/findings/{item.sqli}/{path}", headers=headers)
            assert denied.status_code == 404
        hidden = patch(client, item.sqli, CONFIRM, headers)
        assert hidden.status_code == 404
        assert hidden.json()["error"] == {
            **missing.json()["error"],
            "request_id": hidden.json()["error"]["request_id"],
        }
    assert client.patch(f"/api/v1/findings/{item.sqli}/triage", json=CONFIRM).status_code == 401
    confirm(client, item, world)
    attested = attestation(item, db_now(queue_seed))
    # 引用其他 project 的比較快照：404（與不存在相同）；同 project 但不同 target：422。
    foreign = patch(
        client, item.sqli, resolve_body(other_comparison, attested), world.operator_a.headers
    )
    assert foreign.status_code == 404
    assert (
        patch(
            client, item.sqli, resolve_body(uuid4(), attested), world.operator_a.headers
        ).status_code
        == 404
    )
    sibling = scenario(queue_engine, queue_seed, world)
    sibling_comparison = eligible(queue_engine, sibling)
    mismatch = patch(
        client, item.sqli, resolve_body(sibling_comparison, attested), world.operator_a.headers
    )
    assert mismatch.status_code == 422
    assert mismatch.json()["error"]["code"] == "TARGET_MISMATCH"
    assert (
        patch(
            client, item.sqli, resolve_body(comparison, attested), world.operator_a.headers
        ).status_code
        == 200
    )


def test_target_busy_and_new_observations_block_resolution(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    comparison = eligible(queue_engine, item)
    confirm(client, item, world)
    attested = attestation(item, db_now(queue_seed))
    queued = web_scan(queue_seed, world, item.target, item.grant_id, (ScanEngine.ZAP,))
    busy = patch(client, item.sqli, resolve_body(comparison, attested), world.operator_a.headers)
    assert busy.status_code == 409
    assert busy.json()["error"]["code"] == "TARGET_BUSY"
    # 進行中的 scan 結束時又觀察到同一個問題：比較之後的新有效陽性觀察，不能 resolve（條件 3）。
    lease = parsed_run(queue(queue_engine), ScanEngine.ZAP, (ZAP_SQLI,))
    assert lease.scan_id == queued
    FindingLinker(sessionmaker(queue_engine, expire_on_commit=False)).link(lease)
    queue(queue_engine).advance(lease, RunStatus.SUCCEEDED)
    later = resolve_body(comparison, attestation(item, db_now(queue_seed)))
    message = evidence_error(patch(client, item.sqli, later, world.operator_a.headers))
    assert "observed_after_comparison" in message


def test_finding_list_filters_by_lifecycle_and_exposes_the_version(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    comparison = eligible(queue_engine, item)
    confirm(client, item, world)
    body = resolve_body(comparison, attestation(item, db_now(queue_seed)))
    assert patch(client, item.sqli, body, world.operator_a.headers).status_code == 200
    listed = client.get(
        f"/api/v1/scans/{item.baseline}/findings?lifecycle_state=resolved",
        headers=world.viewer_a.headers,
    ).json()["data"]
    assert [finding["id"] for finding in listed] == [str(item.sqli)]
    assert listed[0]["triage_version"] == 2
    assert listed[0]["resolution_review_required"] is False
    detail = client.get(f"/api/v1/findings/{item.sqli}", headers=world.viewer_a.headers).json()
    assert detail["data"]["distinct_paths"] == 1
    assert detail["data"]["resolution"]["basis"] == "manual_retest"
    unresolved = client.get(f"/api/v1/findings/{item.cors}", headers=world.viewer_a.headers).json()
    assert unresolved["data"]["resolution"] is None
    assert PERSISTENT_FACTS.current_observed is True
