"""GET /api/v1/scans/{id}/observations 與 GET /scans/{id} 的結果（docs/DECISIONS.md §19.10）。

列的內容以 SQL 寫入：解析的流程在 test_worker_zap.py，這裡只驗證 API。跨 project 與不存在的一樣回
404（SEC-16）；只有遮罩後的欄位，沒有 artifact 的路徑或報告的內容。
"""

import json
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from secscan.api_keys.domain import Role
from secscan.scans.domain.catalog import Engine as ScanEngine
from tests.integration.api_support import Caller, Scannable, Seeder, World

pytestmark = pytest.mark.integration

SCANS = "/api/v1/scans"
INSERT = (
    "INSERT INTO observations (scanner_run_id, scan_id, ordinal, source_event_id, source_index, "
    "source_rule, rule_variant, title, raw_severity, severity_label, raw_confidence, "
    "confidence_label, cwe_id, wasc_id, method, path, query, parameter, parameter_location, "
    "attack, evidence, other_info, auth_role, parser_version) VALUES (:run, :scan, :ordinal, "
    ":event, :ordinal, '10038', '10038-1', :title, '2', 'Medium', '3', 'High', 693, 15, 'GET', "
    ":path, 'q=1', 'q', 'query', 'attack-value', 'evidence-value', 'other-value', 'anonymous', "
    "'zap-traditional-json/1')"
)


def _runs(seed: Seeder, scan_id: UUID) -> dict[str, UUID]:
    rows = seed.query("SELECT id, engine FROM scanner_runs WHERE scan_id = :id", id=scan_id)
    return {row.engine: row.id for row in rows}


def _observe(seed: Seeder, scan_id: UUID, run_id: UUID, *ordinals: int) -> None:
    for ordinal in ordinals:
        seed.execute(
            INSERT,
            run=run_id,
            scan=scan_id,
            ordinal=ordinal,
            event=f"{ordinal:064x}",
            title=f"title {ordinal}",
            path=f"/p/{ordinal}",
        )


def _authenticated_scan(seed: Seeder, world: World) -> tuple[UUID, dict[str, UUID]]:
    """preflight 與 zap 兩個 run。"""
    scannable: Scannable = seed.scannable(world)
    scan = seed.scan(
        world.operator_a,
        scannable,
        engines=(ScanEngine.ZAP,),
        auth_profile_id=scannable.profile.id,
    )
    return scan.id, _runs(seed, scan.id)


def _list(client: TestClient, caller: Caller, scan_id: object, query: str = "") -> Any:
    return client.get(f"{SCANS}/{scan_id}/observations{query}", headers=caller.headers)


def test_observations_are_listed_with_the_masked_fields(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan_id, runs = _authenticated_scan(seed, world)
    _observe(seed, scan_id, runs["zap"], 1)

    response = _list(api_client, world.viewer_a, scan_id)

    assert response.status_code == 200
    body = response.json()
    assert body["meta"] == {"page": 1, "limit": 25, "total": 1}
    [item] = body["data"]
    assert UUID(item.pop("id"))
    assert item.pop("created_at").endswith("Z")
    assert item == {
        "scan_id": str(scan_id),
        "scanner_run_id": str(runs["zap"]),
        "engine": "zap",
        "ordinal": 1,
        "source_rule": "10038",
        "rule_variant": "10038-1",
        "title": "title 1",
        "raw_severity": "2",
        "severity_label": "Medium",
        "raw_confidence": "3",
        "confidence_label": "High",
        "cwe_id": 693,
        "wasc_id": 15,
        "method": "GET",
        "path": "/p/1",
        "query": "q=1",
        "parameter": "q",
        "parameter_location": "query",
        "attack": "attack-value",
        "evidence": "evidence-value",
        "other_info": "other-value",
        "auth_role": "anonymous",
        "parser_version": "zap-traditional-json/1",
    }


def test_observations_follow_the_runs_and_the_ordinals(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan_id, runs = _authenticated_scan(seed, world)
    _observe(seed, scan_id, runs["zap"], 2, 1)
    _observe(seed, scan_id, runs["preflight"], 1)

    body = _list(api_client, world.viewer_a, scan_id).json()

    assert [(item["engine"], item["ordinal"]) for item in body["data"]] == [
        ("preflight", 1),
        ("zap", 1),
        ("zap", 2),
    ]


def test_observations_can_be_filtered_by_engine(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan_id, runs = _authenticated_scan(seed, world)
    _observe(seed, scan_id, runs["zap"], 1, 2)
    _observe(seed, scan_id, runs["preflight"], 1)

    body = _list(api_client, world.viewer_a, scan_id, "?engine=zap").json()

    assert body["meta"]["total"] == 2
    assert {item["engine"] for item in body["data"]} == {"zap"}


def test_an_unknown_engine_is_a_422(api_client: TestClient, seed: Seeder, world: World) -> None:
    scan_id, _ = _authenticated_scan(seed, world)

    assert _list(api_client, world.viewer_a, scan_id, "?engine=other").status_code == 422


def test_observations_are_paged(api_client: TestClient, seed: Seeder, world: World) -> None:
    scan_id, runs = _authenticated_scan(seed, world)
    _observe(seed, scan_id, runs["zap"], 1, 2, 3)

    body = _list(api_client, world.viewer_a, scan_id, "?page=2&limit=2").json()

    assert body["meta"] == {"page": 2, "limit": 2, "total": 3}
    assert [item["ordinal"] for item in body["data"]] == [3]


def test_the_limit_has_a_ceiling(api_client: TestClient, seed: Seeder, world: World) -> None:
    scan_id, _ = _authenticated_scan(seed, world)

    assert _list(api_client, world.viewer_a, scan_id, "?limit=101").status_code == 422


def test_a_scan_without_observations_is_an_empty_list(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan_id, _ = _authenticated_scan(seed, world)

    body = _list(api_client, world.viewer_a, scan_id).json()

    assert (body["data"], body["meta"]["total"]) == ([], 0)


def test_another_project_gets_the_same_404_as_a_missing_scan(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan_id, runs = _authenticated_scan(seed, world)
    _observe(seed, scan_id, runs["zap"], 1)
    other = seed.member(world.admin, world.project_b.id, Role.VIEWER)

    foreign = _list(api_client, other, scan_id)
    missing = _list(api_client, other, uuid4())

    assert foreign.status_code == missing.status_code == 404
    assert foreign.json()["error"]["code"] == missing.json()["error"]["code"]


def test_a_key_is_required(api_client: TestClient, seed: Seeder, world: World) -> None:
    scan_id, _ = _authenticated_scan(seed, world)

    assert api_client.get(f"{SCANS}/{scan_id}/observations").status_code == 401


# --- GET /scans/{id} 的每個引擎的結果 --------------------------------------------------------


def _record(seed: Seeder, run_id: UUID, **details: object) -> None:
    document = {
        "status": "timed_out",
        "error_code": "ENGINE_TIMEOUT",
        "excluded": {
            "guard_denied": 1,
            "guard_response": 0,
            "not_answered": 2,
            "out_of_scope": 3,
        },
        "duplicates": 4,
        "truncated_fields": 5,
        "engine_errors": 0,
        "engine_warnings": 1,
        "time_limit_reached": True,
        "traffic_verified": True,
        "problem": None,
        "components": {"reports": "0.46.0"},
        **details,
    }
    seed.execute(
        "UPDATE scanner_runs SET results_recorded = true, parser_version = 'p/1', "
        "engine_version = '2.17.0', exit_code = 2, observation_count = 11, "
        "result_details = CAST(:details AS jsonb) WHERE id = :id",
        details=json.dumps(document),
        id=run_id,
    )


def test_a_scan_shows_the_result_of_each_engine(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan_id, runs = _authenticated_scan(seed, world)
    _record(seed, runs["zap"])

    body = api_client.get(f"{SCANS}/{scan_id}", headers=world.viewer_a.headers).json()

    engines = {engine["engine"]: engine for engine in body["data"]["engines"]}
    assert engines["preflight"]["result"] is None
    assert engines["zap"]["result"] == {
        "parser_version": "p/1",
        "engine_version": "2.17.0",
        "exit_code": 2,
        "observation_count": 11,
        "excluded": {
            "guard_denied": 1,
            "guard_response": 0,
            "not_answered": 2,
            "out_of_scope": 3,
        },
        "duplicates": 4,
        "truncated_fields": 5,
        "engine_errors": 0,
        "engine_warnings": 1,
        "time_limit_reached": True,
        "traffic_verified": True,
        "problem": None,
        "components": {"reports": "0.46.0"},
    }


def test_the_list_of_scans_also_shows_the_result(
    api_client: TestClient, seed: Seeder, world: World
) -> None:
    scan_id, runs = _authenticated_scan(seed, world)
    _record(seed, runs["zap"], problem="report_version")

    body = api_client.get(SCANS, headers=world.viewer_a.headers).json()

    [scan] = [item for item in body["data"] if item["id"] == str(scan_id)]
    [zap] = [engine for engine in scan["engines"] if engine["engine"] == "zap"]
    assert zap["result"]["problem"] == "report_version"
