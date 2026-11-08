"""T21 報告 API：排入佇列 → worker 產生 → 只能以 report id 下載；冪等、配額、權限與 header。"""

import hashlib
import json
from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from markdown_it import MarkdownIt
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.api_keys.domain import Role
from secscan.main import create_app
from secscan.reports.document_schema import ReportDocumentV1
from secscan.reports.domain import wording
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.worker.reports import ReportWorker
from tests.integration.api_support import Seeder, World
from tests.integration.database import ProvisionedDatabase
from tests.integration.finding_support import web_scan
from tests.integration.triage_support import (
    CONFIRM,
    Scenario,
    attestation,
    db_now,
    eligible,
    resolve_body,
    scenario,
)
from tests.unit.reports.test_encoding import assert_safe, flatten

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


def create(
    client: TestClient, scan: object, report_format: str, headers: dict[str, str], key: str = ""
) -> Any:
    return client.post(
        f"/api/v1/scans/{scan}/reports",
        json={"format": report_format},
        headers={**headers, "Idempotency-Key": key or uuid4().hex},
    )


def drain(engine: Engine) -> int:
    return ReportWorker(sessionmaker(engine, expire_on_commit=False), owner="worker-r").drain()


def test_reports_are_generated_and_downloaded_with_safe_headers(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    comparison = eligible(queue_engine, item)
    url = f"/api/v1/findings/{item.sqli}/triage"
    assert client.patch(url, json=CONFIRM, headers=world.operator_a.headers).status_code == 200
    body = resolve_body(comparison, attestation(item, db_now(queue_seed)))
    assert client.patch(url, json=body, headers=world.operator_a.headers).status_code == 200
    created = {
        name: create(client, item.baseline, name, world.operator_a.headers)
        for name in ("json", "markdown")
    }
    for response in created.values():
        assert response.status_code == 202, response.text
        assert response.json()["data"]["status"] == "queued"
    assert drain(queue_engine) == 2
    report_id = created["json"].json()["data"]["id"]
    meta = client.get(f"/api/v1/reports/{report_id}", headers=world.viewer_a.headers).json()
    data = meta["data"]
    assert data["status"] == "succeeded"
    assert data["truncated"] is False
    downloaded = client.get(f"/api/v1/reports/{report_id}/download", headers=world.viewer_a.headers)
    assert downloaded.status_code == 200
    assert hashlib.sha256(downloaded.content).hexdigest() == data["sha256"]
    assert len(downloaded.content) == data["size_bytes"]
    headers = downloaded.headers
    assert headers["content-type"] == "application/json"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["content-security-policy"] == (
        "default-src 'none'; frame-ancestors 'none'; sandbox"
    )
    assert headers["cache-control"] == "no-store"
    assert headers["content-disposition"] == (
        f'attachment; filename="secscan-report-{item.baseline.hex[:8]}-'
        f'{uuid_hex(report_id)[:8]}.json"'
    )
    document = ReportDocumentV1.model_validate_json(downloaded.content)
    resolved = [finding for finding in document.findings if finding.lifecycle_state == "resolved"]
    assert len(resolved) == 1
    assert resolved[0].resolution is not None
    assert resolved[0].resolution.evidence_provenance == "operator_supplied"
    assert document.summary.resolved_operator_supplied == 1
    assert "apple" not in downloaded.text
    assert wording.NOTICES[3] in document.notices
    assert document.authorization.approved_at is not None
    assert len(document.comparisons) == 1
    markdown_id = created["markdown"].json()["data"]["id"]
    markdown = client.get(
        f"/api/v1/reports/{markdown_id}/download", headers=world.operator_a.headers
    )
    assert markdown.headers["content-type"] == "text/markdown; charset=utf-8"
    assert markdown.headers["content-disposition"].endswith('.md"')
    assert_safe(markdown.text)
    tokens = flatten(MarkdownIt("commonmark").enable("table").parse(markdown.text))
    platform = "\n".join(token.content for token in tokens if token.type == "text")
    assert wording.claims_violations(platform) == []
    audits = queue_seed.query(
        "SELECT count(*) AS n FROM audit_events WHERE action = 'report.create'"
    )
    assert audits[0].n == 2


def uuid_hex(value: str) -> str:
    return value.replace("-", "")


def test_idempotency_terminal_scans_and_quotas(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    key = uuid4().hex
    headers = world.operator_a.headers
    first = create(client, item.baseline, "json", headers, key)
    replay = create(client, item.baseline, "json", headers, key)
    assert replay.status_code == 202
    assert replay.json()["data"]["id"] == first.json()["data"]["id"]
    conflict = create(client, item.baseline, "markdown", headers, key)
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    drain(queue_engine)
    terminal = create(client, item.baseline, "json", headers, key)
    assert terminal.status_code == 200
    assert terminal.json()["data"]["status"] == "succeeded"
    missing_key = client.post(
        f"/api/v1/scans/{item.baseline}/reports", json={"format": "json"}, headers=headers
    )
    assert missing_key.status_code == 400
    running = web_scan(queue_seed, world, item.target, item.grant_id, (ScanEngine.ZAP,))
    not_terminal = create(client, running, "json", headers)
    assert not_terminal.status_code == 409
    assert not_terminal.json()["error"]["code"] == "SCAN_NOT_TERMINAL"
    for _ in range(5):
        assert create(client, item.current, "json", headers).status_code == 202
    over = create(client, item.current, "json", headers)
    assert over.status_code == 409
    assert over.json()["error"]["code"] == "QUOTA_EXCEEDED"
    pending = client.get(
        f"/api/v1/reports/{create_id(client, item, headers)}/download", headers=headers
    )
    assert pending.status_code in {404, 409}


def create_id(client: TestClient, item: Scenario, headers: dict[str, str]) -> str:
    listed = client.get(f"/api/v1/scans/{item.current}/reports", headers=headers).json()
    assert listed["meta"]["total"] == 5
    report_id: str = listed["data"][0]["id"]
    not_ready = client.get(f"/api/v1/reports/{report_id}/download", headers=headers)
    assert not_ready.status_code == 409
    assert not_ready.json()["error"]["code"] == "REPORT_NOT_READY"
    return report_id


def test_reports_are_hidden_from_other_projects_and_viewers_cannot_create(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    created = create(client, item.baseline, "json", world.operator_a.headers)
    report_id = created.json()["data"]["id"]
    drain(queue_engine)
    assert create(client, item.baseline, "json", world.viewer_a.headers).status_code == 403
    outsider = queue_seed.member(world.admin, world.project_b.id, Role.OPERATOR)
    missing = client.get(f"/api/v1/reports/{uuid4()}", headers=outsider.headers)
    for path in (
        f"/api/v1/reports/{report_id}",
        f"/api/v1/reports/{report_id}/download",
        f"/api/v1/scans/{item.baseline}/reports",
    ):
        hidden = client.get(path, headers=outsider.headers)
        assert hidden.status_code == 404
        assert hidden.json()["error"]["code"] == missing.json()["error"]["code"]
    assert create(client, item.baseline, "json", outsider.headers).status_code == 404
    assert client.get(f"/api/v1/reports/{report_id}").status_code == 401
    # SEC-18：沒有 path 或 storage_key 的下載方式，也沒有 artifact 下載。
    sneaky = client.get(
        f"/api/v1/reports/{report_id}/download?path=../../etc/passwd&storage_key=x",
        headers=world.operator_a.headers,
    )
    assert sneaky.status_code == 200
    assert json.loads(sneaky.content)["report_id"] == report_id
    artifact = client.get(f"/api/v1/artifacts/{uuid4()}/download", headers=world.admin.headers)
    assert artifact.status_code == 404


def test_sha_mismatch_never_sends_content(
    client: TestClient, queue_engine: Engine, queue_seed: Seeder, world: World, item: Scenario
) -> None:
    created = create(client, item.baseline, "markdown", world.operator_a.headers)
    report_id = created.json()["data"]["id"]
    drain(queue_engine)
    # 只能繞過 trigger 才能改內容：模擬 DB 層的損壞（DDL 權限），API 仍不送出內容。
    queue_seed.execute_together(
        "ALTER TABLE report_contents DISABLE TRIGGER report_contents_immutable",
        "UPDATE report_contents SET content = 'tampered' WHERE report_id = :id",
        "ALTER TABLE report_contents ENABLE TRIGGER report_contents_immutable",
        id=report_id,
    )
    tampered = client.get(f"/api/v1/reports/{report_id}/download", headers=world.operator_a.headers)
    assert tampered.status_code == 500
    assert b"tampered" not in tampered.content
