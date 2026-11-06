"""RESCAN-05：以真的 queue/linker 寫入跨版本證據，API 不借新版 mapping 推論。"""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.findings.domain import fingerprint
from secscan.findings.domain.taxonomy import FINGERPRINT_VERSION, mapping_identity
from secscan.findings.service import FindingLinker
from secscan.scans.domain.catalog import Engine as ScanEngine
from secscan.scans.domain.lifecycle import RunStatus
from secscan.scans.queue import ScanQueue
from tests.integration.api_support import LAB, Seeder, World
from tests.integration.finding_support import (
    ZAP_CORS,
    ZAP_SQLI,
    ZAP_XCTO,
    parsed_run,
    web_scan,
    web_target,
)
from tests.integration.test_comparisons_api import URL
from tests.integration.test_comparisons_api import client as client
from tests.integration.test_comparisons_api import world as world

pytestmark = pytest.mark.integration


def _versioned_pair(
    engine: Engine,
    seed: Seeder,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    changed_part: str,
    retried: bool,
) -> dict[str, str]:
    sessions = sessionmaker(engine, expire_on_commit=False)
    queue = ScanQueue(sessions, lab=LAB, clock=lambda: datetime.now(UTC))
    target, grant = web_target(seed, world)
    version, digest = mapping_identity()
    old_fingerprint_version = FINGERPRINT_VERSION - 1
    old_mapping = {
        "fingerprint": (f"{version.rsplit('+fp-', 1)[0]}+fp-{old_fingerprint_version}", digest),
        "mapping": (f"rules-0.0+{version.split('+', 1)[1]}", digest),
        "taxonomy": (version, "f" * 64),
    }[changed_part]
    assert old_mapping != (version, digest)
    baseline = web_scan(seed, world, target, grant, (ScanEngine.ZAP,))
    run = parsed_run(queue, ScanEngine.ZAP, (ZAP_SQLI, ZAP_CORS))
    with monkeypatch.context() as patch:
        patch.setattr("secscan.findings.service.mapping_identity", lambda: old_mapping)
        if changed_part == "fingerprint":
            patch.setattr(fingerprint, "FINGERPRINT_VERSION", old_fingerprint_version)
        assert FindingLinker(sessions).link(run) == 2
    if retried:
        assert FindingLinker(sessions).link(run) == 0
    [frozen] = seed.query(
        "SELECT link_mapping_version, link_taxonomy_sha256 FROM scanner_runs WHERE id = :run",
        run=run.run_id,
    )
    assert (frozen.link_mapping_version, frozen.link_taxonomy_sha256) == old_mapping
    queue.advance(run, RunStatus.SUCCEEDED)
    current = web_scan(seed, world, target, grant, (ScanEngine.ZAP,))
    next_run = parsed_run(queue, ScanEngine.ZAP, (ZAP_CORS, ZAP_XCTO))
    assert FindingLinker(sessions).link(next_run) == 2
    queue.advance(next_run, RunStatus.SUCCEEDED)
    return {"baseline_scan_id": str(baseline), "current_scan_id": str(current)}


@pytest.mark.parametrize("changed_part", ["fingerprint", "mapping", "taxonomy"])
@pytest.mark.parametrize("retried", [False, True], ids=["direct", "retried-with-new-mapping"])
def test_cross_version_comparison_requires_manual_review_even_for_shared_findings(
    client: TestClient,
    queue_engine: Engine,
    queue_seed: Seeder,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    changed_part: str,
    retried: bool,
) -> None:
    body = _versioned_pair(queue_engine, queue_seed, world, monkeypatch, changed_part, retried)
    taxonomy = Mock(side_effect=AssertionError("不得以目前 taxonomy 推論舊 scan"))
    monkeypatch.setattr("secscan.comparisons.service.load_taxonomy", taxonomy)

    response = client.post(URL, json=body, headers=world.operator_a.headers)
    assert response.status_code == 201, response.text
    snapshot = response.json()["data"]
    assert snapshot["comparability"] == "different"
    assert snapshot["manual_review_required"] is True
    assert "mapping_version_mismatch_or_unknown" in snapshot["reasons"]
    fingerprint_changed = changed_part == "fingerprint"
    assert ("fingerprint_version_mismatch_or_unknown" in snapshot["reasons"]) is fingerprint_changed
    count = 4 if fingerprint_changed else 3
    assert snapshot["counts"] == {
        "new": 0,
        "persistent": 0,
        "not_observed": 0,
        "inconclusive": count,
        "not_comparable": 0,
    }
    path = f"{URL}/{snapshot['id']}"
    page = client.get(f"{path}/findings", headers=world.viewer_a.headers)
    assert page.status_code == 200
    findings = page.json()["data"]
    assert page.json()["meta"]["total"] == count
    shared = 0
    for finding in findings:
        assert finding["classification"] == "inconclusive"
        assert finding["manual_review_required"] is True
        assert "mapping_version_mismatch" in finding["reasons"]
        evidence = finding["evidence"]
        assert evidence["mapping_comparable"] is False
        assert evidence["fingerprint_comparable"] is not fingerprint_changed
        shared += int(evidence["baseline_observed"] and evidence["current_observed"])
    assert shared == (0 if fingerprint_changed else 1)
    assert client.get(path, headers=world.viewer_a.headers).json()["data"] == snapshot
    assert client.post(URL, json=body, headers=world.operator_a.headers).json()["data"] == snapshot
    taxonomy.assert_not_called()
