"""manifest（BENCH-03）：欄位齊全、session 完整才能評估。"""

import json
from typing import Any
from uuid import uuid4

import pytest

from benchmarks.collect import normalize_comparison, normalize_scan
from benchmarks.manifest import (
    DISCLOSURES,
    MANIFEST_VERSION,
    REQUIRED_PROVENANCE,
    ManifestError,
    build_manifest,
    check_manifest,
)
from benchmarks.models import LabeledScan
from benchmarks.schedule import build_schedule
from benchmarks.spec import ExperimentSpec, parse_spec
from tests.unit.bench.samples import comparison_json, finding_json, scan_json

PROVENANCE = dict.fromkeys(REQUIRED_PROVENANCE, "x")


def _spec() -> ExperimentSpec:
    document = {
        "name": "unit-manifest",
        "purpose": "smoke",
        "seed": 3,
        "profile": "web_active_lab",
        "budget": {"requests_per_second": 2, "max_requests": 1200, "max_duration_seconds": 600},
        "groups": [{"id": "C", "engines": ["zap", "nuclei"]}],
        "targets": [{"id": "fixture", "kind": "fixture"}],
        "comparisons": [
            {
                "id": "c1",
                "group": "C",
                "target": "fixture",
                "baseline": "insecure",
                "current": "secure",
            }
        ],
    }
    return parse_spec(json.dumps(document).encode())


def _labeled(spec: ExperimentSpec) -> list[LabeledScan]:
    labeled = []
    for item in build_schedule(spec):
        scan = normalize_scan(scan_json(), [finding_json("sqli")], 3)
        labeled.append(
            LabeledScan(
                position=item.position,
                group=item.group,
                target=item.target,
                target_kind="fixture",
                variant=item.variant.value,
                repetition=item.repetition,
                comparison=item.comparison,
                role=item.role,
                scan=scan,
            )
        )
    return labeled


def _manifest(**overrides: Any) -> dict[str, Any]:
    spec = _spec()
    scans = _labeled(spec)
    snapshot, items = comparison_json(
        scans[0].scan.id, scans[1].scan.id, [(str(uuid4()), "persistent")]
    )
    fields: dict[str, Any] = {
        "spec": spec,
        "spec_sha256": "c" * 64,
        "schedule": build_schedule(spec),
        "scans": scans,
        "comparisons": [("c1", normalize_comparison(snapshot, items))],
        "provenance": PROVENANCE,
        "files": {"scan-01.json": "d" * 64},
        "complete": True,
        "stopped_reason": None,
    }
    fields.update(overrides)
    return build_manifest(**fields)


def test_a_complete_manifest_records_budgets_allotments_and_guard_counts() -> None:
    manifest = check_manifest(_manifest())

    assert manifest["manifest_version"] == MANIFEST_VERSION
    assert [item["role"] for item in manifest["schedule"]] == ["baseline", "current"]
    zap = manifest["scans"][0]["runs"][0]
    assert zap["cap"] == {"max_requests": 760, "max_duration_seconds": 380}
    assert (zap["requests_allotted"], zap["seconds_allotted"]) == (760, 380)
    assert (zap["requests_sent"], zap["requests_denied"], zap["traffic_seconds"]) == (700, 4, 375)
    assert manifest["scans"][0]["findings"] == 1
    assert manifest["comparisons"][0]["items"] == 1
    assert manifest["disclosures"] == list(DISCLOSURES)
    assert "results_not_encrypted" in manifest["disclosures"]
    assert manifest["groups"][0]["engine_budgets"] is None
    json.dumps(manifest)


def test_an_incomplete_session_is_recorded_but_not_evaluated() -> None:
    spec = _spec()
    manifest = _manifest(scans=_labeled(spec)[:1], complete=False, stopped_reason="scan 2 失敗")

    assert manifest["complete"] is False
    with pytest.raises(ManifestError, match="整批作廢"):
        check_manifest(manifest)
    assert check_manifest(manifest, require_complete=False) is manifest


def test_a_complete_manifest_must_cover_the_whole_schedule() -> None:
    spec = _spec()
    with pytest.raises(ManifestError, match="每個 scan"):
        _manifest(scans=_labeled(spec)[:1])
    with pytest.raises(ManifestError, match="每個 scan"):
        _manifest(stopped_reason="x")


@pytest.mark.parametrize("key", ["files", "provenance", "complete", "spec_sha256"])
def test_a_manifest_missing_a_field_is_rejected(key: str) -> None:
    manifest = _manifest()
    del manifest[key]

    with pytest.raises(ManifestError, match=key):
        check_manifest(manifest)


def test_provenance_must_be_complete() -> None:
    manifest = _manifest(provenance={"git_commit": "x"})

    with pytest.raises(ManifestError, match="provenance"):
        check_manifest(manifest)


@pytest.mark.parametrize("manifest", [[], {"manifest_version": 0}])
def test_other_documents_are_rejected(manifest: Any) -> None:
    with pytest.raises(ManifestError):
        check_manifest(manifest)


def test_another_version_is_rejected() -> None:
    manifest = {**_manifest(), "manifest_version": MANIFEST_VERSION + 1}

    with pytest.raises(ManifestError, match="版本"):
        check_manifest(manifest)
