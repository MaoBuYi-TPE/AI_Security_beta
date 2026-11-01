"""Strict diagnosis of the original T33 Juice reviews crash; never A/B success evidence."""

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from cryptography.fernet import Fernet

from tests.live.guard_paths_support import EvidenceStore

STRICT = "strict-1"
EXPECTED_JUICE_PATHS = ("/rest/products/{id}/reviews", "/api/Products/{id}")
EXPECTED_JUICE_EXCLUDED = ("/api/Products/999",)
EXPECTED_JUICE_BUDGET = (
    ("requests_per_second", 2),
    ("max_requests", 5000),
    ("max_duration_seconds", 1500),
)
FAILURE_LABEL = "juice-shop-original-reviews-failure"
CAPTURE_REASON = "incomplete request body"

_REQUIRED = frozenset(
    {
        "environment.json",
        "scanner-image.json",
        "packets.jsonl",
        "capture-validation.json",
        "capture-stderr.log",
        "capture-exit.json",
        "scan-api.json",
        "scan.json",
        "runs.json",
        "observations.json",
        "frozen-scan.json",
        "guard-decisions.jsonl",
        "telemetry.jsonl",
        "summary.json",
        "report.json",
        "zap.log",
        "manifest.json",
        "collection-index.json",
        "collection-errors.json",
        *(
            f"{label}-{command}.{stream}"
            for label in ("target", "capture")
            for command in ("inspect", "logs", "events")
            for stream in ("stdout.log", "stderr.log", "result.json")
        ),
    }
)


def read_failure_artifacts(store: EvidenceStore) -> dict[str, bytes]:
    """Verify the sealed ciphertext before using decrypted diagnostics for assertions."""
    cipher = Fernet(store.key)
    manifest = json.loads(
        cipher.decrypt((store.directory / "evidence-manifest.json.fernet").read_bytes())
    )
    assert {name + ".fernet" for name in _REQUIRED} <= manifest.keys(), "missing sealed evidence"
    artifacts = {}
    for encrypted_name in manifest:
        name = encrypted_name.removesuffix(".fernet")
        path = store.directory / (name + ".fernet")
        assert path.stat().st_mode & 0o077 == 0, "evidence must remain private"
        ciphertext = path.read_bytes()
        assert hashlib.sha256(ciphertext).hexdigest() == manifest[path.name]["sha256"]
        assert len(ciphertext) == manifest[path.name]["bytes"]
        # Packet evidence consists of independently encrypted lines.
        artifacts[name] = (
            b"\n".join(cipher.decrypt(line) for line in ciphertext.splitlines())
            if name == "packets.jsonl"
            else cipher.decrypt(ciphertext)
        )
    return artifacts


def assert_original_reviews_failure(artifacts: Mapping[str, bytes], reason: str) -> None:
    """Reject unrelated EvidenceError, OOM, incomplete collection, or a valid delivery claim."""
    assert artifacts.keys() >= _REQUIRED, "missing diagnosis artifacts"
    assert reason == CAPTURE_REASON, "unexpected measurement failure"
    validation = json.loads(artifacts["capture-validation.json"])
    assert validation["valid"] is False, "failed capture must remain invalid"
    assert validation["reason"] == reason
    assert json.loads(artifacts["collection-errors.json"]) == [], "incomplete collection"
    index = json.loads(artifacts["collection-index.json"])
    for name in (
        "scan-api.json",
        "runs.json",
        "frozen-scan.json",
        "guard-decisions.jsonl",
        "telemetry.jsonl",
        "summary.json",
        "report.json",
        "zap.log",
        "manifest.json",
    ):
        assert index.get(name) is True, "missing original measurement input"
    _assert_target_crash(artifacts)
    _assert_original_scan(artifacts)
    assert "analysis.json" not in artifacts, "failed measurement must not become A/B analysis"


def _assert_target_crash(artifacts: Mapping[str, bytes]) -> None:
    for command in ("inspect", "logs", "events"):
        result = json.loads(artifacts[f"target-{command}.result.json"])
        assert result["returncode"] == 0
        assert result["error"] is None
    [target] = json.loads(artifacts["target-inspect.stdout.log"])
    state = target["State"]
    assert state["Status"] == "exited"
    assert state["Running"] is False
    assert state["ExitCode"] == 1, "unexpected target exit"
    assert state["OOMKilled"] is False, "unexpected OOM"
    logs = artifacts["target-logs.stdout.log"] + artifacts["target-logs.stderr.log"]
    assert b"ReferenceError: get is not defined" in logs, "missing actual Juice reviews crash"
    assert b"/juice-shop/build/routes/productReviews.js" in logs, "unexpected crash location"
    events = [json.loads(line) for line in artifacts["target-events.stdout.log"].splitlines()]
    assert any(
        event.get("Action") == "die"
        and event.get("Actor", {}).get("Attributes", {}).get("exitCode") == "1"
        for event in events
    ), "missing target crash lifecycle"


def _assert_original_scan(artifacts: Mapping[str, bytes]) -> None:
    scan = json.loads(artifacts["scan-api.json"])
    frozen = json.loads(artifacts["frozen-scan.json"])
    runs = json.loads(artifacts["runs.json"])
    [run] = runs
    assert run["engine"] == "zap"
    assert run["guard_policy_version"] == STRICT
    assert scan["profile"] == "api_active_lab"
    assert scan["auth"] is None
    assert frozen["auth_profile_id"] is None
    assert scan["budget"] == dict(EXPECTED_JUICE_BUDGET)
    assert scan["id"] == frozen["scan_id"]
    assert scan["api_spec"]["id"] == frozen["api_spec_id"]
    assert {(op["method"], op["path"]) for op in frozen["operations"]} == {
        ("GET", path) for path in EXPECTED_JUICE_PATHS
    }
    telemetry = [json.loads(line) for line in artifacts["telemetry.jsonl"].splitlines()]
    sent = [entry for entry in telemetry if entry["e"] == "request"]
    assert sent, "no original scanner traffic"
    assert all(entry["method"] == "GET" for entry in sent)
    assert all("%" not in entry["path"] for entry in sent), "strict policy forwarded encoding"
    assert all(entry["path"] not in EXPECTED_JUICE_EXCLUDED for entry in sent)
    summary: dict[str, Any] = json.loads(artifacts["summary.json"])
    assert summary["policy_version"] == STRICT
    assert summary["scan_id"] == scan["id"]
    assert summary["run_id"] == run["id"]
    assert summary["forwarded"] == len(sent) == run["requests_sent"]
    report = json.loads(artifacts["report.json"])
    assert isinstance(report, dict), "invalid raw report"
    assert isinstance(report.get("site"), list), "invalid raw report"
