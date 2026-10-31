"""Independent capture evidence: never infer delivery from a Guard allow log."""

import base64
import json
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from tests.guard_path_cases import PATH_CASES
from tests.guard_path_evidence import (
    PUBLIC_FIELDS,
    EvidenceError,
    public_echo_rows,
    received_requests,
)
from tests.live.guard_paths_support import EvidenceStore


def packet(seq: int, data: bytes, *, flags: int = 0x18) -> dict[str, object]:
    return {
        "source": "10.89.10.254",
        "destination": "10.89.10.221",
        "sport": 40000,
        "dport": 5000,
        "seq": seq,
        "flags": flags,
        "time": 1.0,
        "payload": base64.b64encode(data).decode(),
    }


def test_reassembly_preserves_hex_case_query_order_and_duplicates() -> None:
    raw = b"GET /a/x%3c+%20?q=1 HTTP/1.1\r\nHost: target\r\n\r\n"
    events = [
        packet(9, b"", flags=2),
        packet(10, raw[:17]),
        packet(27, raw[17:]),
        packet(10, raw),
        packet(10 + len(raw), raw),
    ]
    records = received_requests(events)
    assert [r["target"] for r in records] == ["/a/x%3c+%20?q=1"] * 2
    assert [r["path"] for r in records] == ["/a/x%3c+%20"] * 2


def test_body_is_not_mistaken_for_a_second_request() -> None:
    body = b"GET /forbidden HTTP/1.1\r\n\r\n"
    raw = f"POST /a/x HTTP/1.1\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
    assert len(received_requests([packet(9, b"", flags=2), packet(10, raw)])) == 1


@pytest.mark.parametrize(
    "events",
    [
        [packet(10, b"GET / HTTP/1.1\r\n\r\n")],
        [packet(9, b"", flags=2), packet(11, b"GET / HTTP/1.1\r\n\r\n")],
        [packet(9, b"", flags=2), packet(10, b"GET / HTTP/1.1\r\n")],
        [packet(9, b"", flags=2), packet(10, b"GET / HTTP/1.1\r\n\r\n"), packet(10, b"POST")],
    ],
)
def test_incomplete_or_conflicting_capture_cannot_be_verified(
    events: list[dict[str, object]],
) -> None:
    with pytest.raises(EvidenceError):
        received_requests(events)


def test_chunked_body_and_keep_alive_are_parsed_separately() -> None:
    raw = (
        b"POST /a/x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"3\r\nabc\r\n0\r\n\r\nGET /a/y HTTP/1.1\r\n\r\n"
    )
    assert [r["path"] for r in received_requests([packet(9, b"", flags=2), packet(10, raw)])] == [
        "/a/x",
        "/a/y",
    ]


def test_original_evidence_is_encrypted_and_restricted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECSCAN_GUARD_PATH_RECORD_DIR", str(tmp_path / "evidence"))
    store = EvidenceStore.open("strict-1", "fixture")
    original = b"GET /secret-token-canary HTTP/1.1\r\nAuthorization: Bearer private-canary\r\n"
    store.write("raw-request", original)
    store.seal()
    path = store.directory / "raw-request.fernet"
    assert b"private-canary" not in path.read_bytes()
    assert b"secret-token-canary" not in path.read_bytes()
    assert Fernet(store.key).decrypt(path.read_bytes()) == original
    assert path.stat().st_mode & 0o077 == 0
    assert store.directory.stat().st_mode & 0o077 == 0
    manifest = store.directory / "evidence-manifest.json.fernet"
    assert "raw-request.fernet" in json.loads(Fernet(store.key).decrypt(manifest.read_bytes()))
    assert store.key.decode() not in repr(store)


def test_evidence_store_refuses_an_exposed_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECSCAN_GUARD_PATH_RECORD_DIR", str(tmp_path))
    key = tmp_path / ".evidence.key"
    key.write_bytes(Fernet.generate_key())
    key.chmod(0o644)
    with pytest.raises(EvidenceError, match="0600"):
        EvidenceStore.open("strict-1", "fixture")


def test_repeated_measurements_archive_failure_evidence_without_mixing_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECSCAN_GUARD_PATH_RECORD_DIR", str(tmp_path))
    first = EvidenceStore.open("strict-1", "same-label")
    first.write("report.json", {"old": "failed attempt"})
    old_ciphertext = (first.directory / "report.json.fernet").read_bytes()
    second = EvidenceStore.open("strict-1", "same-label")
    assert list(second.directory.iterdir()) == []
    archived = list((tmp_path / "archive").rglob("report.json.fernet"))
    assert len(archived) == 1
    assert archived[0].read_bytes() == old_ciphertext
    second.write("analysis.json", {"new": "attempt without report"})
    second.seal()
    manifest = json.loads(
        Fernet(second.key).decrypt(
            (second.directory / "evidence-manifest.json.fernet").read_bytes()
        )
    )
    assert set(manifest) == {"analysis.json.fernet"}


def test_public_export_is_a_closed_allowlist_not_general_log_redaction() -> None:
    decisions = [
        {
            "method": "GET",
            "path": case.path,
            "policy_version": "strict-1",
            "decision": "allow" if case.strict_reason is None else "deny",
            "reason": case.strict_reason,
            "detail": case.strict_detail,
            "secret": "must-never-be-exported",
        }
        for case in PATH_CASES
    ]
    accepted = [case.path for case in PATH_CASES if case.strict_reason is None]
    telemetry = [{"e": "request", "path": path} for path in accepted]
    receipts = [{"target": path} for path in accepted]
    results = {
        str(i): {"status": 200 if c.strict_reason is None else 403}
        for i, c in enumerate(PATH_CASES)
    }
    rows = public_echo_rows("strict-1", decisions, telemetry, receipts, results)
    assert all(set(row) == PUBLIC_FIELDS for row in rows)
    assert "must-never-be-exported" not in json.dumps(rows)
    decisions[0]["path"] = "/a/unexpected-secret-token"
    with pytest.raises(EvidenceError, match="synthetic corpus"):
        public_echo_rows("strict-1", decisions, telemetry, receipts, results)


# Live evidence is added only after the encrypted sources have been measured and reviewed.
# Empty collection before the first recording is visibly skipped; the final T33 deliverable
# must contain path-evidence.json and its entry in the existing global fixture manifest.
@pytest.mark.parametrize(
    "path", sorted((Path(__file__).parents[1] / "fixtures" / "guard").glob("*.json"))
)
def test_recorded_guard_evidence_matches_the_frozen_security_contract(path: Path) -> None:
    document = json.loads(path.read_text())
    assert document["schema"] == 1
    assert len(document["groups"]) == 4
    assert {(g["framework"], g["policy_version"]) for g in document["groups"]} == {
        (framework, version)
        for framework in ("flask", "express")
        for version in ("strict-1", "encoded-params-1")
    }
    for group in document["groups"]:
        rows = group["rows"]
        assert all(set(row) == PUBLIC_FIELDS for row in rows)
        assert [row["path"] for row in rows] == [case.path for case in PATH_CASES]
        forwarded = [{"e": "request", "path": row["path"]} for row in rows if row["forwarded"]]
        receipts = [{"target": row["path"]} for row in rows if row["received"]]
        results = {str(i): {"status": row["status"]} for i, row in enumerate(rows)}
        assert public_echo_rows(group["policy_version"], rows, forwarded, receipts, results) == rows
    assert len(document["scans"]) == 5
    for scan in document["scans"]:
        assert scan["forwarded"] == scan["received"]
        assert scan["forwarded"] > 0
        if scan["policy_version"] == "strict-1":
            assert scan["forwarded_encoded"] == 0
        if scan["label"] == "vampi-secure":
            assert scan["sqli"] == 0
