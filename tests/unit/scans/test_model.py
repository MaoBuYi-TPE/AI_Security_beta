"""scan 的 domain model 與事件的 payload（docs/DECISIONS.md §13.1、§13.5）。"""

import dataclasses
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from secscan.auth_profiles.domain.model import RESERVED_ROLE_LABELS
from secscan.grants.domain.scope import Budget
from secscan.scans.domain.catalog import Engine, ScanProfile
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import (
    ANONYMOUS_ROLE,
    MAX_EVENT_PAYLOAD_BYTES,
    AuthBinding,
    Coverage,
    EventType,
    Scan,
    ScannerRun,
    VersionRef,
    cancel_requested_payload,
    created_payload,
    run_status_payload,
    scan_status_payload,
)
from secscan.targets.domain import parse_origin

NOW = datetime(2026, 10, 26, 8, 0, tzinfo=UTC)
SCAN_ID = uuid4()


def _run(engine: Engine = Engine.FAKE, sequence: int = 1, **overrides: object) -> ScannerRun:
    fields: dict[str, object] = {
        "id": uuid4(),
        "scan_id": SCAN_ID,
        "engine": engine,
        "sequence": sequence,
        "status": RunStatus.QUEUED,
        "error_code": None,
        "started_at": None,
        "finished_at": None,
        "created_at": NOW,
    }
    fields.update(overrides)
    return ScannerRun(**fields)  # type: ignore[arg-type]


def _scan(**overrides: object) -> Scan:
    fields: dict[str, object] = {
        "id": SCAN_ID,
        "project_id": uuid4(),
        "target_id": uuid4(),
        "target_origin": parse_origin("http://vampi-vuln:5000"),
        "status": ScanStatus.QUEUED,
        "profile": ScanProfile.API_ACTIVE_LAB,
        "scope_grant": VersionRef(id=uuid4(), version=1),
        "api_spec": VersionRef(id=uuid4(), version=2),
        "auth": AuthBinding(profile_id=uuid4(), version=3, role_label="standard_user"),
        "budget": Budget(requests_per_second=2, max_requests=1_000, max_duration_seconds=1_500),
        "runs": (_run(),),
        "coverage": Coverage(eligible_operations=13, ineligible_operations=1),
        "cancel_requested_at": None,
        "created_by_key_id": uuid4(),
        "created_at": NOW,
        "finished_at": None,
    }
    fields.update(overrides)
    return Scan(**fields)  # type: ignore[arg-type]


def test_the_auth_role_is_the_bound_profile_role_or_anonymous() -> None:
    """未認證的 scan 明確標為 anonymous（contract §7），不沿用認證覆蓋的稱呼。"""
    assert _scan().auth_role == "standard_user"
    assert _scan(auth=None).auth_role == ANONYMOUS_ROLE == "anonymous"
    # auth profile 不能用這個 role_label，兩者不會混淆。
    assert ANONYMOUS_ROLE in RESERVED_ROLE_LABELS


def test_a_scan_with_the_fake_engine_is_a_fixture() -> None:
    assert _scan().fixture is True
    zap = _scan(runs=(_run(Engine.ZAP),))
    assert zap.fixture is False


def test_results_are_complete_only_when_completed() -> None:
    for status in ScanStatus:
        finished = NOW if status not in {ScanStatus.QUEUED} else None
        scan = _scan(status=status, finished_at=finished)
        assert scan.results_complete is (status is ScanStatus.COMPLETED)


def test_only_terminal_statuses_are_terminal() -> None:
    assert _scan(status=ScanStatus.CANCELLED, finished_at=NOW).is_terminal is True
    assert _scan(status=ScanStatus.CANCELLING).is_terminal is False


def test_runs_are_kept_in_sequence_order() -> None:
    with pytest.raises(ValueError, match="sequence"):
        _scan(runs=(_run(Engine.NUCLEI, 2), _run(Engine.ZAP, 1)))


def test_a_scan_has_at_least_one_run() -> None:
    with pytest.raises(ValueError, match="run"):
        _scan(runs=())


def test_coverage_counts_are_not_negative() -> None:
    with pytest.raises(ValueError, match="coverage"):
        Coverage(eligible_operations=-1, ineligible_operations=0)


def test_role_label_of_a_binding_cannot_be_anonymous() -> None:
    with pytest.raises(ValueError, match="anonymous"):
        AuthBinding(profile_id=uuid4(), version=1, role_label=ANONYMOUS_ROLE)


def test_versions_are_positive() -> None:
    with pytest.raises(ValueError, match="version"):
        VersionRef(id=uuid4(), version=0)
    with pytest.raises(ValueError, match="version"):
        AuthBinding(profile_id=uuid4(), version=0, role_label="user")


def test_run_error_codes_match_the_status() -> None:
    with pytest.raises(ValueError, match="錯誤碼"):
        _run(status=RunStatus.FAILED, started_at=NOW, finished_at=NOW)
    with pytest.raises(ValueError, match="錯誤碼"):
        _run(status=RunStatus.RUNNING, started_at=NOW, error_code=RunErrorCode.ENGINE_FAILED)


def test_scan_models_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        _scan().status = ScanStatus.RUNNING  # type: ignore[misc]


# --- 事件的 payload：只有白名單的欄位，值都來自 enum ------------------------------------------


def test_created_payload() -> None:
    payload = created_payload(profile=ScanProfile.API_ACTIVE_LAB, engines=(Engine.FAKE,))

    assert payload == {"status": "queued", "profile": "api_active_lab", "engines": ["fake"]}


def test_scan_status_payload() -> None:
    payload = scan_status_payload(status=ScanStatus.RUNNING, previous=ScanStatus.PREPARING)

    assert payload == {"status": "running", "previous_status": "preparing"}


def test_cancel_requested_payload() -> None:
    assert cancel_requested_payload(previous=ScanStatus.RUNNING) == {"previous_status": "running"}


def test_run_status_payload() -> None:
    payload = run_status_payload(
        engine=Engine.FAKE,
        status=RunStatus.FAILED,
        previous=RunStatus.PREPARING,
        error_code=RunErrorCode.SCOPE_REVOKED,
    )

    assert payload == {
        "engine": "fake",
        "status": "failed",
        "previous_status": "preparing",
        "error_code": "SCOPE_REVOKED",
    }
    assert run_status_payload(
        engine=Engine.FAKE, status=RunStatus.RUNNING, previous=RunStatus.PREPARING, error_code=None
    ) == {"engine": "fake", "status": "running", "previous_status": "preparing", "error_code": None}


def test_the_largest_payload_fits_the_db_limit() -> None:
    """DB 的 CHECK 是 1 KiB；所有引擎、最長的狀態與錯誤碼也放得下。"""
    largest = [
        created_payload(profile=ScanProfile.API_ACTIVE_LAB, engines=tuple(Engine)),
        run_status_payload(
            engine=Engine.SCHEMATHESIS,
            status=RunStatus.INTERRUPTED,
            previous=RunStatus.NORMALIZING,
            error_code=max(RunErrorCode, key=len),
        ),
        scan_status_payload(status=ScanStatus.PARTIALLY_COMPLETED, previous=ScanStatus.NORMALIZING),
    ]
    for payload in largest:
        assert len(json.dumps(payload).encode()) <= MAX_EVENT_PAYLOAD_BYTES


def test_event_types() -> None:
    assert {event.value for event in EventType} == {
        "scan.created",
        "scan.status",
        "scan.cancel_requested",
        "run.status",
    }
