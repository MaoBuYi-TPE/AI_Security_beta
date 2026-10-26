"""取消 scan（docs/DECISIONS.md §13.6）：排隊中的 run 直接取消；runner 與 worker 階段的 run
由它們確認，全部終止之後 scan 才是 cancelled。已終止或已要求過取消時不改變任何東西。
"""

from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Row, text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal
from secscan.core.errors import ErrorCode
from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.domain.model import Lease, Scan
from secscan.scans.queue import QueueOperations
from secscan.scans.service import ScanService
from tests.integration.scan_support import ScanWorld, create_scan, scan_world
from tests.integration.scope_support import LAB, app_error, same_response

pytestmark = pytest.mark.integration

OWNER = "runner-cancel-test"
FAKE = frozenset({Engine.FAKE})


@pytest.fixture
def world(db_session: Session) -> ScanWorld:
    return scan_world(db_session)


def _cancel(
    session: Session, world: ScanWorld, scan_id: UUID, *, principal: Principal | None = None
) -> Scan:
    caller = principal if principal is not None else world.operator
    return ScanService(session, lab=LAB).cancel(caller, scan_id, request_id="req-cancel")


def _operations(session: Session) -> QueueOperations:
    return QueueOperations(session, lab=LAB)


def _running(session: Session, world: ScanWorld) -> tuple[Scan, Lease]:
    scan = create_scan(session, world)
    lease = _operations(session).claim(OWNER, FAKE)
    assert lease is not None
    _operations(session).prepare(lease, clock=lambda: world.grant.window.valid_from)
    return scan, lease


def _events(session: Session, scan_id: UUID) -> list[tuple[str, dict[str, object]]]:
    rows = session.execute(
        text("SELECT event_type, payload FROM scan_events WHERE scan_id = :id ORDER BY sequence"),
        {"id": scan_id},
    ).all()
    return [(row.event_type, row.payload) for row in rows]


def _audits(session: Session, scan_id: UUID) -> list[Row[Any]]:
    return list(
        session.execute(
            text(
                "SELECT action, actor_key_id, request_id, redacted_changes FROM audit_events "
                "WHERE object_id = :id AND action = 'scan.cancel'"
            ),
            {"id": scan_id},
        ).all()
    )


def test_cancelling_a_queued_scan_finishes_it_at_once(
    db_session: Session, world: ScanWorld
) -> None:
    scan = create_scan(db_session, world)

    cancelled = _cancel(db_session, world, scan.id)

    assert cancelled.status is ScanStatus.CANCELLED
    assert cancelled.cancel_requested_at is not None
    assert cancelled.finished_at is not None
    [run] = cancelled.runs
    assert (run.status, run.started_at, run.finished_at is not None) == (
        RunStatus.CANCELLED,
        None,
        True,
    )
    assert _events(db_session, scan.id)[1:] == [
        ("scan.cancel_requested", {"previous_status": "queued"}),
        (
            "run.status",
            {
                "engine": "fake",
                "status": "cancelled",
                "previous_status": "queued",
                "error_code": None,
            },
        ),
        ("scan.status", {"status": "cancelled", "previous_status": "queued"}),
    ]
    [audit] = _audits(db_session, scan.id)
    assert (audit.actor_key_id, audit.request_id, audit.redacted_changes) == (
        world.operator.key_id,
        "req-cancel",
        {"previous_status": "queued", "status": "cancelled"},
    )


def test_a_cancelled_queued_run_is_never_claimed(db_session: Session, world: ScanWorld) -> None:
    _cancel(db_session, world, create_scan(db_session, world).id)

    assert _operations(db_session).claim(OWNER, FAKE) is None


def test_a_running_scan_waits_for_the_runner_to_confirm(
    db_session: Session, world: ScanWorld
) -> None:
    """runner 確認停止之後才是 cancelled（CLAUDE.md §8）。"""
    scan, lease = _running(db_session, world)

    cancelling = _cancel(db_session, world, scan.id)

    assert cancelling.status is ScanStatus.CANCELLING
    assert cancelling.runs[0].status is RunStatus.RUNNING
    assert cancelling.finished_at is None
    assert _operations(db_session).heartbeat(lease).cancel_requested is True
    _operations(db_session).advance(lease, RunStatus.CANCELLING)
    done = _operations(db_session).advance(lease, RunStatus.CANCELLED)
    assert done.scan_status is ScanStatus.CANCELLED
    [audit] = _audits(db_session, scan.id)
    assert audit.redacted_changes == {"previous_status": "running", "status": "cancelling"}


def test_a_run_being_parsed_finishes_parsing(db_session: Session, world: ScanWorld) -> None:
    """解析不發流量：已收集的結果繼續解析完、保留下來，之後 scan 才是 cancelled。"""
    scan, lease = _running(db_session, world)
    operations = _operations(db_session)
    operations.advance(lease, RunStatus.COLLECTING)
    operations.advance(lease, RunStatus.COLLECTED)
    parsing = operations.claim_collected(OWNER, FAKE, run_id=lease.run_id)
    assert parsing is not None

    assert _cancel(db_session, world, scan.id).status is ScanStatus.CANCELLING
    assert operations.advance(parsing, RunStatus.SUCCEEDED).scan_status is ScanStatus.CANCELLED


def test_a_collected_run_is_still_parsed_after_a_cancel(
    db_session: Session, world: ScanWorld
) -> None:
    scan, lease = _running(db_session, world)
    operations = _operations(db_session)
    operations.advance(lease, RunStatus.COLLECTING)
    operations.advance(lease, RunStatus.COLLECTED)

    assert _cancel(db_session, world, scan.id).status is ScanStatus.CANCELLING
    parsing = operations.claim_collected(OWNER, FAKE)
    assert parsing is not None
    assert operations.advance(parsing, RunStatus.FAILED, error_code=RunErrorCode.ENGINE_FAILED)


def test_cancelling_twice_records_it_once(db_session: Session, world: ScanWorld) -> None:
    scan, _ = _running(db_session, world)
    first = _cancel(db_session, world, scan.id)
    events = _events(db_session, scan.id)

    again = _cancel(db_session, world, scan.id)

    assert again == first
    assert _events(db_session, scan.id) == events
    assert len(_audits(db_session, scan.id)) == 1


def test_cancelling_a_finished_scan_changes_nothing(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world)
    finished = _cancel(db_session, world, scan.id)
    events = _events(db_session, scan.id)

    assert _cancel(db_session, world, scan.id) == finished
    assert _events(db_session, scan.id) == events
    assert len(_audits(db_session, scan.id)) == 1


def test_only_writers_of_the_project_can_cancel(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world)

    viewer = app_error(lambda: _cancel(db_session, world, scan.id, principal=world.team.viewer_a))
    other = app_error(lambda: _cancel(db_session, world, scan.id, principal=world.team.operator_b))
    missing = app_error(lambda: _cancel(db_session, world, uuid4()))

    assert (viewer.status_code, viewer.code) == (403, ErrorCode.ROLE_NOT_ALLOWED)
    assert (missing.status_code, missing.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, missing)
    # 被拒絕時沒有任何 run 被取消。
    [run] = ScanService(db_session, lab=LAB).get(world.operator, scan.id).runs
    assert run.status is RunStatus.QUEUED


def test_admins_can_cancel_any_scan(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world)

    assert _cancel(db_session, world, scan.id, principal=world.team.admin).status is (
        ScanStatus.CANCELLED
    )
