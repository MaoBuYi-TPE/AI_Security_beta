"""查詢 scan：單筆、清單（篩選、分頁、project 範圍）與事件的輪詢（docs/DECISIONS.md §13.5）。"""

from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from secscan.api_keys.domain import Principal
from secscan.core.errors import ErrorCode
from secscan.core.pagination import PageRequest
from secscan.scans.domain.lifecycle import ScanStatus
from secscan.scans.domain.model import EventType, Scan
from secscan.scans.repository import ScanFilters
from secscan.scans.service import ScanService
from tests.integration.scan_support import ScanWorld, create_scan, scan_world
from tests.integration.scope_support import LAB, app_error, same_response

pytestmark = pytest.mark.integration


@pytest.fixture
def world(db_session: Session) -> ScanWorld:
    return scan_world(db_session)


def _service(session: Session) -> ScanService:
    return ScanService(session, lab=LAB)


def _cancelled(session: Session, world: ScanWorld) -> Scan:
    """一個已結束的 scan（同一個 target 才能再建立下一個）。"""
    scan = create_scan(session, world)
    return _service(session).cancel(world.operator, scan.id, request_id=None)


# --- 單筆 ----------------------------------------------------------------------------------


def test_members_of_the_project_can_read_a_scan(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world)

    for principal in (world.operator, world.team.viewer_a, world.team.admin):
        assert _service(db_session).get(principal, scan.id) == scan


def test_scans_of_other_projects_look_missing(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world)

    other = app_error(lambda: _service(db_session).get(world.team.operator_b, scan.id))
    missing = app_error(lambda: _service(db_session).get(world.operator, uuid4()))

    assert (missing.status_code, missing.code) == (404, ErrorCode.RESOURCE_NOT_FOUND)
    assert same_response(other, missing)


# --- 清單 ----------------------------------------------------------------------------------


def _list(
    session: Session,
    world: ScanWorld,
    filters: ScanFilters | None = None,
    *,
    principal: Principal | None = None,
) -> list[Scan]:
    result = _service(session).list(
        principal if principal is not None else world.operator,
        filters if filters is not None else ScanFilters(target_id=world.target.id),
        PageRequest(page=1, limit=100),
    )
    return list(result.items)


def test_scans_are_listed_newest_first(db_session: Session, world: ScanWorld) -> None:
    first = _cancelled(db_session, world)
    second = create_scan(db_session, world)

    assert [scan.id for scan in _list(db_session, world)] == [second.id, first.id]


def test_the_list_is_limited_to_the_project_of_the_caller(
    db_session: Session, world: ScanWorld
) -> None:
    mine = create_scan(db_session, world)

    assert [scan.id for scan in _list(db_session, world, ScanFilters())] == [mine.id]
    assert _list(db_session, world, ScanFilters(), principal=world.team.operator_b) == []
    assert (
        _list(
            db_session,
            world,
            ScanFilters(target_id=world.target.id),
            principal=world.team.operator_b,
        )
        == []
    )
    assert mine.id in [
        scan.id for scan in _list(db_session, world, ScanFilters(), principal=world.team.admin)
    ]


def test_the_list_filters_by_target_status_and_time(db_session: Session, world: ScanWorld) -> None:
    cancelled = _cancelled(db_session, world)
    queued = create_scan(db_session, world)
    other_target = scan_world(db_session, world.team)
    elsewhere = create_scan(db_session, other_target)

    def ids(filters: ScanFilters) -> set[object]:
        return {scan.id for scan in _list(db_session, world, filters)}

    assert ids(ScanFilters(target_id=world.target.id)) == {cancelled.id, queued.id}
    assert ids(ScanFilters(status=ScanStatus.QUEUED)) == {queued.id, elsewhere.id}
    assert ids(ScanFilters(status=ScanStatus.CANCELLED)) == {cancelled.id}
    created = queued.created_at
    assert ids(ScanFilters(created_after=created)) == {cancelled.id, queued.id, elsewhere.id}
    assert ids(ScanFilters(created_after=created + timedelta(seconds=1))) == set()
    assert ids(ScanFilters(created_before=created)) == set()
    assert ids(ScanFilters(created_before=created + timedelta(seconds=1))) == {
        cancelled.id,
        queued.id,
        elsewhere.id,
    }


def test_the_list_is_paged_with_a_total(db_session: Session, world: ScanWorld) -> None:
    for _ in range(2):
        _cancelled(db_session, world)
    newest = create_scan(db_session, world)

    page = _service(db_session).list(
        world.operator, ScanFilters(target_id=world.target.id), PageRequest(page=1, limit=1)
    )

    assert (page.total, [scan.id for scan in page.items]) == (3, [newest.id])


# --- 事件 ----------------------------------------------------------------------------------


def _events(
    session: Session, world: ScanWorld, scan: Scan, after: int, limit: int = 100
) -> list[int]:
    events = _service(session).events(world.operator, scan.id, after_sequence=after, limit=limit)
    return [event.sequence for event in events]


def test_events_are_polled_after_a_sequence(db_session: Session, world: ScanWorld) -> None:
    scan = _cancelled(db_session, world)
    count = int(
        db_session.execute(
            text("SELECT count(*) FROM scan_events WHERE scan_id = :id"), {"id": scan.id}
        ).scalar_one()
    )

    assert count == 4
    assert _events(db_session, world, scan, after=0) == [1, 2, 3, 4]
    assert _events(db_session, world, scan, after=2) == [3, 4]
    assert _events(db_session, world, scan, after=3) == [4]
    assert _events(db_session, world, scan, after=4) == []
    assert _events(db_session, world, scan, after=99) == []
    assert _events(db_session, world, scan, after=0, limit=1) == [1]
    assert _events(db_session, world, scan, after=1, limit=2) == [2, 3]


def test_an_event_carries_its_type_run_and_payload(db_session: Session, world: ScanWorld) -> None:
    scan = _cancelled(db_session, world)

    events = _service(db_session).events(world.operator, scan.id, after_sequence=0, limit=100)

    assert [event.type for event in events] == [
        EventType.SCAN_CREATED,
        EventType.SCAN_CANCEL_REQUESTED,
        EventType.RUN_STATUS,
        EventType.SCAN_STATUS,
    ]
    assert events[2].scanner_run_id == scan.runs[0].id
    assert all(event.scanner_run_id is None for event in events if event is not events[2])
    assert events[3].payload == {"status": "cancelled", "previous_status": "queued"}


def test_events_of_other_projects_look_missing(db_session: Session, world: ScanWorld) -> None:
    scan = create_scan(db_session, world)
    service = _service(db_session)

    other = app_error(
        lambda: service.events(world.team.operator_b, scan.id, after_sequence=0, limit=10)
    )
    missing = app_error(lambda: service.events(world.operator, uuid4(), after_sequence=0, limit=10))

    assert same_response(other, missing)
    assert [
        event.sequence
        for event in service.events(world.team.viewer_a, scan.id, after_sequence=0, limit=10)
    ] == [1]
