"""容器只能在 run 開始執行時記下（docs/DECISIONS.md §14.6；DB 的 trigger 也這樣要求）。"""

from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from secscan.scans.domain.catalog import Engine
from secscan.scans.domain.lifecycle import RunErrorCode, RunStatus, ScanStatus
from secscan.scans.progress import ContainerAssignment, LockedScan, RunState, ScanProgress
from secscan.targets.domain import parse_origin

IMAGE = "busybox:1.38.0@sha256:" + "ab" * 32


@pytest.mark.parametrize(
    ("current", "to"),
    [
        (RunStatus.RUNNING, RunStatus.COLLECTING),
        (RunStatus.PREPARING, RunStatus.FAILED),
        (RunStatus.RUNNING, RunStatus.TIMED_OUT),
    ],
)
def test_a_container_is_refused_for_any_other_transition(current: RunStatus, to: RunStatus) -> None:
    run_id = uuid4()
    scan = LockedScan(
        id=uuid4(),
        project_id=uuid4(),
        target_id=uuid4(),
        target_origin=parse_origin("http://lab-a:5000"),
        scope_grant_id=uuid4(),
        auth_profile_id=None,
        auth_profile_version=None,
        created_by_key_id=uuid4(),
        max_duration_seconds=60,
        status=ScanStatus.RUNNING,
        cancel_requested=False,
    )
    run = RunState(id=run_id, scan_id=scan.id, engine=Engine.FAKE, sequence=1, status=current)
    container = ContainerAssignment(name=f"secscan-run-{run_id}", image_ref=IMAGE)
    error_code = None if to is RunStatus.COLLECTING else _error(to)

    # 檢查在任何 SQL 之前：沒有連線的 session 也不會被用到。
    with pytest.raises(ValueError, match="容器"):
        ScanProgress(Session()).move(scan, run, to, error_code=error_code, container=container)


def _error(to: RunStatus) -> RunErrorCode:
    return (
        RunErrorCode.ENGINE_FAILED if to is RunStatus.FAILED else RunErrorCode.TIME_LIMIT_EXCEEDED
    )
