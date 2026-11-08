"""TriageRecords 的防禦分支（T21）：找不到 finding、版本已改變、沒有事件時不查摘錄。"""

from uuid import uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.core.pagination import PageRequest
from secscan.findings.domain.model import LifecycleState, TriageState
from secscan.findings.domain.triage import TriageStatus
from secscan.findings.triage_records import StaleTriageVersionError, TriageRecords
from tests.integration.api_support import Seeder
from tests.integration.triage_support import scenario

pytestmark = pytest.mark.integration


def test_missing_findings_stale_versions_and_empty_histories(
    queue_engine: Engine, queue_seed: Seeder
) -> None:
    item = scenario(queue_engine, queue_seed, queue_seed.world())
    with sessionmaker(queue_engine).begin() as session:
        records = TriageRecords(session)
        assert records.lock(uuid4()) is None
        # 版本 0 的 finding：以「版本 2」的變更套用（預期目前是 1）一定失敗，不改任何東西。
        stale = TriageStatus(TriageState.CONFIRMED, LifecycleState.OPEN, 2)
        with pytest.raises(StaleTriageVersionError):
            records.apply(item.sqli, stale)
        history = records.events(item.sqli, PageRequest(page=1, limit=10), with_excerpts=True)
        assert (history.total, history.items) == (0, ())
    [row] = queue_seed.query(
        "SELECT triage_state, triage_version FROM findings WHERE id = :id", id=item.sqli
    )
    assert (row.triage_state, row.triage_version) == ("unreviewed", 0)
