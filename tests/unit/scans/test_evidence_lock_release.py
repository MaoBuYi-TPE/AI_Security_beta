"""advisory lock 的釋放（資料庫審查 L7；docs/DECISIONS.md §30.11）：失敗時讓連線失效，不蓋掉
原本的例外。替身連線，不連 DB。"""

import logging
from typing import Any

import pytest
from sqlalchemy.exc import OperationalError

from secscan.scans.evidence_records import _release


class FakeConnection:
    def __init__(self, *, broken: bool) -> None:
        self.broken = broken
        self.invalidated = False
        self.committed = False

    def scalar(self, _statement: Any) -> bool:
        if self.broken:
            raise OperationalError("SELECT pg_advisory_unlock", {}, Exception("connection lost"))
        return True

    def commit(self) -> None:
        self.committed = True

    def invalidate(self) -> None:
        self.invalidated = True


def test_a_failed_unlock_invalidates_the_connection(caplog: pytest.LogCaptureFixture) -> None:
    connection = FakeConnection(broken=True)
    caplog.set_level(logging.WARNING)

    _release(connection)  # type: ignore[arg-type]

    assert connection.invalidated
    assert "OperationalError" in caplog.text
    assert "connection lost" not in caplog.text


def test_a_normal_unlock_keeps_the_connection() -> None:
    connection = FakeConnection(broken=False)

    _release(connection)  # type: ignore[arg-type]

    assert (connection.committed, connection.invalidated) == (True, False)
