"""guard 的 status（docs/DECISIONS.md §15.3）：guard 每 5 秒寫入，runner 據此判斷可不可用。"""

import json
from dataclasses import replace
from typing import Any
from uuid import UUID

import pytest

from secscan.guard.domain.policy import POLICY_SCHEMA
from secscan.guard.domain.status import (
    STATUS_FRESH_SECONDS,
    GuardStatus,
    StatusError,
    StatusIssue,
    decode_status,
    encode_status,
    status_issue,
)

BOOT = UUID("3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b")
NOW = 1_767_598_800
LISTEN = "10.89.8.254:8080"
STATUS = GuardStatus(
    boot_id=BOOT,
    started_at=NOW - 60,
    updated_at=NOW,
    listen=LISTEN,
    policy_schema=POLICY_SCHEMA,
    enforcing=True,
)


def _document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(encode_status(STATUS))
    document.update(overrides)
    return document


def test_round_trip() -> None:
    assert decode_status(encode_status(STATUS)) == STATUS


def test_encodes_a_flat_document() -> None:
    assert json.loads(encode_status(STATUS)) == {
        "schema": 1,
        "boot_id": str(BOOT),
        "started_at": NOW - 60,
        "updated_at": NOW,
        "listen": LISTEN,
        "policy_schema": POLICY_SCHEMA,
        "enforcing": True,
    }


@pytest.mark.parametrize(
    "document",
    [
        _document(schema=2),
        _document(extra=1),
        _document(boot_id=BOOT.hex),
        _document(updated_at=True),
        _document(updated_at=1.0),
        _document(enforcing=1),
        _document(listen=8080),
        [],
    ],
)
def test_rejects_malformed_status(document: object) -> None:
    with pytest.raises(StatusError):
        decode_status(json.dumps(document).encode())


def test_rejects_oversized_status() -> None:
    with pytest.raises(StatusError):
        decode_status(b" " * 10_000)


def test_fresh_enforcing_status_is_usable() -> None:
    assert status_issue(STATUS, now=NOW, listen=LISTEN) is None
    assert status_issue(STATUS, now=NOW + STATUS_FRESH_SECONDS, listen=LISTEN) is None


@pytest.mark.parametrize(
    ("status", "now", "issue"),
    [
        (None, NOW, StatusIssue.MISSING),
        (STATUS, NOW + STATUS_FRESH_SECONDS + 1, StatusIssue.STALE),
        (STATUS, NOW - STATUS_FRESH_SECONDS - 1, StatusIssue.STALE),  # 時間在未來：不可信
        (replace(STATUS, policy_schema=POLICY_SCHEMA + 1), NOW, StatusIssue.VERSION),
        (replace(STATUS, listen="10.89.8.253:8080"), NOW, StatusIssue.LISTEN),
        (replace(STATUS, enforcing=False), NOW, StatusIssue.NOT_ENFORCING),
    ],
)
def test_status_problems(status: GuardStatus | None, now: int, issue: StatusIssue) -> None:
    assert status_issue(status, now=now, listen=LISTEN) is issue
