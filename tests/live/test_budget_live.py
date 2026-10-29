"""共享預算與 telemetry 的 live 測試（docs/DECISIONS.md §16；SEC-13、SEC-15）。

在 live 的 lab 網路上啟動自己的接收端，經 runner 容器寫 policy、以 probe 從 scan_net 送請求：
- SEC-13：超過 max_requests 的請求不會到達 target（以接收端的紀錄為準），guard 的 summary 記下
  轉送數與用盡；同一個 scan 的請求依速率間隔。
- SEC-15：帶著目標憑證的請求只會轉送到 target 的 origin，其他 origin 收不到任何連線。
"""

import json
from collections.abc import Iterator
from typing import Any

import pytest

from tests.live.guard_support import (
    PORT,
    LivePolicy,
    Receiver,
    probe,
    raw_request,
    remove_policy,
    start_receiver,
    stop_receiver,
    write_policy,
)
from tests.live.support import container, docker, wait_for

pytestmark = pytest.mark.live

TARGET_IP = "10.89.10.202"
CANARY_IP = "10.89.10.203"
ORIGIN = f"http://lab-budget:{PORT}"
CANARY_ORIGIN = f"http://lab-budget-canary:{PORT}"
TOKEN = "Bearer budget-live-canary-token"


@pytest.fixture(scope="module")
def target() -> Iterator[Receiver]:
    receiver = start_receiver("budget-target", ip=TARGET_IP, aliases=("lab-budget",))
    yield receiver
    stop_receiver(receiver)


@pytest.fixture(scope="module")
def canary() -> Iterator[Receiver]:
    receiver = start_receiver("budget-canary", ip=CANARY_IP, aliases=("lab-budget-canary",))
    yield receiver
    stop_receiver(receiver)


def _policy(max_requests: int) -> LivePolicy:
    return write_policy(origin=ORIGIN, ips=(TARGET_IP,), max_requests=max_requests)


def _get(origin: str, path: str, policy: LivePolicy, **options: Any) -> bytes:
    host = origin.removeprefix("http://")
    return raw_request(
        f"{origin}{path}", host=host, authorization=policy.authorization(), **options
    )


def _telemetry(name: str) -> str:
    """runner 唯讀掛載 guard 的 telemetry（§16.3）：從 runner 容器讀。"""
    return docker("exec", container("runner"), "cat", f"/guard/telemetry/{name}")


def _flushed_summary(run_id: str) -> dict[str, Any] | None:
    """拒絕的計數由 guard 每 5 秒寫入一次：等到 summary 中有拒絕的計數。"""
    summary: dict[str, Any] = json.loads(_telemetry(f"{run_id}.summary.json"))
    return summary if summary["denied"] else None


def test_requests_beyond_the_budget_never_reach_the_target(target: Receiver) -> None:
    """SEC-13：上限 3，送 5 個允許的請求：前 3 個到達 target，之後都是 BUDGET_EXHAUSTED。"""
    policy = _policy(max_requests=3)
    before = len(target.records())
    try:
        results = probe(
            [(f"r{index}", _get(ORIGIN, f"/api/items/{index}", policy)) for index in range(5)]
        )
        summary = wait_for(lambda: _flushed_summary(policy.run_id), timeout=20)
        lines = _telemetry(f"{policy.run_id}.jsonl")
    finally:
        remove_policy(policy)

    statuses = [
        (results[f"r{index}"]["status"], results[f"r{index}"]["reason"]) for index in range(5)
    ]
    assert statuses == [(200, None)] * 3 + [(403, "BUDGET_EXHAUSTED")] * 2
    assert target.paths()[before:] == ["/api/items/0", "/api/items/1", "/api/items/2"]
    assert (summary["forwarded"], summary["exhausted"]) == (3, True)
    assert summary["denied"] == {"BUDGET_EXHAUSTED": 2}
    # 2 req/s：三個轉送的請求至少間隔 0.5 秒（第一個不等待）。
    assert summary["last_at"] - summary["first_at"] >= 0.95
    events = [json.loads(line)["e"] for line in lines.splitlines()]
    assert events.count("request") == 3
    assert events.count("response") == 3
    assert "budget-live-canary-token" not in lines


def test_target_credentials_go_only_to_the_approved_origin(
    target: Receiver, canary: Receiver
) -> None:
    """SEC-15：帶著 Authorization 的請求只轉送到 target 的 origin；其他 origin 連一個連線都沒有。"""
    policy = _policy(max_requests=100)
    before, canary_before = len(target.records()), len(canary.records())
    headers = [("Authorization", TOKEN)]
    try:
        results = probe(
            [
                ("target", _get(ORIGIN, "/api/items/1", policy, headers=headers)),
                ("other", _get(CANARY_ORIGIN, "/api/items/1", policy, headers=headers)),
            ]
        )
    finally:
        remove_policy(policy)

    assert (results["target"]["status"], results["other"]["reason"]) == (200, "ORIGIN_MISMATCH")
    [record] = target.records()[before:]
    assert "Authorization" in record["header_names"]
    assert canary.records()[canary_before:] == []
    assert "budget-live-canary-token" not in docker("logs", target.container)
