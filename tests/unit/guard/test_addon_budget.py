"""guard 的共享預算、速率與 telemetry（docs/DECISIONS.md §16；SEC-13、SEC-15）。

- 名額在 requestheaders 保留（DNS 之前），request hook 確定轉送並寫一行；
  任何拒絕、錯誤與取消都釋放。
- 同一個 scan 的請求依速率等待，最多 5 秒；等待之後重新確認 run 的狀態。
- 轉送的請求記下是否帶著 policy 的認證 header；path 不含 query。
- 寫不出 telemetry 的請求不放行（沒有紀錄的流量會讓剩下的預算不可信）。
"""

import asyncio
import os
from pathlib import Path

import pytest

from secscan.guard.addon import PENDING_KEY, Pending
from secscan.guard.domain.budget import RateLimiter, max_pending
from secscan.guard.domain.policy import PolicyState
from secscan.guard.domain.telemetry import (
    ForwardedRequest,
    UpstreamResponse,
    decode_line,
    decode_summary,
    summary_file_name,
    telemetry_file_name,
)
from secscan.guard.telemetry import TelemetryWriteError
from tests.unit.guard.addon_support import (
    NOW,
    RUN_ID,
    SCAN_ID,
    Harness,
    build_harness,
    make_flow,
    make_policy,
    reason_of,
    screen,
)
from tests.unit.guard.flows import FakeFlow, FakeHeaders, FakeResponse

MAX_PENDING = 11  # 每秒 2 個、最多等 5 秒，再加 burst 1


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    return build_harness(tmp_path)


def _send(harness: Harness, flow: FakeFlow, *, status: int = 200) -> FakeFlow:
    """完整走一次：requestheaders → request → 上游回應。"""
    screen(harness, flow)
    if flow.response is None:
        harness.addon.request(flow)
    if flow.response is None:
        flow.response = FakeResponse(status_code=status, content=b"", headers={})
        harness.addon.response(flow)
    return flow


def _records(harness: Harness) -> list[object]:
    path = harness.telemetry / telemetry_file_name(RUN_ID)
    if not path.exists():
        return []
    return [decode_line(line) for line in path.read_bytes().splitlines(keepends=True)]


def _summary(harness: Harness) -> object:
    raw = (harness.telemetry / summary_file_name(RUN_ID)).read_bytes()
    return decode_summary(raw, run_id=RUN_ID)


# --- telemetry --------------------------------------------------------------------------------


def test_forwarded_requests_and_responses_are_recorded(harness: Harness) -> None:
    flow = make_flow(headers=[("Host", "lab-target:8080"), ("Authorization", "Bearer x")])

    _send(harness, flow, status=201)

    assert isinstance(flow.response, FakeResponse)
    assert flow.response.status_code == 201
    assert _records(harness) == [
        ForwardedRequest(sequence=1, at=NOW, method="GET", path="/api/items/7", authenticated=True),
        UpstreamResponse(sequence=1, at=NOW, status=201),
    ]
    summary = _summary(harness)
    assert summary.forwarded == 1  # type: ignore[attr-defined]
    assert summary.scan_id == SCAN_ID  # type: ignore[attr-defined]


def test_requests_without_the_auth_header_are_anonymous(harness: Harness) -> None:
    _send(harness, make_flow())
    harness.write(make_policy(auth_header=None))
    harness.clock[0] += 1
    _send(harness, make_flow(headers=[("Host", "lab-target:8080"), ("Authorization", "x")]))

    flags = [r.authenticated for r in _records(harness) if isinstance(r, ForwardedRequest)]
    assert flags == [False, False]


def test_custom_auth_headers_are_matched_case_insensitively(harness: Harness) -> None:
    harness.write(make_policy(auth_header="x-api-key"))

    _send(harness, make_flow(headers=[("Host", "lab-target:8080"), ("X-API-Key", "k")]))

    [request, _] = _records(harness)
    assert request.authenticated is True  # type: ignore[attr-defined]


def test_queries_and_header_values_are_not_recorded(harness: Harness) -> None:
    _send(
        harness,
        make_flow(
            "/api/items/7?apikey=QUERY-CANARY",
            headers=[("Host", "lab-target:8080"), ("Authorization", "Bearer HEADER-CANARY")],
        ),
    )

    [request, _] = _records(harness)
    assert request.path == "/api/items/7"  # type: ignore[attr-defined]
    for name in os.listdir(harness.telemetry):
        content = (harness.telemetry / name).read_bytes()
        assert b"CANARY" not in content


def test_denials_are_counted_for_the_authenticated_run_only(harness: Harness) -> None:
    screen(harness, make_flow("/api/admin"))
    screen(harness, make_flow(authorization=False))  # 407：不知道是哪個 run，不計

    harness.addon.flush_telemetry()

    summary = _summary(harness)
    assert summary.denied == {"PATH_EXCLUDED": 1}  # type: ignore[attr-defined]
    assert summary.forwarded == 0  # type: ignore[attr-defined]
    assert _records(harness) == []


def test_telemetry_write_failures_deny_the_request(harness: Harness) -> None:
    flow = make_flow()
    screen(harness, flow)
    os.chmod(harness.telemetry, 0o500)
    try:
        harness.addon.request(flow)
    finally:
        os.chmod(harness.telemetry, 0o700)

    assert reason_of(flow) == "GUARD_ERROR"


def test_unreadable_telemetry_fails_closed(harness: Harness) -> None:
    (harness.telemetry / summary_file_name(RUN_ID)).write_bytes(b"{")

    flow = screen(harness, make_flow())

    assert reason_of(flow) == "GUARD_ERROR"
    assert harness.resolver.calls == []


# --- 請求數 -----------------------------------------------------------------------------------


def test_the_budget_caps_forwarded_requests(harness: Harness) -> None:
    harness.write(make_policy(max_requests=2))
    for _ in range(2):
        _send(harness, make_flow())
    calls = len(harness.resolver.calls)

    third = screen(harness, make_flow())

    assert reason_of(third) == "BUDGET_EXHAUSTED"
    assert len(harness.resolver.calls) == calls  # 用盡時不解析 DNS
    harness.addon.flush_telemetry()
    summary = _summary(harness)
    assert summary.forwarded == 2  # type: ignore[attr-defined]
    assert summary.exhausted is True  # type: ignore[attr-defined]
    assert summary.denied == {"BUDGET_EXHAUSTED": 1}  # type: ignore[attr-defined]


def test_a_run_without_budget_left_forwards_nothing(harness: Harness) -> None:
    harness.write(make_policy(max_requests=0))

    flow = screen(harness, make_flow())

    assert reason_of(flow) == "BUDGET_EXHAUSTED"
    assert harness.resolver.calls == []


def test_pending_requests_hold_their_reservation(harness: Harness) -> None:
    harness.write(make_policy(max_requests=1))
    first = screen(harness, make_flow())

    second = screen(harness, make_flow())

    assert first.response is None
    assert reason_of(second) == "BUDGET_EXHAUSTED"


def _blocked_after_screening(harness: Harness, flow: FakeFlow) -> None:
    harness.write(make_policy(max_requests=1, state=PolicyState.BLOCKED))
    harness.addon.request(flow)
    harness.write(make_policy(max_requests=1))


def _error_after_screening(harness: Harness, flow: FakeFlow) -> None:
    harness.addon.error(flow)


def _trailers_after_screening(harness: Harness, flow: FakeFlow) -> None:
    flow.request.trailers = FakeHeaders([("X-Late", "1")])
    harness.addon.request(flow)


@pytest.mark.parametrize(
    "outcome", [_blocked_after_screening, _error_after_screening, _trailers_after_screening]
)
def test_requests_that_are_not_forwarded_release_their_reservation(
    harness: Harness, outcome: object
) -> None:
    harness.write(make_policy(max_requests=1))
    first = screen(harness, make_flow())
    outcome(harness, first)  # type: ignore[operator]

    second = _send(harness, make_flow())

    assert isinstance(second.response, FakeResponse)
    assert second.response.status_code == 200
    assert [r.sequence for r in _records(harness) if isinstance(r, ForwardedRequest)] == [1]


def test_dns_failures_release_their_reservation(harness: Harness) -> None:
    harness.write(make_policy(max_requests=1))
    harness.resolver.answers = ()
    assert reason_of(screen(harness, make_flow())) == "ADDRESS_NOT_ALLOWED"
    harness.resolver.answers = ("10.89.7.20",)

    assert screen(harness, make_flow()).response is None


def test_cancelled_screening_releases_its_reservation(tmp_path: Path) -> None:
    def cancel() -> None:
        raise asyncio.CancelledError

    harness = build_harness(tmp_path, on_sleep=cancel)
    harness.write(make_policy(max_requests=2))
    screen(harness, make_flow())
    with pytest.raises(asyncio.CancelledError):
        screen(harness, make_flow())  # 第二個要等待：等待中被取消
    harness.monotonic[0] += 10

    assert screen(harness, make_flow()).response is None


# --- 速率 -------------------------------------------------------------------------------------


def test_requests_wait_for_the_shared_rate(harness: Harness) -> None:
    for _ in range(3):
        assert screen(harness, make_flow()).response is None

    assert harness.sleeps == [0.5, 0.5]


def test_requests_that_would_wait_too_long_are_rate_limited(tmp_path: Path) -> None:
    harness = build_harness(tmp_path, limiter=RateLimiter(max_wait=0.4))
    harness.write(make_policy(max_requests=2))
    screen(harness, make_flow())

    limited = screen(harness, make_flow())

    assert reason_of(limited) == "RATE_LIMITED"
    assert harness.resolver.calls == ["lab-target"]
    harness.monotonic[0] += 1
    assert screen(harness, make_flow()).response is None  # 被拒絕的不佔名額


def test_the_run_is_checked_again_after_waiting(tmp_path: Path) -> None:
    holder: list[Harness] = []
    harness = build_harness(
        tmp_path,
        on_sleep=lambda: holder[0].write(make_policy(state=PolicyState.BLOCKED)),
    )
    holder.append(harness)
    screen(harness, make_flow())

    waited = screen(harness, make_flow())

    assert reason_of(waited) == "RUN_BLOCKED"
    assert harness.resolver.calls == ["lab-target"]


def test_denial_counting_failures_still_deny(harness: Harness) -> None:
    (harness.telemetry / summary_file_name(RUN_ID)).write_bytes(b"{")

    flow = screen(harness, make_flow("/api/admin"))

    assert reason_of(flow) == "PATH_EXCLUDED"
    assert any(line.get("hook") == "telemetry_denied" for line in harness.lines())


def test_release_failures_are_logged(harness: Harness) -> None:
    flow = make_flow()
    flow.metadata[PENDING_KEY] = Pending(
        policy=make_policy(), method="GET", path="/api/items/7", authenticated=False
    )

    harness.addon.error(flow)  # 這個 run 從沒保留過名額

    assert any(line.get("hook") == "release" for line in harness.lines())


def test_flush_failures_are_logged(harness: Harness) -> None:
    screen(harness, make_flow("/api/admin"))
    os.chmod(harness.telemetry, 0o500)
    try:
        harness.addon.flush_telemetry()
    finally:
        os.chmod(harness.telemetry, 0o700)

    assert any(line.get("event") == "telemetry_flush_failed" for line in harness.lines())


def test_pruning_still_runs_when_flushing_fails(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """volume 寫滿時最需要清理：summary 寫不出來也要刪掉過期的檔案（審查發現）。"""
    pruned: list[bool] = []

    def fail() -> None:
        raise TelemetryWriteError("1 個 summary 寫不出來")

    monkeypatch.setattr(harness.recorder, "flush", fail)

    def prune() -> int:
        pruned.append(True)
        return 0

    monkeypatch.setattr(harness.recorder, "prune", prune)

    harness.addon.flush_telemetry()

    assert pruned == [True]
    assert any(line.get("event") == "telemetry_flush_failed" for line in harness.lines())


def test_prune_failures_are_logged(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail() -> int:
        raise TelemetryWriteError("1 個過期的檔案刪不掉")

    monkeypatch.setattr(harness.recorder, "prune", fail)

    harness.addon.flush_telemetry()

    assert any(line.get("event") == "telemetry_prune_failed" for line in harness.lines())


def test_requests_held_back_by_their_body_cannot_pile_up(tmp_path: Path) -> None:
    """名額在 header 階段保留、body 送完才轉送：延遲 body 可以累積已核准的請求再一次送出
    （審查發現）。保留中的名額最多 速率乘以最長等待再加 burst 個，之後回 RATE_LIMITED。"""
    harness = build_harness(tmp_path, limiter=RateLimiter(max_wait=1_000))
    harness.write(make_policy(max_requests=100))
    held = [screen(harness, make_flow()) for _ in range(MAX_PENDING)]
    assert all(flow.response is None for flow in held)

    extra = screen(harness, make_flow())

    assert reason_of(extra) == "RATE_LIMITED"
    harness.addon.request(held[0])  # body 送完、轉送：空出一個名額
    assert screen(harness, make_flow()).response is None


def test_the_pending_limit_follows_the_rate() -> None:
    budget = make_policy().budget

    assert max_pending(budget) == MAX_PENDING == 2 * 5 + 1
