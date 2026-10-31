"""guard addon 測試共用的 harness：policy 目錄、telemetry 目錄、假的 resolver、時鐘與等待。

速率的等待以假的 sleep 記下並推進 monotonic 時鐘，測試不會真的等待。
"""

import asyncio
import base64
import io
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.addon import GuardAddon
from secscan.guard.domain.budget import RateLimiter, RunBudget
from secscan.guard.domain.credentials import token_digest
from secscan.guard.domain.policy import (
    GuardPolicyVersion,
    Policy,
    PolicyState,
    encode_policy,
    policy_file_name,
)
from secscan.guard.events import GuardLog, guard_logger
from secscan.guard.files import write_atomic
from secscan.guard.store import PolicyStore
from secscan.guard.telemetry import TelemetryRecorder
from secscan.targets.domain import LabNetwork, parse_ipv4, parse_origin
from tests.unit.guard.flows import FakeClient, FakeFlow, FakeRequest, FakeResponse, make_response

RUN_ID = UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")
SCAN_ID = UUID("0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d")
BOOT_ID = UUID("3c4d5e6f-7081-4293-a4b5-c6d7e8f90a1b")
TOKEN = "T" * 31 + "okenValue-_1"  # token_urlsafe(32)：43 個字元
NOW = 1_767_598_800
LAB = LabNetwork(IPv4Network("10.89.7.0/24"))
SCAN_NET = IPv4Network("10.89.8.0/24")
GUARD_IPS = frozenset({IPv4Address("10.89.7.254"), IPv4Address("10.89.8.254")})


def proxy_authorization(run_id: UUID = RUN_ID, token: str = TOKEN) -> str:
    return "Basic " + base64.b64encode(f"{run_id}:{token}".encode()).decode()


def make_policy(
    *,
    origin: str = "http://lab-target:8080",
    state: PolicyState = PolicyState.ACTIVE,
    token: str = TOKEN,
    not_after: int = NOW + 600,
    renew_until: int = NOW + 30,
    ips: tuple[str, ...] = ("10.89.7.20",),
    max_requests: int = 100,
    auth_header: str | None = "authorization",
    run_id: UUID = RUN_ID,
) -> Policy:
    return Policy(
        policy_version=GuardPolicyVersion.STRICT,
        run_id=run_id,
        scan_id=SCAN_ID,
        state=state,
        token_sha256=token_digest(token),
        not_after=not_after,
        renew_until=renew_until,
        scope=Scope(
            origins=(parse_origin(origin),),
            ips=tuple(parse_ipv4(ip) for ip in ips),
            paths=("/api/items/{id}", "/api/items"),
            allow_all_paths=False,
            excluded_paths=("/api/admin",),
            methods=(HttpMethod.GET, HttpMethod.POST),
        ),
        budget=RunBudget(requests_per_second=2, burst=1, max_requests=max_requests),
        auth_header=auth_header,
    )


@dataclass
class Resolver:
    answers: tuple[str, ...] | BaseException = ("10.89.7.20",)
    calls: list[str] = field(default_factory=list)

    async def __call__(self, host: str) -> tuple[str, ...]:
        self.calls.append(host)
        if isinstance(self.answers, BaseException):
            raise self.answers
        return self.answers


@dataclass
class Harness:
    directory: Path
    telemetry: Path
    resolver: Resolver
    addon: GuardAddon
    recorder: TelemetryRecorder
    stream: io.StringIO
    clock: list[float]
    monotonic: list[float]
    sleeps: list[float]

    def write(self, policy: Policy) -> None:
        write_atomic(self.directory, policy_file_name(policy.run_id), encode_policy(policy))

    def lines(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]


def build_harness(
    tmp_path: Path,
    *,
    limiter: RateLimiter | None = None,
    on_sleep: Callable[[], None] = lambda: None,
) -> Harness:
    stream = io.StringIO()
    resolver = Resolver()
    clock = [float(NOW)]
    monotonic = [1_000.0]
    sleeps: list[float] = []
    telemetry = tmp_path / "telemetry"
    telemetry.mkdir()
    recorder = TelemetryRecorder(telemetry, boot_id=BOOT_ID, clock=lambda: clock[0])

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        on_sleep()
        monotonic[0] += seconds
        clock[0] += seconds

    addon = GuardAddon(
        store=PolicyStore(tmp_path),
        resolve=resolver,
        lab=LAB,
        scan_network=SCAN_NET,
        guard_ips=GUARD_IPS,
        make_response=make_response,
        recorder=recorder,
        limiter=limiter or RateLimiter(),
        clock=lambda: clock[0],
        monotonic=lambda: monotonic[0],
        sleep=sleep,
        log=GuardLog(guard_logger(f"test-{uuid4().hex}", stream)),
    )
    harness = Harness(
        tmp_path, telemetry, resolver, addon, recorder, stream, clock, monotonic, sleeps
    )
    harness.write(make_policy())
    return harness


def make_flow(
    target: str = "/api/items/7",
    *,
    method: str = "GET",
    host: str = "lab-target",
    port: int = 8080,
    headers: list[tuple[str, str]] | None = None,
    authorization: str | bool | None = None,
    client: FakeClient | None = None,
) -> FakeFlow:
    fields = headers if headers is not None else [("Host", f"{host}:{port}")]
    if authorization is not False:
        value = authorization if isinstance(authorization, str) else proxy_authorization()
        fields = [*fields, ("Proxy-Authorization", value)]
    return FakeFlow(
        request=FakeRequest(method=method, target=target, host=host, port=port, headers=fields),
        client_conn=client or FakeClient(),
    )


def screen(harness: Harness, flow: FakeFlow) -> FakeFlow:
    asyncio.run(harness.addon.requestheaders(flow))
    return flow


def denied(flow: FakeFlow) -> FakeResponse:
    assert isinstance(flow.response, FakeResponse)
    return flow.response


def reason_of(flow: FakeFlow) -> str:
    return denied(flow).headers["X-Secscan-Guard"]
