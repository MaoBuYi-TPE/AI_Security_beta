"""guard 的 mitmproxy addon（docs/DECISIONS.md §15.5）：以假的 flow 驅動每個 hook。

- 放行：刪除 Proxy-*、連線綁定到驗證過的 IP、Host 寫回 canonical、記下核准。
- 拒絕：帳密與 policy 的問題一律 407（附 Proxy-Authenticate）；其餘 403 加上 X-Secscan-Guard。
- 任何例外都拒絕；放行要有正向的核准紀錄，後面的 hook 找不到就拒絕（mitmproxy 吞掉例外後會放行）。
"""

import asyncio
import base64
import io
import json
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest

from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.addon import APPROVAL_KEY, DENIAL_KEY, Approval, GuardAddon
from secscan.guard.domain.credentials import token_digest
from secscan.guard.domain.policy import Policy, PolicyState, encode_policy, policy_file_name
from secscan.guard.events import GuardLog, guard_logger
from secscan.guard.files import remove_file, write_atomic
from secscan.guard.resolver import ResolveError
from secscan.guard.store import PolicyStore
from secscan.targets.domain import LabNetwork, parse_ipv4, parse_origin
from tests.unit.guard.flows import (
    FakeClient,
    FakeFlow,
    FakeHeaders,
    FakeRequest,
    FakeResponse,
    FakeServer,
    FakeServerConnection,
    make_response,
)

RUN_ID = UUID("6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")
TOKEN = "T" * 31 + "okenValue-_1"  # token_urlsafe(32)：43 個字元
NOW = 1_767_598_800
LAB = LabNetwork(IPv4Network("10.89.7.0/24"))
SCAN_NET = IPv4Network("10.89.8.0/24")
GUARD_IPS = frozenset({IPv4Address("10.89.7.254"), IPv4Address("10.89.8.254")})


def _authorization(run_id: UUID = RUN_ID, token: str = TOKEN) -> str:
    return "Basic " + base64.b64encode(f"{run_id}:{token}".encode()).decode()


def _policy(
    *,
    origin: str = "http://lab-target:8080",
    state: PolicyState = PolicyState.ACTIVE,
    token: str = TOKEN,
    not_after: int = NOW + 600,
    renew_until: int = NOW + 30,
    ips: tuple[str, ...] = ("10.89.7.20",),
) -> Policy:
    return Policy(
        run_id=RUN_ID,
        scan_id=uuid4(),
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
    resolver: Resolver
    addon: GuardAddon
    stream: io.StringIO
    clock: list[float]

    def write(self, policy: Policy) -> None:
        write_atomic(self.directory, policy_file_name(policy.run_id), encode_policy(policy))

    def lines(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.stream.getvalue().splitlines()]


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    stream = io.StringIO()
    resolver = Resolver()
    clock = [float(NOW)]
    addon = GuardAddon(
        store=PolicyStore(tmp_path),
        resolve=resolver,
        lab=LAB,
        scan_network=SCAN_NET,
        guard_ips=GUARD_IPS,
        make_response=make_response,
        clock=lambda: clock[0],
        log=GuardLog(guard_logger(f"test-{uuid4().hex}", stream)),
    )
    result = Harness(tmp_path, resolver, addon, stream, clock)
    result.write(_policy())
    return result


def _flow(
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
        value = authorization if isinstance(authorization, str) else _authorization()
        fields = [*fields, ("Proxy-Authorization", value)]
    return FakeFlow(
        request=FakeRequest(method=method, target=target, host=host, port=port, headers=fields),
        client_conn=client or FakeClient(),
    )


def _screen(harness: Harness, flow: FakeFlow) -> FakeFlow:
    asyncio.run(harness.addon.requestheaders(flow))
    return flow


def _denied(flow: FakeFlow) -> FakeResponse:
    assert isinstance(flow.response, FakeResponse)
    return flow.response


def _reason(flow: FakeFlow) -> str:
    return _denied(flow).headers["X-Secscan-Guard"]


# --- 放行 -------------------------------------------------------------------------------------


def test_allowed_request_is_bound_to_the_verified_ip(harness: Harness) -> None:
    flow = _flow(headers=[("Host", "lab-target:8080"), ("Proxy-Connection", "keep-alive")])

    _screen(harness, flow)

    assert flow.response is None
    assert flow.request.host == "10.89.7.20"
    assert flow.request.port == 8080
    assert flow.request.headers.get_all("host") == ["lab-target:8080"]
    assert [
        name for name in flow.request.headers.names() if name.lower().startswith("proxy-")
    ] == []
    assert flow.metadata[APPROVAL_KEY] == Approval(RUN_ID, "10.89.7.20", 8080)
    assert harness.resolver.calls == ["lab-target"]


def test_port_80_origins_get_the_short_host(harness: Harness) -> None:
    harness.write(_policy(origin="http://lab-target"))
    flow = _flow(port=80, headers=[("Host", "lab-target")])

    _screen(harness, flow)

    assert flow.response is None
    assert flow.request.headers.get_all("host") == ["lab-target"]


def test_ip_origins_are_not_resolved(harness: Harness) -> None:
    harness.write(_policy(origin="http://10.89.7.20:3000"))
    flow = _flow(host="10.89.7.20", port=3000)

    _screen(harness, flow)

    assert flow.response is None
    assert harness.resolver.calls == []
    assert flow.request.headers.get_all("host") == ["10.89.7.20:3000"]


def test_allowed_request_is_logged_without_secrets(harness: Harness) -> None:
    flow = _flow(
        "/api/items/7?apikey=QUERY-CANARY",
        headers=[("Host", "lab-target:8080"), ("Authorization", "Bearer HEADER-CANARY")],
    )

    _screen(harness, flow)

    [line] = harness.lines()
    assert line["event"] == "request"
    assert line["decision"] == "allow"
    assert line["run_id"] == str(RUN_ID)
    assert (line["method"], line["host"], line["port"], line["path"]) == (
        "GET",
        "lab-target",
        8080,
        "/api/items/7",
    )
    assert line["upstream"] == "10.89.7.20"
    text = harness.stream.getvalue()
    for canary in ("QUERY-CANARY", "HEADER-CANARY", TOKEN, _authorization()):
        assert canary not in text


# --- 帳密與 policy：407 ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("authorization", "detail"),
    [
        (False, "CREDENTIALS_INVALID"),
        ("Basic bm9wZQ==", "CREDENTIALS_INVALID"),
        (_authorization(token="W" * 43), "TOKEN_MISMATCH"),
        (_authorization(run_id=uuid4()), "RUN_NOT_ACTIVE"),
    ],
)
def test_credential_problems_are_407(harness: Harness, authorization: Any, detail: str) -> None:
    flow = _screen(harness, _flow(authorization=authorization))

    response = _denied(flow)
    assert response.status_code == 407
    assert response.headers["Proxy-Authenticate"] == 'Basic realm="secscan-guard"'
    assert response.headers["X-Secscan-Guard"] == "PROXY_AUTH_REQUIRED"
    [line] = harness.lines()
    assert line["detail"] == detail
    assert "run_id" not in line or line["run_id"] is None
    assert harness.resolver.calls == []


def test_corrupt_policy_is_407(harness: Harness) -> None:
    remove_file(harness.directory, policy_file_name(RUN_ID))
    write_atomic(harness.directory, policy_file_name(RUN_ID), b"{broken")

    flow = _screen(harness, _flow())

    assert _denied(flow).status_code == 407
    assert harness.lines()[0]["detail"] == "POLICY_INVALID"


# --- run 的狀態、請求本身：403 ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("policy", "reason"),
    [
        (_policy(state=PolicyState.BLOCKED), "RUN_BLOCKED"),
        (_policy(not_after=NOW), "RUN_EXPIRED"),
        (_policy(renew_until=NOW), "POLICY_STALE"),
    ],
)
def test_run_state_is_403(harness: Harness, policy: Policy, reason: str) -> None:
    harness.write(policy)

    flow = _screen(harness, _flow())

    assert _denied(flow).status_code == 403
    assert _reason(flow) == reason
    assert harness.lines()[0]["run_id"] == str(RUN_ID)


@pytest.mark.parametrize(
    ("flow", "reason"),
    [
        (_flow(host="lab-canary", headers=[("Host", "lab-canary:8080")]), "ORIGIN_MISMATCH"),
        (_flow(headers=[("Host", "other:1")]), "ORIGIN_MISMATCH"),
        (_flow("/api/admin"), "PATH_EXCLUDED"),
        (_flow(method="DELETE"), "METHOD_NOT_AUTHORIZED"),
        (_flow("/elsewhere"), "PATH_NOT_AUTHORIZED"),
        (_flow("/api/%2e%2e/admin"), "PATH_AMBIGUOUS"),
        (_flow(headers=[("Host", "lab-target:8080"), ("X-Original-URL", "/a")]), "OVERRIDE_HEADER"),
        (_flow(headers=[("Host", "lab-target:8080"), ("Upgrade", "websocket")]), "UPGRADE_DENIED"),
    ],
)
def test_requests_outside_the_grant_are_403(harness: Harness, flow: FakeFlow, reason: str) -> None:
    _screen(harness, flow)

    assert _denied(flow).status_code == 403
    assert _reason(flow) == reason
    assert APPROVAL_KEY not in flow.metadata
    assert harness.resolver.calls == []  # 不在範圍內就不解析（不替 client 查任何名稱）
    assert flow.request.host != "10.89.7.20"


@pytest.mark.parametrize(
    ("answers", "reason"),
    [
        (("10.89.7.20", "10.89.7.99"), "ADDRESS_NOT_ALLOWED"),
        (("10.89.7.254",), "ADDRESS_NOT_ALLOWED"),
        ((), "ADDRESS_NOT_ALLOWED"),
        (ResolveError("DNS 解析失敗"), "DNS_FAILED"),
    ],
)
def test_dns_answers_are_checked(
    harness: Harness, answers: tuple[str, ...] | BaseException, reason: str
) -> None:
    harness.resolver.answers = answers

    flow = _screen(harness, _flow())

    assert _reason(flow) == reason
    assert harness.resolver.calls == ["lab-target"]


def test_ip_origin_outside_the_current_lab_is_denied(harness: Harness) -> None:
    harness.write(_policy(origin="http://10.89.9.20:3000", ips=("10.89.9.20",)))

    flow = _screen(harness, _flow(host="10.89.9.20", port=3000))

    assert _reason(flow) == "ADDRESS_NOT_ALLOWED"


# --- 例外：一律拒絕 ---------------------------------------------------------------------------


def test_unexpected_errors_deny(harness: Harness) -> None:
    harness.resolver.answers = RuntimeError("boom SECRET-IN-MESSAGE")

    flow = _screen(harness, _flow())

    assert _reason(flow) == "GUARD_ERROR"
    assert APPROVAL_KEY not in flow.metadata
    assert "SECRET-IN-MESSAGE" not in harness.stream.getvalue()
    assert {"event": "hook_failed", "hook": "requestheaders", "error": "RuntimeError"}.items() <= (
        next(line for line in harness.lines() if line["event"] == "hook_failed").items()
    )


def test_a_failing_response_factory_kills_the_flow(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object) -> object:
        raise RuntimeError("factory")

    monkeypatch.setattr(harness.addon, "_make_response", broken)
    flow = _flow(authorization=False)

    _screen(harness, flow)

    assert flow.killed
    assert flow.response is None


def test_cancellation_is_not_swallowed(harness: Harness) -> None:
    harness.resolver.answers = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        _screen(harness, _flow())


# --- request hook：第二道 ---------------------------------------------------------------------


def _approved(harness: Harness) -> FakeFlow:
    flow = _screen(harness, _flow())
    assert flow.response is None
    return flow


def test_request_hook_passes_an_approved_flow(harness: Harness) -> None:
    flow = _approved(harness)

    harness.addon.request(flow)

    assert flow.response is None


def test_request_hook_leaves_denied_flows_alone(harness: Harness) -> None:
    flow = _screen(harness, _flow("/api/admin"))
    first = flow.response

    harness.addon.request(flow)

    assert flow.response is first


def test_request_hook_denies_flows_without_approval(harness: Harness) -> None:
    flow = _flow()

    harness.addon.request(flow)

    assert _reason(flow) == "NOT_APPROVED"


def test_request_hook_denies_a_retargeted_flow(harness: Harness) -> None:
    flow = _approved(harness)
    flow.request.host = "10.89.7.21"

    harness.addon.request(flow)

    assert _reason(flow) == "NOT_APPROVED"


@pytest.mark.parametrize("change", ["block", "remove", "expire"])
def test_request_hook_rechecks_the_run(harness: Harness, change: str) -> None:
    """requestheaders 之後、讀完 body 之前，run 被封鎖（例如取消）。"""
    flow = _approved(harness)
    if change == "block":
        harness.write(_policy(state=PolicyState.BLOCKED))
    elif change == "remove":
        remove_file(harness.directory, policy_file_name(RUN_ID))
    else:
        harness.clock[0] = NOW + 30

    harness.addon.request(flow)

    expected = {"block": "RUN_BLOCKED", "remove": "RUN_BLOCKED", "expire": "POLICY_STALE"}
    assert _reason(flow) == expected[change]
    assert APPROVAL_KEY not in flow.metadata


def test_request_hook_denies_trailers(harness: Harness) -> None:
    flow = _approved(harness)
    flow.request.trailers = FakeHeaders([("X-Trail", "v")])

    harness.addon.request(flow)

    assert _reason(flow) == "TRAILERS_DENIED"


def test_request_hook_denies_on_errors(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    flow = _approved(harness)

    def broken(_: UUID) -> object:
        raise RuntimeError("store")

    monkeypatch.setattr(harness.addon._store, "load", broken)
    harness.addon.request(flow)

    assert _reason(flow) == "GUARD_ERROR"


# --- 其他 hook --------------------------------------------------------------------------------


def test_connect_is_always_denied(harness: Harness) -> None:
    flow = _flow(method="CONNECT")

    harness.addon.http_connect(flow)

    assert _reason(flow) == "CONNECT_DENIED"
    assert _denied(flow).status_code == 403


def _connect(harness: Harness, client: FakeClient, address: tuple[str, int]) -> FakeServer:
    server = FakeServer(address=address)
    harness.addon.server_connect(FakeServerConnection(client=client, server=server))
    return server


def test_server_connect_needs_an_approval_from_the_same_client(harness: Harness) -> None:
    flow = _approved(harness)

    assert _connect(harness, flow.client_conn, ("10.89.7.20", 8080)).error is None
    assert _connect(harness, flow.client_conn, ("10.89.7.21", 8080)).error is not None
    assert _connect(harness, FakeClient(id="other"), ("10.89.7.20", 8080)).error is not None


def test_server_connect_rechecks_the_run(harness: Harness) -> None:
    flow = _approved(harness)
    harness.write(_policy(state=PolicyState.BLOCKED))

    assert _connect(harness, flow.client_conn, ("10.89.7.20", 8080)).error is not None


def test_server_connect_kills_on_errors(harness: Harness) -> None:
    flow = _approved(harness)
    server = FakeServer(address=("10.89.7.20", 8080))

    harness.addon.server_connect(FakeServerConnection(client=flow.client_conn, server=server))
    assert server.error is None
    harness.addon.server_connect(FakeServerConnection(client=None, server=server))  # type: ignore[arg-type]

    assert server.error is not None


def test_disconnect_forgets_the_approvals(harness: Harness) -> None:
    flow = _approved(harness)

    harness.addon.client_disconnected(flow.client_conn)

    assert _connect(harness, flow.client_conn, ("10.89.7.20", 8080)).error is not None


@pytest.mark.parametrize(
    ("peername", "allowed"),
    [
        (("10.89.8.2", 40000), True),
        (("10.89.7.20", 40000), False),  # lab 那一側
        (("127.0.0.1", 40000), False),
        (None, False),
        (("::1", 40000, 0, 0), False),
    ],
)
def test_clients_must_come_from_the_scan_network(
    harness: Harness, peername: Any, allowed: bool
) -> None:
    client = FakeClient(peername=peername)

    harness.addon.client_connected(client)

    assert (client.error is None) is allowed


@pytest.mark.parametrize("hook", ["tcp_start", "udp_start", "websocket_start"])
def test_raw_protocols_are_killed(harness: Harness, hook: str) -> None:
    flow = _flow()

    getattr(harness.addon, hook)(flow)

    assert flow.killed


def test_response_and_error_are_logged(harness: Harness) -> None:
    flow = _approved(harness)
    flow.response = FakeResponse(200, b"ok", {})
    flow.server_conn = FakeServer(address=("10.89.7.20", 8080), peername=("10.89.7.20", 8080))

    harness.addon.response(flow)
    harness.addon.error(flow)

    response, error = harness.lines()[-2:]
    assert (response["event"], response["status"], response["run_id"]) == (
        "response",
        200,
        str(RUN_ID),
    )
    assert error["event"] == "upstream_error"
    assert response["upstream"] == "10.89.7.20"


def test_logging_failures_never_raise(harness: Harness) -> None:
    flow = FakeFlow(request=None)  # type: ignore[arg-type]

    harness.addon.response(flow)
    harness.addon.error(flow)
    harness.addon.client_disconnected(None)  # type: ignore[arg-type]


def test_running_marks_the_addon_ready_and_notifies(tmp_path: Path) -> None:
    calls: list[str] = []
    addon = GuardAddon(
        store=PolicyStore(tmp_path),
        resolve=Resolver(),
        lab=LAB,
        scan_network=SCAN_NET,
        guard_ips=GUARD_IPS,
        make_response=make_response,
        log=GuardLog(guard_logger(f"ready-{uuid4().hex}", io.StringIO())),
        on_ready=lambda: calls.append("ready"),
    )

    assert addon.ready is False
    addon.running()

    assert addon.ready is True
    assert calls == ["ready"]


def test_underscore_proxy_headers_are_removed_too(harness: Harness) -> None:
    flow = _flow(headers=[("Host", "lab-target:8080"), ("Proxy_Connection", "keep-alive")])

    _screen(harness, flow)

    assert flow.response is None
    assert [n for n in flow.request.headers.names() if n.lower().startswith("proxy")] == []


def test_a_denial_without_a_response_is_killed_by_the_request_hook(harness: Harness) -> None:
    """建立回應與中止都失敗時，request hook 不能只相信拒絕的旗標（審查發現）。"""
    flow = _flow("/api/admin")
    flow.metadata[DENIAL_KEY] = "PATH_EXCLUDED"

    harness.addon.request(flow)

    assert flow.killed


def test_upstream_responses_cannot_impersonate_the_guard(harness: Harness) -> None:
    """靶機自己加上 X-Secscan-Guard 時刪除：M3 的 parser 依它排除 guard 的回應（審查發現）。"""
    flow = _approved(harness)
    flow.response = FakeResponse(200, b"ok", {"X-Secscan-Guard": "PATH_EXCLUDED", "A": "b"})

    harness.addon.response(flow)

    assert isinstance(flow.response, FakeResponse)
    assert "X-Secscan-Guard" not in flow.response.headers
    assert flow.response.headers["A"] == "b"


def test_guard_denials_keep_their_reason_header(harness: Harness) -> None:
    flow = _screen(harness, _flow("/api/admin"))

    harness.addon.response(flow)

    assert _reason(flow) == "PATH_EXCLUDED"
