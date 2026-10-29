"""egress guard 的 mitmproxy addon（docs/DECISIONS.md §15.5）。

requestheaders 依固定順序檢查（帳密與 policy → run 的狀態 → 請求本身 → 預算 → 速率 → 再查一次 run
→ DNS → 綁定）；拒絕時設定 response，mitmproxy 就不建立上游連線（§15 實測 2）。後面的 hook 是第二道
防線：
- request：已拒絕的不處理；其餘要有核准，再查一次 run 的狀態，有 trailer 就拒絕；通過才確定轉送，
  計入預算並寫 telemetry（§16）。寫不出 telemetry 就拒絕。
- server_connect：目的位址必須是同一條 client 連線核准過的，而且 run 仍然有效。
- client_connected：來源必須在 scan_net；tcp、udp、websocket 一律中止。

每個 hook 都捕捉 Exception 並拒絕（或中止連線）：mitmproxy 吞掉 addon 的例外之後會照常放行
（§15 實測 3）。CancelledError 不是 Exception，照常傳遞。
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address
from uuid import UUID

from secscan.guard.domain.addresses import pick_upstream
from secscan.guard.domain.budget import RateLimiter
from secscan.guard.domain.credentials import (
    PROXY_AUTHENTICATE,
    parse_proxy_authorization,
    token_matches,
)
from secscan.guard.domain.policy import CompiledPolicy, Policy, PolicyError
from secscan.guard.domain.requests import (
    DENY_STATUS,
    GUARD_HEADER,
    Reason,
    RequestView,
    canonical_authority,
    header_key,
    request_reason,
    run_state_reason,
    split_target,
)
from secscan.guard.events import GuardLog
from secscan.guard.flows import (
    Client,
    Flow,
    KillableFlow,
    Request,
    ResponseFactory,
    ServerConnection,
)
from secscan.guard.resolver import ResolveError
from secscan.guard.store import PolicyStore
from secscan.guard.telemetry import TelemetryRecorder, TelemetryWriteError
from secscan.targets.domain import LabNetwork

APPROVAL_KEY = "secscan.guard.approval"
DENIAL_KEY = "secscan.guard.denial"
PENDING_KEY = "secscan.guard.pending"
FORWARDED_KEY = "secscan.guard.forwarded"
_PROXY_HEADER_PREFIX = "proxy-"
_KILLED = "blocked by secscan egress guard"

Resolver = Callable[[str], Awaitable[tuple[str, ...]]]


@dataclass(frozen=True, slots=True)
class Approval:
    """requestheaders 放行的請求：run 與綁定的上游位址。"""

    run_id: UUID
    address: str
    port: int


@dataclass(frozen=True, slots=True)
class Pending:
    """保留了名額、還沒確定轉送的請求：request hook 確定，或拒絕、錯誤時釋放（只處理一次）。"""

    policy: Policy
    method: str
    path: str
    authenticated: bool


@dataclass(frozen=True, slots=True)
class Forwarded:
    """已經轉送的請求：回應的那一行以同一個序號記下。"""

    run_id: UUID
    sequence: int


class _DeniedError(Exception):
    def __init__(
        self,
        reason: Reason,
        *,
        policy: Policy | None = None,
        run_id: UUID | None = None,
        detail: str | None = None,
    ):
        super().__init__(reason.value)
        self.reason = reason
        self.policy = policy
        self.run_id = policy.run_id if policy is not None else run_id
        self.detail = detail


class GuardAddon:
    def __init__(
        self,
        *,
        store: PolicyStore,
        resolve: Resolver,
        lab: LabNetwork,
        scan_network: IPv4Network,
        guard_ips: frozenset[IPv4Address],
        make_response: ResponseFactory,
        recorder: TelemetryRecorder,
        log: GuardLog,
        limiter: RateLimiter | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        on_ready: Callable[[], None] = lambda: None,
    ) -> None:
        self._store = store
        self._resolve = resolve
        self._lab = lab
        self._scan_network = scan_network
        self._guard_ips = guard_ips
        self._make_response = make_response
        self._recorder = recorder
        self._limiter = limiter if limiter is not None else RateLimiter()
        self._log = log
        self._clock = clock
        self._monotonic = monotonic
        self._sleep = sleep
        # client 連線 → 核准過的 (位址, port) → run。server_connect 據此判斷。
        self._approved: dict[str, dict[tuple[str, int], UUID]] = {}
        # mitmproxy 開始監聽之後（running hook）才算在檢查：status 的 enforcing 依此決定。
        self.ready = False
        self._on_ready = on_ready

    def running(self) -> None:
        self.ready = True
        self._on_ready()

    # --- 連線 ---------------------------------------------------------------------------------

    def client_connected(self, client: Client) -> None:
        try:
            if not self._from_scan_network(client.peername):
                client.error = _KILLED
                self._log.refused("client_refused")
        except Exception as exc:  # noqa: BLE001 - mitmproxy 吞掉例外後會放行：一律中止
            client.error = _KILLED
            self._log.hook_failed("client_connected", exc)

    def client_disconnected(self, client: Client) -> None:
        try:
            self._approved.pop(client.id, None)
        except Exception as exc:  # noqa: BLE001 - 只是清除，失敗不影響判斷
            self._log.hook_failed("client_disconnected", exc)

    def server_connect(self, data: ServerConnection) -> None:
        try:
            address = data.server.address
            approvals = self._approved.get(data.client.id, {})
            run_id = None if address is None else approvals.get((address[0], address[1]))
            if run_id is None or self._run_reason(run_id) is not None:
                data.server.error = _KILLED
                self._log.refused("server_connect_refused")
        except Exception as exc:  # noqa: BLE001 - mitmproxy 吞掉例外後會放行：一律中止
            data.server.error = _KILLED
            self._log.hook_failed("server_connect", exc)

    # --- HTTP ---------------------------------------------------------------------------------

    async def requestheaders(self, flow: Flow) -> None:
        try:
            await self._screen(flow)
        except _DeniedError as denied:
            self._deny(flow, denied)
        except Exception as exc:  # noqa: BLE001 - mitmproxy 吞掉例外後會放行：一律拒絕
            self._log.hook_failed("requestheaders", exc)
            self._deny(flow, _DeniedError(Reason.GUARD_ERROR))

    def request(self, flow: Flow) -> None:
        try:
            if DENIAL_KEY in flow.metadata:
                # 拒絕時建立回應與中止都失敗過：不能只相信旗標（審查發現）。
                if flow.response is None:
                    self._kill(flow, "request")
                return
            approval = flow.metadata.get(APPROVAL_KEY)
            pending = flow.metadata.get(PENDING_KEY)
            if (
                not isinstance(approval, Approval)
                or not isinstance(pending, Pending)
                or pending.policy.run_id != approval.run_id
                or (flow.request.host, flow.request.port) != (approval.address, approval.port)
            ):
                raise _DeniedError(Reason.NOT_APPROVED)
            reason = self._run_reason(approval.run_id)
            if reason is not None:
                raise _DeniedError(reason, policy=pending.policy)
            if flow.request.trailers is not None:
                raise _DeniedError(Reason.TRAILERS_DENIED, policy=pending.policy)
            self._forward(flow, pending)
        except _DeniedError as denied:
            self._deny(flow, denied)
        except Exception as exc:  # noqa: BLE001 - mitmproxy 吞掉例外後會放行：一律拒絕
            self._log.hook_failed("request", exc)
            self._deny(flow, _DeniedError(Reason.GUARD_ERROR))

    def http_connect(self, flow: Flow) -> None:
        """P0 只有 http：CONNECT（HTTPS 或任意 TCP 通道）一律拒絕。"""
        self._deny(flow, _DeniedError(Reason.CONNECT_DENIED))

    def tcp_start(self, flow: KillableFlow) -> None:
        self._kill(flow, "tcp_start")

    def udp_start(self, flow: KillableFlow) -> None:
        self._kill(flow, "udp_start")

    def websocket_start(self, flow: KillableFlow) -> None:
        self._kill(flow, "websocket_start")

    def response(self, flow: Flow) -> None:
        """靶機的回應不能冒充 guard：M3 的 parser 依 X-Secscan-Guard 排除 guard 的回應。"""
        try:
            headers = getattr(flow.response, "headers", None)
            if DENIAL_KEY not in flow.metadata and headers is not None and GUARD_HEADER in headers:
                del headers[GUARD_HEADER]
        except Exception as exc:  # noqa: BLE001 - 刪不掉就不轉給 client
            self._log.hook_failed("response", exc)
            self._kill(flow, "response")
        self._record_response(flow)
        self._exchange("response", flow)

    def error(self, flow: Flow) -> None:
        self._release(flow)
        self._exchange("upstream_error", flow)

    def flush_telemetry(self) -> None:
        """定期把拒絕的計數寫進 summary，並刪掉過期的檔案（由啟動程式的背景工作呼叫）。"""
        try:
            self._recorder.flush()
            self._recorder.prune()
        except TelemetryWriteError as exc:
            self._log.refused("telemetry_flush_failed", error=str(exc))

    # --- 判斷 ---------------------------------------------------------------------------------

    async def _screen(self, flow: Flow) -> None:
        view = _view(flow.request)
        flow.metadata.pop(APPROVAL_KEY, None)
        compiled = self._authenticate(view)
        policy = compiled.policy
        reason = run_state_reason(policy, now=self._clock()) or request_reason(view, compiled)
        if reason is not None:
            raise _DeniedError(reason, policy=policy)
        if not self._recorder.reserve(policy):
            raise _DeniedError(Reason.BUDGET_EXHAUSTED, policy=policy)
        flow.metadata[PENDING_KEY] = Pending(
            policy=policy,
            method=view.method,
            path=split_target(view.target)[0],
            authenticated=_carries(view, policy.auth_header),
        )
        try:
            await self._pace(policy)
            upstream = await self._upstream(compiled)
            self._approve(flow, compiled, upstream)
        except BaseException:
            # 拒絕、例外與取消（CancelledError）都要釋放名額；_deny 再呼叫也只會釋放一次。
            self._release(flow)
            raise
        self._log.decision(
            allowed=True, reason=None, run_id=policy.run_id, view=view, upstream=str(upstream)
        )

    async def _pace(self, policy: Policy) -> None:
        """同一個 scan 的請求依速率等待（最多 MAX_RATE_WAIT_SECONDS）；等待之後再查一次 run。"""
        wait = self._limiter.reserve(policy.scan_id, policy.budget, now=self._monotonic())
        if wait is None:
            raise _DeniedError(Reason.RATE_LIMITED, policy=policy)
        if wait <= 0:
            return
        await self._sleep(wait)
        reason = self._run_reason(policy.run_id)
        if reason is not None:
            raise _DeniedError(reason, policy=policy)

    def _forward(self, flow: Flow, pending: Pending) -> None:
        """確定轉送：計入預算、寫一行 telemetry。寫不出來就拒絕（recorder 已釋放名額）。"""
        flow.metadata.pop(PENDING_KEY, None)
        try:
            sequence = self._recorder.forwarded(
                pending.policy.run_id,
                method=pending.method,
                path=pending.path,
                authenticated=pending.authenticated,
                at=self._clock(),
            )
        except TelemetryWriteError as exc:
            self._log.refused("telemetry_write_failed", error=str(exc))
            raise _DeniedError(Reason.GUARD_ERROR, policy=pending.policy) from None
        flow.metadata[FORWARDED_KEY] = Forwarded(pending.policy.run_id, sequence)

    def _release(self, flow: Flow) -> None:
        try:
            pending = flow.metadata.pop(PENDING_KEY, None)
            if isinstance(pending, Pending):
                self._recorder.release(pending.policy.run_id)
        except Exception as exc:  # noqa: BLE001 - 釋放失敗只會少放行，記下來
            self._log.hook_failed("release", exc)

    def _record_response(self, flow: Flow) -> None:
        try:
            forwarded = flow.metadata.get(FORWARDED_KEY)
            status = getattr(flow.response, "status_code", None)
            if isinstance(forwarded, Forwarded) and isinstance(status, int):
                self._recorder.response(
                    forwarded.run_id, sequence=forwarded.sequence, status=status, at=self._clock()
                )
        except Exception as exc:  # noqa: BLE001 - 回應已經在路上；只記下來
            self._log.hook_failed("telemetry_response", exc)

    def _authenticate(self, view: RequestView) -> CompiledPolicy:
        """帳密、policy 與 token；任何一項不符都是 407，原因只寫進 log。"""
        credentials = parse_proxy_authorization(view.values("proxy-authorization"))
        if credentials is None:
            raise _DeniedError(Reason.PROXY_AUTH_REQUIRED, detail="CREDENTIALS_INVALID")
        try:
            compiled = self._store.load(credentials.run_id)
        except PolicyError:
            raise _DeniedError(Reason.PROXY_AUTH_REQUIRED, detail="POLICY_INVALID") from None
        if compiled is None:
            raise _DeniedError(Reason.PROXY_AUTH_REQUIRED, detail="RUN_NOT_ACTIVE")
        if not token_matches(credentials.token, compiled.policy.token_sha256):
            raise _DeniedError(Reason.PROXY_AUTH_REQUIRED, detail="TOKEN_MISMATCH")
        return compiled

    async def _upstream(self, compiled: CompiledPolicy) -> IPv4Address:
        origin = compiled.origin
        if origin.ip is not None:
            answers: tuple[str, ...] = (str(origin.ip),)
        else:
            try:
                answers = await self._resolve(origin.host)
            except ResolveError:
                raise _DeniedError(Reason.DNS_FAILED, policy=compiled.policy) from None
        upstream = pick_upstream(
            answers, allowed=compiled.policy.scope.ips, lab=self._lab, guard=self._guard_ips
        )
        if upstream is None:
            raise _DeniedError(Reason.ADDRESS_NOT_ALLOWED, policy=compiled.policy)
        return upstream

    def _approve(self, flow: Flow, compiled: CompiledPolicy, upstream: IPv4Address) -> None:
        """連線綁定到驗證過的 IP（事後重新解析不會生效），Host 寫回 canonical 的 authority。"""
        request = flow.request
        request.host = str(upstream)
        request.headers["Host"] = canonical_authority(compiled.origin)
        names = {
            name.decode("latin-1").lower()
            for name, _ in request.headers.fields
            if header_key(name.decode("latin-1")).startswith(_PROXY_HEADER_PREFIX)
        }
        for name in names:
            del request.headers[name]
        approval = Approval(compiled.policy.run_id, str(upstream), request.port)
        flow.metadata[APPROVAL_KEY] = approval
        client = self._approved.setdefault(flow.client_conn.id, {})
        client[(approval.address, approval.port)] = approval.run_id

    def _run_reason(self, run_id: UUID) -> Reason | None:
        """policy 不見了或損毀，都當成已封鎖（run 已結束或不可信）。"""
        try:
            compiled = self._store.load(run_id)
        except PolicyError:
            return Reason.RUN_BLOCKED
        if compiled is None:
            return Reason.RUN_BLOCKED
        return run_state_reason(compiled.policy, now=self._clock())

    def _from_scan_network(self, peername: tuple[object, ...] | None) -> bool:
        if not peername or not isinstance(peername[0], str):
            return False
        try:
            address = ip_address(peername[0])
        except ValueError:
            return False
        return isinstance(address, IPv4Address) and address in self._scan_network

    # --- 回應與紀錄 ---------------------------------------------------------------------------

    def _deny(self, flow: Flow, denied: _DeniedError) -> None:
        reason = denied.reason
        self._release(flow)
        self._count_denial(denied)
        try:
            flow.metadata.pop(APPROVAL_KEY, None)
            flow.metadata[DENIAL_KEY] = reason.value
            headers = {
                GUARD_HEADER: reason.value,
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "no-store",
            }
            if reason is Reason.PROXY_AUTH_REQUIRED:
                headers["Proxy-Authenticate"] = PROXY_AUTHENTICATE
            body = f"blocked by secscan egress guard: {reason.value}\n".encode("ascii")
            flow.response = self._make_response(DENY_STATUS[reason], body, headers)
        except Exception as exc:  # noqa: BLE001 - 連回應都建立不了：中止這個 flow
            self._log.hook_failed("deny", exc)
            self._kill(flow, "deny")
        try:
            view = _view(flow.request)
        except Exception:  # noqa: BLE001 - 只影響紀錄的內容
            view = None
        self._log.decision(
            allowed=False,
            reason=reason.value,
            run_id=denied.run_id,
            view=view,
            detail=denied.detail,
        )

    def _count_denial(self, denied: _DeniedError) -> None:
        """只計 token 驗證過的 run（407 不知道是哪個 run，不計）。"""
        if denied.policy is None:
            return
        try:
            self._recorder.denied(denied.policy, denied.reason)
        except Exception as exc:  # noqa: BLE001 - 已經拒絕；計數失敗只記下來
            self._log.hook_failed("telemetry_denied", exc)

    def _kill(self, flow: KillableFlow, hook: str) -> None:
        try:
            flow.kill()
            self._log.refused("flow_killed", hook=hook)
        except Exception as exc:  # noqa: BLE001 - 已經無法處理；記下來
            self._log.hook_failed(hook, exc)

    def _exchange(self, event: str, flow: Flow) -> None:
        try:
            approval = flow.metadata.get(APPROVAL_KEY)
            run_id = approval.run_id if isinstance(approval, Approval) else None
            status = getattr(flow.response, "status_code", None)
            peer = flow.server_conn.peername
            upstream = str(peer[0]) if peer else None
            self._log.exchange(event, run_id=run_id, status=status, upstream=upstream)
        except Exception as exc:  # noqa: BLE001 - 只是紀錄
            self._log.hook_failed(event, exc)


def _view(request: Request) -> RequestView:
    return RequestView(
        method=request.data.method.decode("latin-1"),
        scheme=request.scheme,
        host=request.host,
        port=request.port,
        target=request.data.path.decode("latin-1"),
        headers=tuple(
            (name.decode("latin-1"), value.decode("latin-1"))
            for name, value in request.headers.fields
        ),
    )


def _carries(view: RequestView, header: str | None) -> bool:
    """請求是否帶著 policy 指定的認證 header（名稱不分大小寫；_ 與 - 視為相同）。"""
    return header is not None and any(header_key(name) == header for name, _ in view.headers)
