"""guard 的 addon 與真的 mitmproxy 物件（在 guard 的映像中執行；docs/DECISIONS.md §15.1）。

單元測試以 Protocol 的假物件模擬 flow；這裡以 mitmproxy 12.2.3 自己的 Request、HTTPFlow、Client、
Server 與 tflow 驅動同一個 addon，確認 addon 用到的屬性與行為（headers.fields、data.method、
設定 host 之後的 Host、Response.make、server.error、flow.kill）和假物件一致。
輸出一行 JSON：{檢查的名稱: true/false}。
"""

import asyncio
import base64
import json
import sys
import tempfile
import time
import uuid
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any

sys.path.insert(0, "/opt/secscan-guard")

from mitmproxy import connection, http  # type: ignore[import-not-found]
from mitmproxy.proxy.server_hooks import (  # type: ignore[import-not-found]
    ServerConnectionHookData,
)
from mitmproxy.test import tflow  # type: ignore[import-not-found]

from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.addon import APPROVAL_KEY, GuardAddon
from secscan.guard.domain.credentials import new_token, token_digest
from secscan.guard.domain.policy import (
    Policy,
    PolicyState,
    encode_policy,
    policy_file_name,
)
from secscan.guard.events import GuardLog, guard_logger
from secscan.guard.files import write_atomic
from secscan.guard.store import PolicyStore
from secscan.targets.domain import LabNetwork, parse_ipv4, parse_origin

TARGET_IP = "10.89.10.200"
SCAN_CLIENT = ("10.89.9.10", 40000)


async def _resolve(_: str) -> tuple[str, ...]:
    return (TARGET_IP,)


def _addon(directory: Path) -> GuardAddon:
    return GuardAddon(
        store=PolicyStore(directory),
        resolve=_resolve,
        lab=LabNetwork(IPv4Network("10.89.10.0/24")),
        scan_network=IPv4Network("10.89.9.0/24"),
        guard_ips=frozenset({IPv4Address("10.89.9.254"), IPv4Address("10.89.10.254")}),
        make_response=http.Response.make,
        log=GuardLog(guard_logger("contract", open("/dev/null", "w"))),
    )


def _flow(run_id: uuid.UUID, token: str, *, url: str, method: str = "GET") -> Any:
    credentials = base64.b64encode(f"{run_id}:{token}".encode()).decode()
    host = url.split("/")[2]
    request = http.Request.make(
        method,
        url,
        headers={
            "Host": host,
            "Proxy-Authorization": f"Basic {credentials}",
            "Proxy-Connection": "x",
        },
    )
    request.authority = ""  # regular mode 的 HTTP/1：hook 之前就改成 origin-form（§15 實測 5）
    client = connection.Client(peername=SCAN_CLIENT, sockname=("10.89.9.254", 8080))
    return tflow.tflow(client_conn=client, req=request)


def main() -> None:
    directory = Path(tempfile.mkdtemp())
    run_id, token = uuid.uuid4(), new_token()
    now = int(time.time())
    policy = Policy(
        run_id=run_id,
        scan_id=uuid.uuid4(),
        state=PolicyState.ACTIVE,
        token_sha256=token_digest(token),
        not_after=now + 600,
        renew_until=now + 600,
        scope=Scope(
            origins=(parse_origin("http://lab-target:8080"),),
            ips=(parse_ipv4(TARGET_IP),),
            paths=("/api/items/{id}",),
            allow_all_paths=False,
            excluded_paths=("/api/admin",),
            methods=(HttpMethod.GET,),
        ),
    )
    write_atomic(directory, policy_file_name(run_id), encode_policy(policy))
    addon = _addon(directory)
    checks: dict[str, bool] = {}

    allowed = _flow(run_id, token, url="http://lab-target:8080/api/items/7")
    asyncio.run(addon.requestheaders(allowed))
    addon.request(allowed)
    headers = allowed.request.headers
    checks["allowed_has_no_response"] = allowed.response is None
    checks["bound_to_ip"] = allowed.request.host == TARGET_IP
    checks["host_is_canonical"] = headers.get_all("host") == ["lab-target:8080"]
    checks["proxy_headers_removed"] = not any(name.lower().startswith("proxy-") for name in headers)
    checks["approval_recorded"] = APPROVAL_KEY in allowed.metadata

    approved = connection.Server(address=(TARGET_IP, 8080))
    addon.server_connect(ServerConnectionHookData(server=approved, client=allowed.client_conn))
    other = connection.Server(address=("10.89.10.201", 8080))
    addon.server_connect(ServerConnectionHookData(server=other, client=allowed.client_conn))
    checks["server_connect_allows_the_approved_address"] = approved.error is None
    checks["server_connect_kills_other_addresses"] = other.error is not None

    excluded = _flow(run_id, token, url="http://lab-target:8080/api/admin")
    asyncio.run(addon.requestheaders(excluded))
    response = excluded.response
    checks["denial_is_a_real_response"] = isinstance(response, http.Response)
    checks["denial_is_403_with_reason"] = (
        response.status_code == 403 and response.headers.get("X-Secscan-Guard") == "PATH_EXCLUDED"
    )

    lowercase = _flow(run_id, token, url="http://lab-target:8080/api/items/7", method="get")
    asyncio.run(addon.requestheaders(lowercase))
    checks["raw_method_is_compared"] = lowercase.response is not None

    unauthenticated = _flow(run_id, "W" * 43, url="http://lab-target:8080/api/items/7")
    asyncio.run(addon.requestheaders(unauthenticated))
    denied = unauthenticated.response
    checks["bad_token_is_407_with_challenge"] = (
        denied.status_code == 407 and "Proxy-Authenticate" in denied.headers
    )

    allowed.response = http.Response.make(200, b"ok", {"x-secscan-guard": "PATH_EXCLUDED"})
    addon.response(allowed)
    checks["upstream_cannot_impersonate_the_guard"] = (
        "X-Secscan-Guard" not in allowed.response.headers
    )
    addon.response(excluded)
    checks["guard_denials_keep_the_reason"] = (
        excluded.response.headers.get("X-Secscan-Guard") == "PATH_EXCLUDED"
    )

    tcp = tflow.ttcpflow()
    addon.tcp_start(tcp)
    checks["tcp_is_killed"] = tcp.error is not None

    outside = connection.Client(peername=("10.89.10.5", 1), sockname=("10.89.9.254", 8080))
    inside = connection.Client(peername=SCAN_CLIENT, sockname=("10.89.9.254", 8080))
    addon.client_connected(outside)
    addon.client_connected(inside)
    checks["clients_outside_scan_net_are_refused"] = outside.error is not None
    checks["scan_net_clients_are_accepted"] = inside.error is None

    sys.stdout.write(json.dumps(checks) + "\n")


if __name__ == "__main__":
    main()
