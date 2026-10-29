"""egress guard 的 live 測試（docs/DECISIONS.md §15；SECURITY_AND_TESTING SEC-02 到 SEC-10）。

以收包紀錄為準：每個被拒絕的請求，接收端都不能收到任何連線；每組負向的檢查都搭配一個送到同一個
接收端的允許請求，證明接收端確實在記錄。拓撲（make test-live-runner 建立）：
- live scan 網路 10.89.9.0/24、live lab 網路 10.89.10.0/24；guard 在兩邊的 .254。
- lab-target（10.89.10.200，alias lab-target、lab-rebind）、lab-canary（10.89.10.201），
  以及接在 live control_net 上的 control canary。
"""

import json
from collections.abc import Iterator
from typing import Any

import pytest

from tests.live.guard_support import (
    CANARY_IP,
    HERE,
    TARGET_IP,
    LivePolicy,
    Receiver,
    guard_log,
    probe,
    raw_request,
    reconnect,
    remove_policy,
    start_receiver,
    stop_receiver,
    write_policy,
)
from tests.live.support import (
    GUARD_IMAGE,
    GUARD_IP,
    GUARD_LAB_IP,
    LAB_NET,
    PROJECT,
    SCAN_NET,
    container,
    docker,
    inspect,
    wait_for,
)

pytestmark = pytest.mark.live

TARGET = "http://lab-target:8080"


@pytest.fixture(scope="module")
def target() -> Iterator[Receiver]:
    receiver = start_receiver(
        "target", ip=TARGET_IP, aliases=("lab-target", "lab-rebind", "lab-target-alt")
    )
    yield receiver
    stop_receiver(receiver)


@pytest.fixture(scope="module")
def canary() -> Iterator[Receiver]:
    receiver = start_receiver("canary", ip=CANARY_IP, aliases=("lab-canary",))
    yield receiver
    stop_receiver(receiver)


@pytest.fixture(scope="module")
def control_canary() -> Iterator[Receiver]:
    receiver = start_receiver(
        "control-canary", ip=None, aliases=("control-canary",), network=f"{PROJECT}_control_net"
    )
    yield receiver
    stop_receiver(receiver)


@pytest.fixture
def policy() -> Iterator[LivePolicy]:
    created = write_policy()
    yield created
    remove_policy(created)


def _get(path: str, policy: LivePolicy, **options: Any) -> bytes:
    return raw_request(f"{TARGET}{path}", authorization=policy.authorization(), **options)


def _new_paths(receiver: Receiver, before: int) -> list[str]:
    return receiver.paths()[before:]


# --- guard 容器本身 ---------------------------------------------------------------------------


def test_the_guard_is_hardened_and_sits_only_on_scan_and_lab() -> None:
    info = inspect(container("guard"))
    host = info["HostConfig"]
    networks = info["NetworkSettings"]["Networks"]

    assert info["Config"]["User"] == "10001:10001"
    assert host["ReadonlyRootfs"] is True
    assert host["CapDrop"] == ["ALL"]
    assert host["SecurityOpt"] == ["no-new-privileges:true"]
    assert host["Privileged"] is False
    assert host["PortBindings"] in (None, {})
    assert {name: value["IPAddress"] for name, value in networks.items()} == {
        SCAN_NET: GUARD_IP,
        LAB_NET: GUARD_LAB_IP,
    }
    mounts = {mount["Destination"]: mount["RW"] for mount in info["Mounts"]}
    assert mounts == {"/guard/policies": False, "/guard/status": True, "/guard/telemetry": True}
    assert "docker.sock" not in json.dumps(info["Mounts"])


def test_the_guard_reports_that_it_is_enforcing() -> None:
    # 非 0 結束時 docker() 會失敗。
    docker(
        "exec",
        container("guard"),
        "python3",
        "-I",
        "-B",
        "/opt/secscan-guard/run_guard.py",
        "--check",
    )

    state = inspect(container("guard"))["State"]
    assert state["Health"]["Status"] == "healthy"


def test_the_guard_listens_only_on_the_scan_side(target: Receiver, policy: LivePolicy) -> None:
    """lab 那一側（靶機）連不到 guard 的 proxy：反向的請求一律失敗。"""
    results = probe(
        [("from-lab", _get("/api/items/7", policy))], target=f"{GUARD_LAB_IP}:8080", network=LAB_NET
    )

    assert results["from-lab"]["status"] is None


def test_the_addon_works_with_real_mitmproxy_flows() -> None:
    """單元測試的假物件和 mitmproxy 12.2.3 的真物件行為一致（guard_contract.py）。"""
    output = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp",  # noqa: S108
        "--entrypoint",
        "python3",
        "-v",
        f"{HERE / 'guard_contract.py'}:/c/guard_contract.py:ro",
        GUARD_IMAGE,
        "-I",
        "-B",
        "/c/guard_contract.py",
    )

    checks = json.loads(output.splitlines()[-1])
    assert len(checks) >= 18
    assert all(checks.values()), checks


# --- SEC-02、SEC-05、SEC-08、SEC-09：逐請求的檢查 --------------------------------------------


def _cases(policy: LivePolicy) -> list[tuple[str, bytes, int | None, str | None]]:
    auth = policy.authorization()
    wrong = policy.authorization(token="W" * 43)
    return [
        # 帳密
        ("no-credentials", raw_request(f"{TARGET}/api/items/7"), 407, "PROXY_AUTH_REQUIRED"),
        ("wrong-token", raw_request(f"{TARGET}/api/items/7", authorization=wrong), 407, None),
        # SEC-02：別的 origin
        (
            "canary-name",
            raw_request(
                "http://lab-canary:8080/api/items/7", host="lab-canary:8080", authorization=auth
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "canary-ip",
            raw_request(
                f"http://{CANARY_IP}:8080/api/items/7", host=f"{CANARY_IP}:8080", authorization=auth
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "target-ip-form",
            raw_request(
                f"http://{TARGET_IP}:8080/api/items/7", host=f"{TARGET_IP}:8080", authorization=auth
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "other-port",
            raw_request(
                "http://lab-target:8081/api/items/7", host="lab-target:8081", authorization=auth
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "other-alias",
            raw_request(
                "http://lab-target-alt:8080/api/items/7",
                host="lab-target-alt:8080",
                authorization=auth,
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        # SEC-05：同一個 origin 的其他寫法與 Host 不一致
        (
            "uppercase",
            raw_request(
                "http://LAB-target:8080/api/items/7", host="LAB-target:8080", authorization=auth
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "trailing-dot",
            raw_request(
                "http://lab-target.:8080/api/items/7", host="lab-target.:8080", authorization=auth
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "host-mismatch",
            raw_request(f"{TARGET}/api/items/7", host="lab-canary:8080", authorization=auth),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "padded-port",
            raw_request(
                "http://lab-target:08080/api/items/7", host="lab-target:08080", authorization=auth
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "hex-ip",
            raw_request(
                "http://0x0a590ac8:8080/api/items/7", host="0x0a590ac8:8080", authorization=auth
            ),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "userinfo",
            raw_request("http://x@lab-target:8080/api/items/7", authorization=auth),
            400,
            None,
        ),
        (
            "origin-form-other-host",
            raw_request("/api/items/7", host="lab-canary:8080", authorization=auth),
            403,
            "ORIGIN_MISMATCH",
        ),
        (
            "no-host-http10",
            raw_request(f"{TARGET}/api/items/7", host=None, authorization=auth, version="HTTP/1.0"),
            403,
            "ORIGIN_MISMATCH",
        ),
        # SEC-08：path 與 method
        ("excluded", _get("/api/admin", policy), 403, "PATH_EXCLUDED"),
        ("excluded-case", _get("/API/ADMIN", policy), 403, "PATH_EXCLUDED"),
        ("not-granted", _get("/elsewhere", policy), 403, "PATH_NOT_AUTHORIZED"),
        ("encoded-dots", _get("/api/%2e%2e/admin", policy), 403, "PATH_AMBIGUOUS"),
        ("double-slash", _get("//api/items/7", policy), 403, "PATH_AMBIGUOUS"),
        ("semicolon", _get("/api/items/7;x=1", policy), 403, "PATH_AMBIGUOUS"),
        ("dot-segment", _get("/api/./items/7", policy), 403, "PATH_AMBIGUOUS"),
        ("literal-placeholder", _get("/api/items/{id}", policy), 403, "PATH_AMBIGUOUS"),
        ("delete", _get("/api/items/7", policy, method="DELETE"), 403, "METHOD_NOT_AUTHORIZED"),
        ("lowercase-get", _get("/api/items/7", policy, method="get"), 403, "METHOD_NOT_AUTHORIZED"),
        ("trace", _get("/api/items/7", policy, method="TRACE"), 403, "METHOD_NOT_AUTHORIZED"),
        (
            "post-with-body",
            _get("/api/items/7", policy, method="POST", body=b"x" * 10),
            403,
            "METHOD_NOT_AUTHORIZED",
        ),
        (
            "options-star",
            raw_request("*", method="OPTIONS", authorization=auth),
            403,
            "PATH_AMBIGUOUS",
        ),
        (
            "method-override",
            _get("/api/items/7", policy, headers=[("X-HTTP-Method-Override", "DELETE")]),
            403,
            "OVERRIDE_HEADER",
        ),
        (
            "original-url",
            _get("/api/items/7", policy, headers=[("X-Original-URL", "/api/admin")]),
            403,
            "OVERRIDE_HEADER",
        ),
        ("query-method", _get("/api/items/7?_method=DELETE", policy), 403, "OVERRIDE_HEADER"),
        (
            "websocket",
            _get(
                "/api/items/7",
                policy,
                headers=[("Upgrade", "websocket"), ("Connection", "Upgrade")],
            ),
            403,
            "UPGRADE_DENIED",
        ),
        # SEC-09：HTTPS 與 CONNECT
        (
            "connect",
            raw_request("lab-target:8080", method="CONNECT", authorization=auth),
            403,
            "CONNECT_DENIED",
        ),
        (
            "https",
            raw_request("https://lab-target:8080/api/items/7", authorization=auth),
            403,
            "SCHEME_DENIED",
        ),
    ]


def test_out_of_scope_requests_never_reach_any_receiver(
    target: Receiver, canary: Receiver, control_canary: Receiver, policy: LivePolicy
) -> None:
    cases = _cases(policy)
    before = len(target.records())
    allowed = ("allowed-first", _get("/api/items/7?page=1", policy))
    allowed_last = ("allowed-last", _get("/api/items", policy))

    results = probe([allowed, *[(name, raw) for name, raw, _, _ in cases], allowed_last])

    assert results["allowed-first"]["status"] == 200
    assert results["allowed-last"]["status"] == 200
    for name, _, status, reason in cases:
        assert results[name]["status"] == status, name
        if reason is not None:
            assert results[name]["reason"] == reason, name
    assert _new_paths(target, before) == ["/api/items/7?page=1", "/api/items"]
    assert canary.records() == []
    assert control_canary.records() == []


def test_the_target_sees_canonical_requests_without_proxy_credentials(
    target: Receiver, policy: LivePolicy
) -> None:
    """收包證明（DoD 2）：Host 是 canonical、沒有 Proxy-*，來源是 guard 的 lab 位址。"""
    before = len(target.records())

    results = probe(
        [("allowed", _get("/api/items/9", policy, headers=[("Proxy-Connection", "keep-alive")]))]
    )

    assert results["allowed"]["status"] == 200
    [record] = target.records()[before:]
    assert record["host"] == ["lab-target:8080"]
    assert record["proxy_authorization"] is False
    assert record["peer"] == GUARD_LAB_IP
    assert record["method"] == "GET"


# --- SEC-03：redirect -------------------------------------------------------------------------


def test_redirects_are_checked_like_any_other_request(
    target: Receiver, canary: Receiver, policy: LivePolicy
) -> None:
    """guard 轉送 302；工具跟隨之後的請求照同樣的規則重新檢查。"""
    first = probe(
        [
            ("to-canary", _get("/api/items/redirect", policy)),
            ("to-excluded", _get("/api/items/redirect-excluded", policy)),
        ]
    )
    assert first["to-canary"]["status"] == 302
    assert first["to-excluded"]["status"] == 302

    followed = probe(
        [
            (
                "canary",
                raw_request(
                    str(first["to-canary"]["location"]),
                    host="lab-canary:8080",
                    authorization=policy.authorization(),
                ),
            ),
            ("excluded", _get(str(first["to-excluded"]["location"]), policy)),
        ]
    )

    assert followed["canary"]["reason"] == "ORIGIN_MISMATCH"
    assert followed["excluded"]["reason"] == "PATH_EXCLUDED"
    assert canary.records() == []


# --- SEC-04：DNS 與 IP 的綁定 -----------------------------------------------------------------


def test_a_name_moved_to_another_container_is_refused(target: Receiver, canary: Receiver) -> None:
    """origin 的名稱改指向 grant 以外的 IP（rebinding），或同時指向兩個容器：一律拒絕。"""
    rebind = write_policy(origin="http://lab-rebind:8080")
    request = raw_request(
        "http://lab-rebind:8080/api/items/7",
        host="lab-rebind:8080",
        authorization=rebind.authorization(),
    )
    try:
        assert probe([("before", request)])["before"]["status"] == 200

        reconnect(canary, ip=CANARY_IP, aliases=("lab-canary", "lab-rebind"))
        shared = probe([("shared", request)])["shared"]
        reconnect(target, ip=TARGET_IP, aliases=("lab-target", "lab-target-alt"))
        moved = probe([("moved", request)])["moved"]
    finally:
        reconnect(target, ip=TARGET_IP, aliases=("lab-target", "lab-rebind", "lab-target-alt"))
        reconnect(canary, ip=CANARY_IP, aliases=("lab-canary",))
        remove_policy(rebind)

    assert (shared["status"], shared["reason"]) == (403, "ADDRESS_NOT_ALLOWED")
    assert (moved["status"], moved["reason"]) == (403, "ADDRESS_NOT_ALLOWED")
    assert canary.records() == []


# --- SEC-06：不能經 guard 到達基礎設施 ---------------------------------------------------------


@pytest.mark.parametrize(
    "authority",
    [
        "db:5432",
        "socket-proxy:2375",
        "api:8000",
        "control-canary:8080",
        "169.254.169.254:80",
        "host.docker.internal:80",
        "localhost.localdomain:80",
        f"{GUARD_LAB_IP}:8080",
    ],
)
def test_infrastructure_is_unreachable_through_the_guard(
    control_canary: Receiver, policy: LivePolicy, authority: str
) -> None:
    result = probe(
        [
            (
                "infra",
                raw_request(
                    f"http://{authority}/", host=authority, authorization=policy.authorization()
                ),
            )
        ]
    )["infra"]

    assert (result["status"], result["reason"]) == (403, "ORIGIN_MISMATCH")
    assert control_canary.records() == []


def test_the_guard_itself_has_no_route_to_infrastructure(control_canary: Receiver) -> None:
    """guard 被攻陷時也一樣：它只接 scan 與 lab，解析不到、也連不到其他網路。"""
    script = (
        "import socket\n"
        "for host, port in [('db', 5432), ('socket-proxy', 2375), ('control-canary', 8080),"
        " ('169.254.169.254', 80), ('example.com', 80)]:\n"
        "    try:\n"
        "        socket.create_connection((host, port), timeout=2).close(); print('connected')\n"
        "    except OSError:\n"
        "        print('failed')\n"
    )

    output = docker("exec", container("guard"), "python3", "-I", "-c", script)

    assert output.split() == ["failed"] * 5
    assert control_canary.records() == []


# --- SEC-07：掃描容器只能連到 guard -----------------------------------------------------------


def test_scan_containers_cannot_bypass_the_guard(target: Receiver, canary: Receiver) -> None:
    before = len(target.records())
    plain = raw_request("/api/items/7")

    direct = {
        "target": probe([("x", plain)], target=f"{TARGET_IP}:8080")["x"],
        "canary": probe([("x", plain)], target=f"{CANARY_IP}:8080")["x"],
        "guard-lab-side": probe([("x", plain)], target=f"{GUARD_LAB_IP}:8080")["x"],
    }
    lookups = docker(
        "run",
        "--rm",
        "--network",
        SCAN_NET,
        "--entrypoint",
        "python3",
        "secscan-guard:dev",
        "-I",
        "-c",
        "import socket\nfor name in ['example.com', 'lab-target', 'db']:\n"
        "    try:\n        socket.getaddrinfo(name, 80); print('resolved')\n"
        "    except OSError:\n        print('unresolved')\n",
    )

    assert all(result["status"] is None for result in direct.values()), direct
    assert lookups.split() == ["unresolved"] * 3
    assert len(target.records()) == before
    assert canary.records() == []


# --- SEC-01（期限）、policy 的狀態 -------------------------------------------------------------


def test_expired_stale_blocked_and_corrupt_policies_stop_traffic(target: Receiver) -> None:
    expiring = write_policy(not_after_in=8)
    stale = write_policy(renew_in=-1)
    blocked = write_policy(state="blocked")
    corrupt = write_policy(corrupt=True)
    try:
        allowed = probe(
            [("now", raw_request(f"{TARGET}/api/items/1", authorization=expiring.authorization()))]
        )
        wait_for(
            lambda: (
                probe(
                    [
                        (
                            "later",
                            raw_request(
                                f"{TARGET}/api/items/1", authorization=expiring.authorization()
                            ),
                        )
                    ]
                )["later"]["reason"]
                == "RUN_EXPIRED"
            ),
            timeout=30,
            interval=1,
        )
        others = probe(
            [
                (name, raw_request(f"{TARGET}/api/items/1", authorization=item.authorization()))
                for name, item in (("stale", stale), ("blocked", blocked), ("corrupt", corrupt))
            ]
        )
    finally:
        for item in (expiring, stale, blocked, corrupt):
            remove_policy(item)

    assert allowed["now"]["status"] == 200
    assert others["stale"]["reason"] == "POLICY_STALE"
    assert others["blocked"]["reason"] == "RUN_BLOCKED"
    assert (others["corrupt"]["status"], others["corrupt"]["reason"]) == (
        407,
        "PROXY_AUTH_REQUIRED",
    )


# --- 紀錄不外洩 -------------------------------------------------------------------------------


def test_tokens_and_query_strings_never_reach_logs_or_settings(policy: LivePolicy) -> None:
    canary_query = "QUERYCANARY7f3a"
    probe([("query", _get(f"/api/items/7?secret={canary_query}", policy))])

    for service in ("guard", "runner", "api", "worker"):
        logs = docker("logs", container(service), check=False)
        assert policy.token not in logs, service
        assert canary_query not in logs, service
        assert policy.token not in json.dumps(inspect(container(service))), service
    paths = [str(entry["path"]) for entry in guard_log() if "path" in entry]
    assert "/api/items/7" in paths
    # path 只記 query 之前的部分；"?" 本身是不可見或空的值的替代字。
    assert all(path == "?" or "?" not in path for path in paths)
