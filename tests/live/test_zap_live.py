"""ZAP 的 live 測試（docs/DECISIONS.md §18；make test-live-zap）。

真的 ZAP 映像經 runner、socket-proxy 與 egress guard 掃描 live 自己 lab 網路上的小型網站
（zap_site.py；不是 Juice Shop 或 VAmPI，那些在 T16）。收包證據以網站與 canary 的紀錄、guard 的
決策 log 為準：
- capability probe：runner 啟動時實際執行映像，GET /scanners 顯示版本。
- -silent 與伺服器產生的 AF plan：guard 只看到 target 的請求（沒有 zaproxy.org、OAST 或其他 host）。
- 範圍：grant 排除的 path、grant 不允許的 method、不在範圍的 DELETE operation 都沒有到達網站。
- 認證：bearer、api_key_header、cookie 都以 ZAP_AUTH_HEADER* 注入，值只到 target；不在容器的
  Env、Cmd、Labels，也不在 out/。anonymous 沒有任何認證 header。
- 取消：先封鎖 guard 再停止容器；量測 ZAP 收到 SIGTERM 之後的行為。
- 量測（§18.10）：拒絕的原因、2 MiB 的回應、cookie 的合併、規格的邊界：印在輸出、記在 TOOLS.md。
"""

import hashlib
import json
from collections import Counter
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

import pytest

from tests.live.guard_support import Receiver, start_receiver, stop_receiver
from tests.live.run_support import ContainerEvents, PolicyWatch, borrow, first, stopped_at
from tests.live.support import Api, admin_key, docker, inspect, scan_containers, wait_for
from tests.live.zap_support import (
    CANARY_IP,
    SITE_IP,
    ZAP_VERSION,
    Lab,
    Site,
    lab,
    manifest,
    now,
    requests_since,
    run_file,
    start_site,
    stop_site,
    wait_for_zap,
)

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture(scope="module")
def canary() -> Iterator[Receiver]:
    receiver = start_receiver("zap-canary", ip=CANARY_IP, aliases=("lab-canary",))
    yield receiver
    stop_receiver(receiver)


@pytest.fixture
def sites() -> Iterator[list[Site]]:
    started: list[Site] = []
    yield started
    for site in started:
        stop_site(site)


def _site(sites: list[Site], item: Lab) -> Site:
    site = start_site(item.host, ip=SITE_IP, alias=item.host)
    sites.append(site)
    return site


def _container(scan_id: str) -> str:
    def find() -> str | None:
        names = scan_containers(scan_id, "zap")
        return names[0] if names else None

    return wait_for(find, timeout=180)


def _hosts(entries: list[dict[str, Any]]) -> set[tuple[object, object]]:
    return {(entry.get("host"), entry.get("port")) for entry in entries if "host" in entry}


def _assert_hidden(info: dict[str, Any], *secrets: str) -> None:
    """secret 不在容器的設定中（執行中 inspect 的結果；Env 只有非秘密的值、Cmd 是 script、Labels
    只有 id）。
    """
    config = json.dumps(info["Config"])
    for secret in secrets:
        assert secret not in config


def _measure(label: str, entries: list[dict[str, Any]]) -> None:
    reasons = Counter(str(entry.get("reason")) for entry in entries if entry["decision"] == "deny")
    allowed = sum(1 for entry in entries if entry["decision"] == "allow")
    print(f"[量測] {label}：放行 {allowed}，拒絕 {dict(reasons)}")  # noqa: T201


def test_the_runner_probe_reports_the_pinned_zap(admin: Api) -> None:
    zap = wait_for_zap(admin)

    assert zap["version"] == ZAP_VERSION
    assert zap["integrated"] is False  # 預覽開關：T15 才開放
    assert zap["image"].startswith("zaproxy/zap-stable:20261016@sha256:")


def test_an_anonymous_web_scan_stays_inside_the_grant(
    admin: Api, canary: Receiver, sites: list[Site]
) -> None:
    wait_for_zap(admin)
    item = lab(admin, kind="web", paths=None, excluded=["/admin"], methods=["GET", "HEAD"])
    site = _site(sites, item)
    started = now()

    scan_id = item.scan("web_active_lab", budget={"max_duration_seconds": 240})
    container = _container(scan_id)
    run_id = container.removeprefix("secscan-run-")
    token = borrow(container).token
    config = inspect(container)
    engine = item.finished_zap(scan_id)

    assert engine["status"] == "collected", engine
    assert "SECSCAN_TARGET_AUTH=none" in config["Config"]["Env"]
    assert not [env for env in config["Config"]["Env"] if env.startswith("ZAP_AUTH")]
    assert config["HostConfig"]["ReadonlyRootfs"] is True
    assert config["Config"]["User"] == "10001:10001"
    _assert_hidden(config, token)
    records = site.records()
    assert records, "ZAP 沒有送出任何請求（proxy 的設定沒有生效？）"
    paths = [urlsplit(record["path"]).path for record in records]
    assert "/admin" not in {path.lower() for path in paths}
    assert {record["method"] for record in records} <= {"GET", "HEAD"}
    assert all(not record["auth"] for record in records)
    assert "/static/big.js" in paths
    assert canary.records() == []
    entries = requests_since(started)
    assert _hosts(entries) == {(item.host, 3000)}
    _measure("web anonymous", entries)
    document = manifest(run_id)
    assert document["exit_code"] in {0, 2}
    assert {entry["path"] for entry in document["files"]} >= {"zap-report.json", "zap.log"}
    report = json.loads(run_file(run_id, "out/zap-report.json") or b"{}")
    assert report["@version"] == ZAP_VERSION
    assert {site_entry["@name"] for site_entry in report["site"]} <= {item.origin}
    log = (run_file(run_id, "out/zap.log") or b"").decode()
    assert token not in log
    assert token not in json.dumps(report)


SPEC: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {
        "title": "lab items",
        "version": "1",
        "contact": {"url": "http://lab-canary:8080/contact"},
        "license": {"name": "x", "url": "http://lab-canary:8080/license"},
    },
    "externalDocs": {"url": "http://lab-canary:8080/docs"},
    "servers": [{"url": "http://lab-canary:8080/api"}],
    "paths": {
        "/items": {
            "get": {"operationId": "listItems", "responses": {"200": {"description": "ok"}}}
        },
        "/items/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}
            ],
            "get": {
                "operationId": "getItem",
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Item"}}
                        },
                        "links": {
                            "self": {
                                "operationId": "getItem",
                                "parameters": {"id": "$response.body#/id"},
                            }
                        },
                    }
                },
            },
            "delete": {"operationId": "deleteItem", "responses": {"204": {"description": "gone"}}},
        },
    },
    "components": {
        "schemas": {
            "Item": {
                "id": "http://lab-canary:8080/schemas/item",
                "type": "object",
                "discriminator": {"propertyName": "kind"},
                "properties": {"id": {"type": "integer"}, "kind": {"type": "string"}},
                "example": {"id": 1, "kind": "http://lab-canary:8080/example"},
            }
        }
    },
}


def _api_lab(admin: Api) -> Lab:
    return lab(admin, kind="api", paths=["/api/items", "/api/items/{id}", "/me"], methods=["GET"])


def _upload(item: Lab, spec: dict[str, Any]) -> str:
    uploaded = item.operator.data(
        "POST",
        f"/targets/{item.target_id}/api-specs",
        raw=json.dumps(spec).encode(),
        content_type="application/json",
    )
    return str(uploaded["id"])


def _profile(item: Lab, kind: str, secret: str, header: str | None = None) -> str:
    body: dict[str, Any] = {
        "name": kind.replace("_", "-"),
        "role_label": "standard_user",
        "type": kind,
        "secret": secret,
        "preflight": {
            "method": "GET",
            "path": "/me",
            "expected_status": 200,
            "expected_json": {"/status": "success"},
        },
    }
    if header is not None:
        body["header_name"] = header
    created = item.operator.data("POST", f"/targets/{item.target_id}/auth-profiles", body)
    return str(created["id"])


def test_a_bearer_api_scan_sends_only_eligible_operations_to_the_target(
    admin: Api, canary: Receiver, sites: list[Site]
) -> None:
    wait_for_zap(admin)
    item = _api_lab(admin)
    site = _site(sites, item)
    token = f"zap-live-{_digest(item.host)}"
    spec_id = _upload(item, SPEC)
    profile_id = _profile(item, "bearer", token)
    started = now()

    scan_id = item.scan(
        "api_active_lab",
        spec_id=spec_id,
        auth_profile_id=profile_id,
        budget={"max_duration_seconds": 240},
    )
    container = _container(scan_id)
    config = inspect(container)
    proxy_token = borrow(container).token
    engine = item.finished_zap(scan_id)

    assert engine["status"] == "collected", engine
    env = config["Config"]["Env"]
    assert "SECSCAN_TARGET_AUTH=header" in env
    assert "ZAP_AUTH_HEADER=Authorization" in env
    assert f"ZAP_AUTH_HEADER_SITE={item.host}" in env
    _assert_hidden(config, token, proxy_token)
    records = site.records()
    zap_records = [record for record in records if urlsplit(record["path"]).path != "/me"]
    assert zap_records, "ZAP 沒有送出任何請求"
    assert "DELETE" not in {record["method"] for record in records}
    assert {urlsplit(record["path"]).path.split("/")[1] for record in zap_records} == {"api"}
    expected = _digest(f"Bearer {token}")
    assert {record["auth"].get("authorization") for record in zap_records} == {expected}
    assert canary.records() == []
    entries = requests_since(started)
    assert _hosts(entries) == {(item.host, 3000)}
    _measure("api bearer", entries)
    run_id = container.removeprefix("secscan-run-")
    for name in ("out/zap.log", "out/zap-report.json"):
        content = (run_file(run_id, name) or b"").decode()
        assert token not in content
        assert proxy_token not in content


@pytest.mark.parametrize(
    ("kind", "header", "wire"),
    [("api_key_header", "X-Api-Key", "x-api-key"), ("cookie", None, "cookie")],
)
def test_header_and_cookie_profiles_reach_only_the_target(
    admin: Api, canary: Receiver, sites: list[Site], kind: str, header: str | None, wire: str
) -> None:
    wait_for_zap(admin)
    item = _api_lab(admin)
    site = _site(sites, item)
    secret = f"session={_digest(item.host)}" if kind == "cookie" else f"key-{_digest(item.host)}"
    spec_id = _upload(item, SPEC)
    profile_id = _profile(item, kind, secret, header)
    started = now()

    # 2 req/s、300 個請求：maxDuration 以請求數計算（150 秒減去保留的 60 秒），ZAP 自己結束。
    scan_id = item.scan(
        "api_active_lab",
        spec_id=spec_id,
        auth_profile_id=profile_id,
        budget={"max_requests": 300},
    )
    engine = item.finished_zap(scan_id)

    assert engine["status"] == "collected", engine
    zap_records = [r for r in site.records() if urlsplit(r["path"]).path != "/me"]
    assert zap_records
    digests = Counter(record["auth"].get(wire) for record in zap_records)
    print(f"[量測] {kind}：{wire} 的值 {dict(digests)}，預期 {_digest(secret)}")  # noqa: T201
    assert digests[_digest(secret)] == len(zap_records)
    assert canary.records() == []
    assert _hosts(requests_since(started)) == {(item.host, 3000)}


def test_cancelling_blocks_the_guard_before_stopping_zap(admin: Api, sites: list[Site]) -> None:
    wait_for_zap(admin)
    item = lab(admin, kind="web", paths=None, methods=["GET", "HEAD"])
    site = _site(sites, item)
    events = ContainerEvents.start()

    scan_id = item.scan("web_active_lab", budget={"max_duration_seconds": 600})
    container = _container(scan_id)
    run_id = container.removeprefix("secscan-run-")
    wait_for(lambda: site.records() or None, timeout=120)
    watch = PolicyWatch.start(run_id, seconds=40)
    item.operator.data("POST", f"/scans/{scan_id}/cancel")
    engine = item.finished_zap(scan_id, timeout=60)
    events.stop()

    assert engine["status"] == "cancelled"
    blocked_at = first(watch.changes(), "blocked")
    container_events = events.of(container)
    assert blocked_at <= stopped_at(container_events)
    late = [record for record in site.records() if record["t"] > blocked_at + 1.0]
    assert late == []
    after = [
        entry
        for entry in requests_since(blocked_at)
        if entry.get("run_id") == run_id and entry["decision"] == "deny"
    ]
    exits = [moment for moment, action in container_events if action == "die"]
    kills = [moment for moment, action in container_events if action == "kill"]
    print(  # noqa: T201
        f"[量測] 取消：封鎖之後被拒 {len(after)} 個；kill→die "
        f"{(min(exits) - min(kills)) if exits and kills else '?'} 秒"
    )


def test_a_reference_heavy_spec_runs_within_the_container_limits(
    admin: Api, canary: Receiver, sites: list[Site]
) -> None:
    wait_for_zap(admin)
    item = _api_lab(admin)
    _site(sites, item)
    schemas: dict[str, Any] = {"Leaf": {"type": "string", "example": "x"}}
    previous = "Leaf"
    for level in range(8):
        name = f"Level{level}"
        schemas[name] = {
            "type": "object",
            "properties": {f"p{i}": {"$ref": f"#/components/schemas/{previous}"} for i in range(3)},
        }
        previous = name
    spec = {
        **SPEC,
        "paths": {
            "/items": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": f"#/components/schemas/{previous}"}
                                }
                            },
                        }
                    }
                }
            }
        },
        "components": {"schemas": schemas},
    }
    spec_id = _upload(item, spec)
    started = now()

    scan_id = item.scan("api_active_lab", spec_id=spec_id, budget={"max_requests": 300})
    engine = item.finished_zap(scan_id)

    print(f"[量測] 參照炸彈（3^8）：run {engine['status']} {engine['error_code']}")  # noqa: T201
    assert engine["status"] in {"collected", "failed"}
    assert canary.records() == []
    assert _hosts(requests_since(started)) <= {(item.host, 3000)}


def test_the_probe_container_and_scan_containers_are_gone(admin: Api) -> None:
    wait_for_zap(admin)
    filters = ("--filter", "label=secscan.managed=true", "--filter", "label=secscan.engine=zap")
    assert docker("ps", "-a", "-q", *filters).split() == []
