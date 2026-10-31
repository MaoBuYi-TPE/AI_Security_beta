"""執行中撤銷 grant（docs/DECISIONS.md §17.5；SEC-01 後半）。

管理員撤銷 grant 之後，下一次心跳（≤ 5 秒）看到撤銷：runner 先封鎖 guard、再停止容器，run 是
failed（SCOPE_REVOKED）。以借用的 proxy-url 每 20 ms 送一次請求的背景探針記下 guard 的回應：撤銷
之後 10 秒內開始拒絕、之後接收端收不到任何請求；policy 的觀察者記下封鎖早於容器的 kill／die。
不中斷 stack。
"""

import time
import uuid
from collections.abc import Iterator
from urllib.parse import urlsplit

import pytest

from tests.live.guard_support import (
    Receiver,
    guard_log,
    probe,
    start_receiver,
    stop_receiver,
    watch,
)
from tests.live.run_support import (
    ContainerEvents,
    PolicyWatch,
    borrow,
    fake_engine,
    first,
    running,
    stopped_at,
)
from tests.live.support import (
    LAB_IP,
    Api,
    Scannable,
    admin_key,
    scan_containers,
    scannable,
    wait_for,
)

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]


@pytest.fixture(scope="module")
def admin() -> Api:
    return Api(admin_key())


@pytest.fixture
def target(admin: Api) -> Iterator[tuple[Scannable, Receiver, str]]:
    item = scannable(admin, f"canary-{uuid.uuid4().hex[:12]}")
    origin = str(item.operator.data("GET", f"/targets/{item.target_id}")["canonical_origin"])
    host = urlsplit(origin).hostname
    assert host is not None
    receiver = start_receiver(f"revoke-target-{host}", ip=LAB_IP, aliases=(host,), port=5000)
    yield item, receiver, origin
    stop_receiver(receiver)


@pytest.fixture
def events() -> Iterator[ContainerEvents]:
    stream = ContainerEvents.start()
    yield stream
    stream.stop()


def test_revoking_the_grant_stops_a_running_scan(
    admin: Api, target: tuple[Scannable, Receiver, str], events: ContainerEvents
) -> None:
    item, receiver, origin = target
    scan_id = item.scan()
    name = running(scan_id)
    borrowed = borrow(name)
    request = borrowed.request(origin, "/users/v1")
    assert probe([("before", request)])["before"]["status"] == 200
    watcher = watch(request, seconds=15)
    policy = PolicyWatch.start(borrowed.run_id, seconds=12)

    admin.data("POST", f"/scope-grants/{item.grant_id}/revoke", {"reason": "live 測試：撤回授權"})
    revoked_at = time.time()
    results = watcher.results()
    wait_for(lambda: fake_engine(item, scan_id)["status"] == "failed", timeout=60)

    allowed = [result for result in results if result["status"] == 200]
    denied = [result for result in results if result["status"] != 200]
    assert allowed
    assert denied
    first_denied = min(result["t"] for result in denied)
    assert max(result["t"] for result in allowed) < first_denied
    assert first_denied - revoked_at < 10  # 心跳每 5 秒
    assert {(result["status"], result["reason"]) for result in denied} <= {
        (403, "RUN_BLOCKED"),
        (407, "PROXY_AUTH_REQUIRED"),
    }
    blocked = [
        float(entry["ts"])
        for entry in guard_log()
        if entry.get("reason") == "RUN_BLOCKED" and entry.get("run_id") == borrowed.run_id
    ]
    assert blocked, "封鎖到刪除 policy 之間應該有 RUN_BLOCKED"
    events.stop()
    assert first(policy.changes(), "blocked") <= stopped_at(events.of(name))
    # preflight 的兩個 GET /me 也到達這個接收端（§16.5）：只數借用的 proxy-url 送出的請求。
    borrowed_paths = [record for record in receiver.records() if record["path"] == "/users/v1"]
    assert len(borrowed_paths) == 1 + len(allowed)
    assert fake_engine(item, scan_id)["error_code"] == "SCOPE_REVOKED"
    wait_for(lambda: scan_containers(scan_id) == [] or None, timeout=30)
    # preflight 在撤銷之前已經成功，但它不是結果引擎：掃描引擎都沒有成功 → failed
    # （docs/DECISIONS.md §19.8；T14 之前是 partially_completed）。
    assert item.status(scan_id) == "failed"
