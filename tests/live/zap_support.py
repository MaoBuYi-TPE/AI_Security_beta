"""ZAP 的 live 測試的共用工具（docs/DECISIONS.md §18.10；make test-live-zap）。

- 小型網站（zap_site.py）與 canary（receiver.py）只接在 live 自己的 lab 網路上。
- zap 在 T15 才開放：live 的 API 以 SCAN_PREVIEW_ENGINES=zap 啟動（Makefile 的
  SECSCAN_LIVE_PREVIEW_ENGINES）。zap 的 run 停在 collected（worker 還不解析），所以每個情境用新的
  project 與 target，以 run 的狀態判斷。
- runs volume 以唯讀的輔助容器讀取（manifest、報告、zap.log）；runner 不在宿主上。
"""

import json
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from tests.live.guard_support import HERE, guard_log
from tests.live.support import BUSYBOX, GUARD_IMAGE, LAB_NET, Api, docker, wait_for

PREFIX = "secscan-live-zap-"
SITE_IP = "10.89.10.210"
CANARY_IP = "10.89.10.211"
SITE_PORT = 3000
RUNS_VOLUME = "secscan_live_runs"
ZAP_VERSION = "2.17.0"
# ZAP 的 JVM 啟動、spider、active scan 與報告：比 plan 的 maxDuration 多留一些。
RUN_TIMEOUT = 600.0


@dataclass(frozen=True)
class Site:
    name: str

    @property
    def container(self) -> str:
        return f"{PREFIX}{self.name}"

    def records(self) -> list[dict[str, Any]]:
        lines = docker("logs", self.container).splitlines()
        records = [json.loads(line) for line in lines if line.startswith("{")]
        return [record for record in records if "ready" not in record]


def start_site(name: str, *, ip: str, alias: str) -> Site:
    site = Site(name)
    docker("rm", "-f", site.container, check=False)
    docker(
        "run",
        "-d",
        "--name",
        site.container,
        "--network",
        LAB_NET,
        "--ip",
        ip,
        "--network-alias",
        alias,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--entrypoint",
        "python3",
        "-v",
        f"{HERE / 'zap_site.py'}:/site/zap_site.py:ro",
        GUARD_IMAGE,
        "-I",
        "-B",
        "-u",
        "/site/zap_site.py",
        name,
        str(SITE_PORT),
    )
    wait_for(lambda: '"ready": true' in docker("logs", site.container), timeout=20)
    return site


def stop_site(site: Site) -> None:
    docker("rm", "-f", site.container, check=False)


@dataclass(frozen=True)
class Lab:
    """一個新的 project、operator 與 target（指向小型網站），以及核准的 grant。"""

    operator: Api
    host: str
    origin: str
    target_id: str
    grant_id: str

    def scan(
        self,
        profile: str,
        *,
        spec_id: str | None = None,
        auth_profile_id: str | None = None,
        budget: dict[str, int] | None = None,
    ) -> str:
        status, payload = self.operator.call(
            "POST",
            "/scans",
            {
                "target_id": self.target_id,
                "scope_grant_id": self.grant_id,
                "api_spec_id": spec_id,
                "auth_profile_id": auth_profile_id,
                "profile": profile,
                "engines": ["zap"],
                "budget": budget or {},
            },
            headers={"Idempotency-Key": str(uuid.uuid4())},
        )
        assert status == 202, (status, payload.get("error"))
        return str(payload["data"]["id"])

    def zap(self, scan_id: str) -> dict[str, Any]:
        engines = self.operator.data("GET", f"/scans/{scan_id}")["engines"]
        [engine] = [engine for engine in engines if engine["engine"] == "zap"]
        return dict(engine)

    def finished_zap(self, scan_id: str, *, timeout: float = RUN_TIMEOUT) -> dict[str, Any]:
        """等 zap 的 run 不再執行（collected 或終止）。"""
        done = {"collected", "failed", "cancelled", "timed_out", "interrupted"}

        def check() -> dict[str, Any] | None:
            engine = self.zap(scan_id)
            return engine if engine["status"] in done else None

        return wait_for(check, timeout=timeout, interval=3)


def lab(
    admin: Api,
    *,
    kind: str,
    paths: list[str] | None,
    excluded: list[str] | None = None,
    methods: list[str] | None = None,
) -> Lab:
    project = admin.data("POST", "/projects", {"name": f"zap-{uuid.uuid4().hex[:8]}"})
    issued = admin.data(
        "POST", f"/projects/{project['id']}/keys", {"name": "op", "role": "operator"}
    )
    operator = Api(issued["key"])
    host = f"lab-zap-{uuid.uuid4().hex[:6]}"
    origin = f"http://{host}:{SITE_PORT}"
    target = operator.data(
        "POST",
        f"/projects/{project['id']}/targets",
        {"name": host, "kind": kind, "base_url": origin},
    )
    grant = operator.data(
        "POST",
        f"/targets/{target['id']}/scope-grants",
        {
            "allowed_origins": [origin],
            "allowed_ips": [SITE_IP],
            "allowed_paths": paths or [],
            "allow_all_paths": paths is None,
            "excluded_paths": excluded or [],
            "allowed_methods": methods or ["GET", "HEAD"],
            "authorization_reference": "live test（自己的 lab 網路）",
            "valid_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    admin.data("POST", f"/scope-grants/{grant['id']}/approve", {"note": "隔離的 live stack"})
    return Lab(operator, host, origin, target["id"], grant["id"])


def run_file(run_id: str, path: str) -> bytes | None:
    """runs volume 中這個 run 的檔案（唯讀掛載的輔助容器；不存在時是 None）。"""
    output = docker(
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        # run 的目錄是 0700、屬於 10001：沒有 capability 的 root 讀不了。
        "--user",
        "10001:10001",
        "-v",
        f"{RUNS_VOLUME}:/runs:ro",
        "--entrypoint",
        "sh",
        BUSYBOX,
        "-c",
        f'cat "/runs/{uuid.UUID(run_id)}/{path}" 2>/dev/null || true',
    )
    return output.encode() if output else None


def manifest(run_id: str) -> dict[str, Any]:
    content = run_file(run_id, "manifest.json")
    assert content is not None, "沒有 manifest：run 沒有收集輸出"
    document = json.loads(content)
    assert isinstance(document, dict)
    return document


def zap_capability(admin: Api) -> dict[str, Any]:
    engines = admin.data("GET", "/scanners")["engines"]
    [zap] = [engine for engine in engines if engine["engine"] == "zap"]
    return dict(zap)


def wait_for_zap(admin: Api) -> dict[str, Any]:
    """runner 啟動時的 probe（JVM 啟動約 15 秒）通過、zap 可用。"""

    def check() -> dict[str, Any] | None:
        zap = zap_capability(admin)
        return zap if zap["available"] else None

    return wait_for(check, timeout=240, interval=3)


def requests_since(moment: float) -> list[dict[str, Any]]:
    """guard 在這個時間之後記下的每一個請求的判斷（含 407 的 proxy 認證）。"""
    return [
        entry
        for entry in guard_log()
        if entry.get("event") == "request" and float(entry["ts"]) >= moment
    ]


def now() -> float:
    return time.time()
