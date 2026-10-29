"""live 測試共用：docker CLI、平台 API 的最小 client，以及建立可以掃描的 target。

只在 make test-live-runner 建立的獨立 stack 上使用（compose 專案 SECSCAN_LIVE_PROJECT，API 綁
127.0.0.1:8765）。不碰開發用的 db，也不碰 127.0.0.1:8000 的其他服務。
"""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

PROJECT = os.environ.get("SECSCAN_LIVE_PROJECT", "secscan-live")
API = "http://127.0.0.1:8765/api/v1"
SCAN_NET = "secscan_live_scan_net"
LAB_NET = "secscan_live_lab_net"
SECRETS_VOLUME = "secscan_live_run_secrets"
POLICIES_VOLUME = "secscan_live_guard_policies"
STATUS_VOLUME = "secscan_live_guard_status"
TELEMETRY_VOLUME = "secscan_live_guard_telemetry"
# live stack 的 lab 網段（LAB_CIDR）與 guard 的固定位址（Makefile 的 LIVE_*）。
LAB_CIDR = "10.89.10.0/24"
GUARD_IP = "10.89.9.254"
GUARD_LAB_IP = "10.89.10.254"
SPEC = Path(__file__).resolve().parents[1] / "fixtures" / "openapi" / "vampi-openapi3.yml"
BUSYBOX = "busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e"
LAB_IP = "10.89.10.20"
GUARD_IMAGE = "secscan-guard:dev"


def docker(*arguments: str, stdin: str | None = None, check: bool = True) -> str:
    # 執行的是固定的 docker 指令與測試自己組的參數，沒有外部輸入。
    result = subprocess.run(  # noqa: S603
        ["docker", *arguments],  # noqa: S607
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"docker {arguments[0]} 失敗：{result.stderr.strip()}")
    return result.stdout


def container(service: str) -> str:
    return f"{PROJECT}-{service}-1"


def inspect(name: str) -> dict[str, Any]:
    [info] = json.loads(docker("inspect", name))
    return dict(info)


def scan_containers(scan_id: str, engine: str | None = None) -> list[str]:
    """scan 的容器（engine 給定時只看那個引擎的，例如 preflight 或 fake）。"""
    filters = ["--filter", f"label=secscan.scan_id={scan_id}"]
    if engine is not None:
        filters += ["--filter", f"label=secscan.engine={engine}"]
    output = docker("ps", "-a", *filters, "--format", "{{.Names}}")
    return output.split()


def wait_for[T](check: Callable[[], T | None], *, timeout: float, interval: float = 0.5) -> T:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value is not None and value is not False:
            return value
        time.sleep(interval)
    raise AssertionError(f"{timeout} 秒內沒有等到")


@dataclass
class Api:
    key: str = field(repr=False)

    def call(
        self,
        method: str,
        path: str,
        body: object = None,
        *,
        raw: bytes | None = None,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        sent = {"Authorization": f"Bearer {self.key}", **(headers or {})}
        if data is not None:
            sent["Content-Type"] = content_type
        request = urllib.request.Request(API + path, data=data, method=method, headers=sent)  # noqa: S310
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def data(self, method: str, path: str, body: object = None, **options: Any) -> Any:
        status, payload = self.call(method, path, body, **options)
        assert 200 <= status < 300, (status, payload.get("error"))
        return payload["data"]


def admin_key() -> str:
    """以 runner 容器裡的本機 CLI 建立 admin key（完整的 key 只寫到 stdout）。"""
    return docker(
        "exec", container("runner"), "secscan-admin", "create-admin-key", "--name", "live"
    ).strip()


@dataclass(frozen=True)
class Scannable:
    operator: Api
    host: str
    target_id: str
    grant_id: str
    spec_id: str
    profile_id: str

    def scan(self) -> str:
        status, payload = self.operator.call(
            "POST",
            "/scans",
            {
                "target_id": self.target_id,
                "scope_grant_id": self.grant_id,
                "api_spec_id": self.spec_id,
                "auth_profile_id": self.profile_id,
                "profile": "api_active_lab",
                "engines": ["fake"],
            },
            headers={"Idempotency-Key": str(uuid.uuid4())},
        )
        assert status == 202, (status, payload.get("error"))
        return str(payload["data"]["id"])

    def status(self, scan_id: str) -> str:
        return str(self.operator.data("GET", f"/scans/{scan_id}")["status"])


def scannable(admin: Api, secret: str) -> Scannable:
    """新的 project、operator、target、核准的 grant、規格與 bearer profile（secret 是 canary）。"""
    project = admin.data("POST", "/projects", {"name": f"live-{uuid.uuid4().hex[:8]}"})
    issued = admin.data(
        "POST", f"/projects/{project['id']}/keys", {"name": "op", "role": "operator"}
    )
    operator = Api(issued["key"])
    host = f"lab-{uuid.uuid4().hex[:6]}"
    origin = f"http://{host}:5000"
    target = operator.data(
        "POST",
        f"/projects/{project['id']}/targets",
        {"name": host, "kind": "api", "base_url": origin},
    )
    grant = operator.data(
        "POST",
        f"/targets/{target['id']}/scope-grants",
        {
            "allowed_origins": [origin],
            "allowed_ips": [LAB_IP],
            "allowed_paths": ["/users/v1", "/users/v1/{username}", "/me"],
            "allowed_methods": ["GET"],
            "authorization_reference": "live test",
            "valid_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    admin.data("POST", f"/scope-grants/{grant['id']}/approve", {"note": "隔離的 live stack"})
    spec = operator.data(
        "POST",
        f"/targets/{target['id']}/api-specs",
        raw=SPEC.read_bytes(),
        content_type="application/yaml",
    )
    profile = operator.data(
        "POST",
        f"/targets/{target['id']}/auth-profiles",
        {
            "name": "user",
            "role_label": "standard_user",
            "type": "bearer",
            "secret": secret,
            "preflight": {
                "method": "GET",
                "path": "/me",
                "expected_status": 200,
                "expected_json": {"/status": "success"},
            },
        },
    )
    return Scannable(operator, host, target["id"], grant["id"], spec["id"], profile["id"])
