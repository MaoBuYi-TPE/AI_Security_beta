"""egress guard 的 live 測試共用（docs/DECISIONS.md §15）：接收端、探針與 policy。

- 接收端（receiver.py）接在 live 的 lab 網路（或 control_net）上，記下每一個 TCP accept。
- 探針（guard_probe.py）接在 live 的 scan 網路上，送原始的 HTTP 請求；帳密經 stdin 傳入。
- policy 經 `docker exec runner` 以 runner 的程式寫入（時間取自 VM 的時鐘，不用宿主的）。
兩個腳本都在 guard 的映像中執行（只需要 Python 的標準函式庫），容器名稱以 secscan-live-t11- 開頭；
make test-live-runner 拆除時會刪掉接在這兩個網路上的容器。
"""

import base64
import json
import subprocess
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.live.support import GUARD_IMAGE, GUARD_IP, LAB_NET, SCAN_NET, container, docker, wait_for

HERE = Path(__file__).resolve().parent
PREFIX = "secscan-live-t11-"
PROXY = f"{GUARD_IP}:8080"
TARGET_IP = "10.89.10.200"
CANARY_IP = "10.89.10.201"
PORT = 8080

_WRITE_POLICY = """
import json, sys, time, uuid
from pathlib import Path
from secscan.grants.domain.scope import HttpMethod, Scope
from secscan.guard.domain.budget import RunBudget
from secscan.guard.domain.credentials import new_token, token_digest
from secscan.guard.domain.policy import Policy, PolicyState, encode_policy, policy_file_name
from secscan.guard.files import remove_file, write_atomic
from secscan.targets.domain import parse_ipv4, parse_origin

spec = json.load(sys.stdin)
directory = Path("/guard/policies")
run_id = uuid.UUID(spec["run_id"]) if spec["run_id"] else uuid.uuid4()
if spec["remove"]:
    remove_file(directory, policy_file_name(run_id))
    print(json.dumps({"run_id": str(run_id)}))
    raise SystemExit
now = int(time.time())
token = spec["token"] or new_token()
policy = Policy(
    run_id=run_id,
    scan_id=uuid.uuid4(),
    state=PolicyState(spec["state"]),
    token_sha256=token_digest(token),
    not_after=now + spec["not_after_in"],
    renew_until=now + spec["renew_in"],
    scope=Scope(
        origins=(parse_origin(spec["origin"]),),
        ips=tuple(parse_ipv4(ip) for ip in spec["ips"]),
        paths=tuple(spec["paths"]),
        allow_all_paths=False,
        excluded_paths=tuple(spec["excluded"]),
        methods=tuple(HttpMethod(method) for method in spec["methods"]),
    ),
    budget=RunBudget(
        requests_per_second=spec["rate"], burst=1, max_requests=spec["max_requests"]
    ),
    auth_header=spec["auth_header"],
)
raw = b"{broken" if spec["corrupt"] else encode_policy(policy)
write_atomic(directory, policy_file_name(run_id), raw)
print(json.dumps({"run_id": str(run_id), "token": token, "now": now}))
"""


@dataclass(frozen=True)
class LivePolicy:
    run_id: str
    token: str = field(repr=False)

    def authorization(self, token: str | None = None) -> str:
        credentials = f"{self.run_id}:{token or self.token}".encode()
        return "Basic " + base64.b64encode(credentials).decode()


def write_policy(
    *,
    origin: str = f"http://lab-target:{PORT}",
    ips: Sequence[str] = (TARGET_IP,),
    paths: Sequence[str] = ("/api/items/{id}", "/api/items"),
    excluded: Sequence[str] = ("/api/admin",),
    methods: Sequence[str] = ("GET",),
    state: str = "active",
    not_after_in: int = 600,
    renew_in: int = 600,
    corrupt: bool = False,
    reuse: LivePolicy | None = None,
    rate: int = 2,
    max_requests: int = 1000,
    auth_header: str | None = "authorization",
) -> LivePolicy:
    """在 runner 容器內寫入 policy（runner 的程式、VM 的時鐘）；reuse 時沿用 run_id 與 token。"""
    spec = {
        "run_id": reuse.run_id if reuse else None,
        "token": reuse.token if reuse else None,
        "remove": False,
        "origin": origin,
        "ips": list(ips),
        "paths": list(paths),
        "excluded": list(excluded),
        "methods": list(methods),
        "state": state,
        "not_after_in": not_after_in,
        "renew_in": renew_in,
        "corrupt": corrupt,
        "rate": rate,
        "max_requests": max_requests,
        "auth_header": auth_header,
    }
    output = docker(
        "exec",
        "-i",
        container("runner"),
        "python",
        "-I",
        "-c",
        _WRITE_POLICY,
        stdin=json.dumps(spec),
    )
    result = json.loads(output)
    return LivePolicy(run_id=result["run_id"], token=result["token"])


def remove_policy(policy: LivePolicy) -> None:
    spec = {"run_id": policy.run_id, "remove": True}
    docker(
        "exec",
        "-i",
        container("runner"),
        "python",
        "-I",
        "-c",
        _WRITE_POLICY,
        stdin=json.dumps(spec),
    )


def raw_request(
    target: str,
    *,
    method: str = "GET",
    host: str | None = f"lab-target:{PORT}",
    authorization: str | None = None,
    headers: Iterable[tuple[str, str]] = (),
    body: bytes = b"",
    version: str = "HTTP/1.1",
) -> bytes:
    """一個原始的請求：target 是 request target（absolute-form、origin-form 或 authority）。"""
    lines = [f"{method} {target} {version}"]
    if host is not None:
        lines.append(f"Host: {host}")
    if authorization is not None:
        lines.append(f"Proxy-Authorization: {authorization}")
    lines.extend(f"{name}: {value}" for name, value in headers)
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


def probe(
    cases: Sequence[tuple[str, bytes]], *, target: str = PROXY, network: str = SCAN_NET
) -> dict[str, dict[str, Any]]:
    """在 network 上的一次性容器送出每個 case，回傳 名稱 → 結果。"""
    payload = {
        "target": target,
        "cases": [{"name": name, "raw": base64.b64encode(raw).decode()} for name, raw in cases],
    }
    output = docker(
        "run",
        "--rm",
        "-i",
        "--network",
        network,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--entrypoint",
        "python3",
        "-v",
        f"{HERE / 'guard_probe.py'}:/probe/guard_probe.py:ro",
        GUARD_IMAGE,
        "-I",
        "-B",
        "/probe/guard_probe.py",
        stdin=json.dumps(payload),
    )
    results = [json.loads(line) for line in output.splitlines() if line.strip()]
    return {result["name"]: result for result in results}


class Watch:
    """背景的探針：在一段時間內反覆送同一個請求（觀察取消前後的轉變）。帳密經 stdin 傳入。"""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self._process = process

    def results(self, *, timeout: float = 120) -> list[dict[str, Any]]:
        """等探針結束，回傳每一次的結果（t 是容器內的時間）。"""
        assert self._process.stdout is not None
        output = self._process.stdout.read()
        self._process.wait(timeout=timeout)
        return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def watch(raw: bytes, *, seconds: float, interval: float = 0.02) -> Watch:
    payload = {
        "target": PROXY,
        "watch": {"raw": base64.b64encode(raw).decode(), "interval": interval, "seconds": seconds},
    }
    # 固定的 docker 指令與測試自己組的參數；帳密只在 stdin。
    process = subprocess.Popen(  # noqa: S603
        [  # noqa: S607
            "docker",
            "run",
            "--rm",
            "-i",
            "--name",
            f"{PREFIX}watch-{uuid.uuid4().hex[:8]}",
            "--network",
            SCAN_NET,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--entrypoint",
            "python3",
            "-v",
            f"{HERE / 'guard_probe.py'}:/probe/guard_probe.py:ro",
            GUARD_IMAGE,
            "-I",
            "-B",
            "/probe/guard_probe.py",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert process.stdin is not None
    process.stdin.write(json.dumps(payload))
    process.stdin.close()
    return Watch(process)


@dataclass(frozen=True)
class Receiver:
    name: str

    @property
    def container(self) -> str:
        return f"{PREFIX}{self.name}"

    def records(self) -> list[dict[str, Any]]:
        lines = docker("logs", self.container).splitlines()
        records = [json.loads(line) for line in lines if line.startswith("{")]
        return [record for record in records if "ready" not in record]

    def paths(self) -> list[str]:
        return [str(record["path"]) for record in self.records()]


def start_receiver(
    name: str,
    *,
    ip: str | None,
    aliases: Sequence[str] = (),
    network: str = LAB_NET,
    port: int = PORT,
) -> Receiver:
    receiver = Receiver(name)
    docker("rm", "-f", receiver.container, check=False)
    alias_flags = [flag for alias in aliases for flag in ("--network-alias", alias)]
    ip_flags = ["--ip", ip] if ip is not None else []
    docker(
        "run",
        "-d",
        "--name",
        receiver.container,
        "--network",
        network,
        *ip_flags,
        *alias_flags,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--entrypoint",
        "python3",
        "-v",
        f"{HERE / 'receiver.py'}:/receiver/receiver.py:ro",
        GUARD_IMAGE,
        "-I",
        "-B",
        "-u",
        "/receiver/receiver.py",
        name,
        str(port),
    )
    wait_for(lambda: '"ready": true' in docker("logs", receiver.container), timeout=20)
    return receiver


def stop_receiver(receiver: Receiver) -> None:
    docker("rm", "-f", receiver.container, check=False)


def reconnect(
    receiver: Receiver, *, ip: str, aliases: Sequence[str], network: str = LAB_NET
) -> None:
    """換掉接收端的 alias（SEC-04：同一個名稱改指向別的容器）。"""
    docker("network", "disconnect", "-f", network, receiver.container)
    alias_flags = [flag for alias in aliases for flag in ("--alias", alias)]
    docker("network", "connect", "--ip", ip, *alias_flags, network, receiver.container)


def guard_log() -> list[dict[str, Any]]:
    """guard 的 JSON 紀錄（每行一筆）。"""
    lines = docker("logs", container("guard")).splitlines()
    return [json.loads(line) for line in lines if line.startswith('{"ts"')]
