"""T16 的 live 靶機：Juice Shop 與 VAmPI（docs/DECISIONS.md §20；make test-live-lab）。

- 映像與 compose.lab.yaml 相同（tag@digest，由那裡讀出，不另外寫一份）；接在 live 自己的 lab 網路
  （internal）上、固定 IP、不發布 port。記憶體只夠一次一個靶機（docs/TOOLS.md §2）。
- 準備憑證（VAmPI 的 /createdb 與登入、Juice Shop 的登入）由一次性的輔助容器（guard 映像的
  python，只接 lab 網路）執行，不經 guard：這是操作者取得 token 的步驟，不是掃描的流量，也不算預算。
  token 只交給 auth profile，不印出、不寫進錄製的檔案。
- VAmPI 的 tokentimetolive 可以縮短，誘發掃描中途的 token 失效（§20.4）。
"""

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from tests.live.support import GUARD_IMAGE, LAB_NET, docker, wait_for

LAB_FILE = Path(__file__).resolve().parents[2] / "compose.lab.yaml"
PREFIX = "secscan-live-lab-"
JUICE_SHOP_IP = "10.89.10.220"
VAMPI_IP = "10.89.10.221"
# T30 自製 fixture app：lab 網路上半段還沒被 .210/.211/.220/.221 佔用的位址。
FIXTURE_IP = "10.89.10.222"
JUICE_SHOP_PORT = 3000
VAMPI_PORT = 5000
FIXTURE_PORT = 8080
# fixture app 跑在 guard 映像的 python（stdlib）：把套件唯讀掛進去、以 -c 設好 sys.path 後匯入。
FIXTURE_DIR = Path(__file__).resolve().parent / "fixture_app"
_FIXTURE_LAUNCH = (
    "import sys; sys.path.insert(0, '/site'); from fixture_app.app import main; main()"
)
# compose.lab.yaml 的預設（掃描中途不會過期）。
LONG_TOKEN_SECONDS = 3600
# Juice Shop 的種子使用者（data/static/users.yml，customer）；VAmPI 的種子使用者（/createdb）。
JUICE_SHOP_USER = {"email": "jim@juice-sh.op", "password": "ncc-1701"}
VAMPI_USER = {"username": "name1", "password": "pass1"}
_CALL = """
import http.client, json, sys, urllib.error, urllib.request
url, method, body = sys.argv[1], sys.argv[2], sys.argv[3]
data = body.encode() if body else None
headers = {"Content-Type": "application/json"} if data else {}
request = urllib.request.Request(url, data=data, method=method, headers=headers)
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        status, text = response.status, response.read().decode("utf-8", "replace")
except urllib.error.HTTPError as error:
    status, text = error.code, error.read().decode("utf-8", "replace")
except (OSError, http.client.HTTPException):
    status, text = 0, ""
print(json.dumps({"status": status, "body": text}))
"""


def lab_image(service: str) -> str:
    services = yaml.safe_load(LAB_FILE.read_text(encoding="utf-8"))["services"]
    return str(services[service]["image"])


@dataclass(frozen=True)
class Target:
    container: str
    host: str
    ip: str
    port: int

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    def memory(self) -> str:
        """docker stats 的記憶體用量（量測用）。"""
        return docker("stats", "--no-stream", "--format", "{{.MemUsage}}", self.container).strip()


def _host(kind: str) -> str:
    return f"lab-{kind}-{uuid.uuid4().hex[:6]}"


def _run(target: Target, image: str, options: list[str], ready: str) -> Target:
    """啟動之後以輔助容器輪詢 ready 的 path 直到 200（Juice Shop 是 distroless，沒有 shell 可以跑
    docker 的 health-cmd）。
    """
    docker("rm", "-f", target.container, check=False)
    docker(
        "run",
        "-d",
        "--name",
        target.container,
        "--network",
        LAB_NET,
        "--ip",
        target.ip,
        "--network-alias",
        target.host,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "256",
        *options,
        image,
    )
    wait_for(lambda: lab_call(target, "GET", ready)[0] == 200, timeout=240, interval=3)
    return target


def start_juice_shop() -> Target:
    """compose.lab.yaml 的 juice-shop：NODE_ENV=unsafe、1 GiB；rootfs 可寫（啟動時寫 SQLite）。"""
    target = Target(f"{PREFIX}juice-shop", _host("juice"), JUICE_SHOP_IP, JUICE_SHOP_PORT)
    options = ["--memory", "1g", "-e", "NODE_ENV=unsafe"]
    return _run(target, lab_image("juice-shop"), options, "/rest/admin/application-version")


def start_vampi(*, vulnerable: bool, token_seconds: int = LONG_TOKEN_SECONDS) -> Target:
    """compose.lab.yaml 的 vampi：唯讀 rootfs、DB 在 tmpfs、512 MiB；建好之後呼叫 /createdb。"""
    kind = "vampi-vuln" if vulnerable else "vampi-secure"
    target = Target(f"{PREFIX}{kind}", _host(kind), VAMPI_IP, VAMPI_PORT)
    options = [
        "--memory",
        "512m",
        "--read-only",
        "--tmpfs",
        "/tmp",  # noqa: S108 - 靶機容器內的 tmpfs
        "--tmpfs",
        "/vampi/database",
        "-e",
        f"vulnerable={1 if vulnerable else 0}",
        "-e",
        f"tokentimetolive={token_seconds}",
    ]
    _run(target, lab_image("vampi-vuln"), options, "/")
    status, _ = lab_call(target, "GET", "/createdb")
    assert status == 200, status
    return target


def start_fixture(*, vulnerable: bool) -> Target:
    """T30 自製 fixture app（弱點版或修補版）；掛在 guard 映像的 python 上，只接 lab 網路。"""
    kind = "fixture-vuln" if vulnerable else "fixture-secure"
    target = Target(f"{PREFIX}{kind}", _host(kind), FIXTURE_IP, FIXTURE_PORT)
    docker("rm", "-f", target.container, check=False)
    docker(
        "run",
        "-d",
        "--name",
        target.container,
        "--network",
        LAB_NET,
        "--ip",
        target.ip,
        "--network-alias",
        target.host,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--pids-limit",
        "256",
        "--memory",
        "256m",
        "--entrypoint",
        "python3",
        "-v",
        f"{FIXTURE_DIR}:/site/fixture_app:ro",
        GUARD_IMAGE,
        "-I",
        "-B",
        "-u",
        "-c",
        _FIXTURE_LAUNCH,
        target.host,
        str(target.port),
        "1" if vulnerable else "0",
    )
    wait_for(lambda: '"ready": true' in docker("logs", target.container), timeout=30, interval=1)
    return target


def fixture_records(target: Target) -> list[dict[str, Any]]:
    """fixture app 每個請求輸出一行 JSON 收包證據（排除 ready 那一行）。"""
    lines = docker("logs", target.container).splitlines()
    records = [json.loads(line) for line in lines if line.startswith("{")]
    return [record for record in records if "ready" not in record]


def stop_target(target: Target) -> None:
    docker("rm", "-f", target.container, check=False)


def lab_call(
    target: Target, method: str, path: str, body: dict[str, Any] | None = None
) -> tuple[int, str]:
    """在 lab 網路上以輔助容器送一個請求（不經 guard；只用來準備憑證與資料）。"""
    output = docker(
        "run",
        "--rm",
        "--network",
        LAB_NET,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--entrypoint",
        "python3",
        GUARD_IMAGE,
        "-I",
        "-c",
        _CALL,
        f"{target.origin}{path}",
        method,
        json.dumps(body) if body is not None else "",
    )
    result = json.loads(output)
    return int(result["status"]), str(result["body"])


def vampi_token(target: Target) -> str:
    status, body = lab_call(target, "POST", "/users/v1/login", VAMPI_USER)
    assert status == 200, status
    token = json.loads(body)["auth_token"]
    assert isinstance(token, str)
    return token


def juice_shop_token(target: Target) -> str:
    status, body = lab_call(target, "POST", "/rest/user/login", JUICE_SHOP_USER)
    assert status == 200, status
    token = json.loads(body)["authentication"]["token"]
    assert isinstance(token, str)
    return token
