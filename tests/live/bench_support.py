"""T31 的 Live harness 共用（docs/DECISIONS.md §29；make bench）。

只在 make test-live-runner 建立的隔離 stack（secscan-live、API 127.0.0.1:8765）上使用：經平台的公開
API 建立 project、target、grant 與 scan，在 live 自己的 lab 網路上啟動靶機，等 scan 結束後以
benchmarks.collect 收集。不使用其他 live 測試的私有函式，也不改既有的 live 測試。

- 靶機只能是 lab_support 的三種，位址固定在 live 的 lab 網段；同一個靶場在 session 中用同一個
  host（每次重建 origin 不變），每個 scan 之前重建容器，讓資料快照相同。
- Juice Shop、VAmPI 的映像必須已經存在（make lab-images 是另外的步驟），這裡不 pull。
- 等待的上限依 scan 的總秒數加上固定的額外時間，不沿用 zap_support.RUN_TIMEOUT 的 600 秒。
"""

import hashlib
import subprocess
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from benchmarks.collect import Fetch
from benchmarks.models import ScanRecord
from benchmarks.spec import ExperimentSpec, Group, TargetKind, Variant
from tests.live.guard_support import guard_log
from tests.live.lab_support import (
    FIXTURE_DIR,
    LAB_FILE,
    Target,
    lab_image,
    start_fixture,
    start_juice_shop,
    start_vampi,
)
from tests.live.support import GUARD_IMAGE, Api, docker, wait_for

ROOT = Path(__file__).resolve().parents[2]
ENGINE_WAIT_SECONDS = 240
# ZAP 的 JVM 啟動、收集、worker 的解析與每個 run 的清理都不算在 scan 的流量秒數內。
WAIT_OVERHEAD_SECONDS = 900
WEB_METHODS = ["GET", "HEAD", "POST"]
TERMINAL_SCANS = frozenset(
    {"completed", "partially_completed", "failed", "timed_out", "cancelled", "interrupted"}
)
LAB_IMAGES = {TargetKind.JUICE_SHOP: "juice-shop", TargetKind.VAMPI: "vampi-vuln"}
# strict-1 的 guard path 規則沒有執行期的版本代號：以 commit 與 guard 映像識別（§29）。
PATH_POLICY = "strict-1"


@dataclass(frozen=True)
class Placement:
    """一個（組別, 靶場）在平台上的 project、operator、target 與核准的 grant。"""

    operator: Api
    project_id: str
    target_id: str
    grant_id: str
    host: str


def session_hosts(spec: ExperimentSpec) -> dict[str, str]:
    """每個靶場在 session 中固定的 host（各組別的 target 用同一個 origin）。"""
    return {
        target.id: f"lab-{target.kind.value.replace('_', '-')}-{uuid.uuid4().hex[:6]}"
        for target in spec.targets
    }


def require_lab_images(kinds: Sequence[TargetKind]) -> None:
    for kind in sorted(set(kinds) & set(LAB_IMAGES)):
        image = lab_image(LAB_IMAGES[kind])
        docker("image", "inspect", image)


def start_target(kind: TargetKind, variant: Variant, host: str) -> Target:
    vulnerable = variant is Variant.INSECURE
    if kind is TargetKind.FIXTURE:
        return start_fixture(vulnerable=vulnerable, host=host)
    if kind is TargetKind.VAMPI:
        return start_vampi(vulnerable=vulnerable, host=host)
    return start_juice_shop(host=host)


def place(admin: Api, *, group: str, target: Target) -> Placement:
    project = admin.data("POST", "/projects", {"name": f"bench-{group}-{uuid.uuid4().hex[:6]}"})
    issued = admin.data(
        "POST", f"/projects/{project['id']}/keys", {"name": "bench", "role": "operator"}
    )
    operator = Api(issued["key"])
    created = operator.data(
        "POST",
        f"/projects/{project['id']}/targets",
        {"name": target.host, "kind": "web", "base_url": target.origin},
    )
    grant = operator.data(
        "POST",
        f"/targets/{created['id']}/scope-grants",
        {
            "allowed_origins": [target.origin],
            "allowed_ips": [target.ip],
            "allowed_paths": [],
            "allow_all_paths": True,
            "excluded_paths": [],
            "allowed_methods": WEB_METHODS,
            "authorization_reference": "T31 benchmark（隔離的 live lab 網路）",
            "valid_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        },
    )
    admin.data("POST", f"/scope-grants/{grant['id']}/approve", {"note": "隔離的 live stack"})
    return Placement(operator, project["id"], created["id"], grant["id"], target.host)


def wait_for_engines(admin: Api, engines: Sequence[str]) -> list[dict[str, Any]]:
    """runner 啟動時的 probe 通過、引擎可用之後，回傳 GET /scanners 的引擎清單。"""

    def ready() -> list[dict[str, Any]] | None:
        listed = admin.data("GET", "/scanners")["engines"]
        available = {item["engine"] for item in listed if item["available"]}
        return list(listed) if set(engines) <= available else None

    return wait_for(ready, timeout=ENGINE_WAIT_SECONDS, interval=3)


def create_scan(placement: Placement, spec: ExperimentSpec, group: Group) -> str:
    body: dict[str, Any] = {
        "target_id": placement.target_id,
        "scope_grant_id": placement.grant_id,
        "profile": spec.profile,
        "engines": list(group.engines),
        "budget": spec.budget.model_dump(mode="json"),
    }
    if group.engine_budgets is not None:
        body["engine_budgets"] = [share.model_dump(mode="json") for share in group.engine_budgets]
    status, payload = placement.operator.call(
        "POST", "/scans", body, headers={"Idempotency-Key": str(uuid.uuid4())}
    )
    assert status == 202, (status, payload.get("error"))
    return str(payload["data"]["id"])


def wait_finished(api: Api, scan_id: str, *, budget_seconds: int) -> None:
    def finished() -> bool:
        return api.data("GET", f"/scans/{scan_id}")["status"] in TERMINAL_SCANS

    wait_for(finished, timeout=budget_seconds + WAIT_OVERHEAD_SECONDS, interval=5)


def fetcher(api: Api) -> Fetch:
    def fetch(path: str) -> Mapping[str, Any]:
        status, payload = api.call("GET", path)
        assert status == 200, (status, payload.get("error"))
        return payload

    return fetch


def create_comparison(api: Api, baseline: str, current: str) -> str:
    body = {"baseline_scan_id": baseline, "current_scan_id": current}
    status, payload = api.call("POST", "/scan-comparisons", body)
    assert status == 201, (status, payload.get("error"))
    return str(payload["data"]["id"])


def guard_hosts_since(moment: float) -> set[tuple[Any, Any]]:
    """guard 在這個時間之後記下的請求的 (host, port)（只該有靶機）。"""
    return {
        (entry.get("host"), entry.get("port"))
        for entry in guard_log()
        if entry.get("event") == "request" and float(entry["ts"]) >= moment and "host" in entry
    }


def provenance(
    admin: Api, *, scanners: list[dict[str, Any]], hosts: Mapping[str, str]
) -> dict[str, Any]:
    """manifest 的身分：API 拿得到的（scanners、scan-profiles）與 harness 記下的（commit、本機映像、
    fixture 的原始碼雜湊、靶機映像的參照、strict-1）。"""
    return {
        "git_commit": _git("rev-parse", "HEAD"),
        "git_dirty": bool(_git("status", "--porcelain")),
        "scanners": scanners,
        "scan_profiles": admin.data("GET", "/scan-profiles"),
        "targets": {
            "hosts": dict(hosts),
            "fixture_source_sha256": _tree_sha256(FIXTURE_DIR),
            "fixture_runtime_image": _image_id(GUARD_IMAGE),
            "lab_images": {kind.value: lab_image(name) for kind, name in LAB_IMAGES.items()},
            "lab_file_sha256": hashlib.sha256(LAB_FILE.read_bytes()).hexdigest(),
        },
        "guard_image": _image_id(GUARD_IMAGE),
        "path_policy": {"name": PATH_POLICY, "source": "harness", "identified_by": "git_commit"},
    }


def assert_allotments(scan: ScanRecord) -> None:
    """每個開始過的容器 run：分到的等於 min（scan 剩下的, 引擎的上限）；轉送數不超過分到的。

    剩下的以之前的 run 的 guard 計數算（轉送數不明時以分到的數量計），和平台的 RunRecords 相同；
    BUDGET-02、BUDGET-03 的實際執行版本。
    """
    used_requests = used_seconds = 0
    for run in sorted(scan.runs, key=lambda item: item.sequence):
        if run.requests_allotted is None:
            continue
        requests = scan.max_requests - used_requests
        seconds = scan.max_duration_seconds - used_seconds
        if run.cap is not None:
            requests = min(requests, run.cap.max_requests)
            seconds = min(seconds, run.cap.max_duration_seconds)
        assert (run.requests_allotted, run.seconds_allotted) == (requests, seconds), run
        assert run.requests_sent is None or run.requests_sent <= run.requests_allotted, run
        assert run.traffic_seconds is not None, run
        used_requests += (
            run.requests_sent if run.requests_sent is not None else run.requests_allotted
        )
        used_seconds += run.traffic_seconds


def _git(*arguments: str) -> str:
    # 固定的 git 指令，沒有外部輸入。
    result = subprocess.run(  # noqa: S603
        ["git", *arguments],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip()


def _image_id(image: str) -> str:
    return docker("image", "inspect", "--format", "{{.Id}}", image).strip()


def _tree_sha256(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        digest.update(path.relative_to(directory).as_posix().encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()
