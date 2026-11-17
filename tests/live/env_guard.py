"""Live 的隔離檢查（T23b-b2；docs/DECISIONS.md §32；計畫 §3.1、§3.1.1）。

make test-live-runner 在白名單的環境（LIVE_PROC_ENV）中，以
`uv run --locked python -I tests/live/env_guard.py <子命令>` 執行；recipe 只負責串接，判斷都在這裡。
只輸出名稱與數量，不輸出任何值（設定、秘密、.env 的內容都不印出）。只用標準函式庫、yaml 與
secscan.cli.secret_files（以 -I 執行，不 import tests 與工作目錄的模組）。細節見各函式的 docstring：

- engine [--expect ID]：本機的 Engine 與驗證過的 compose 主版本；印出 Engine ID（開始時、up 之前、
  結束時各確認一次）。
- preflight --base DIR：拒絕上一次留下的 Live 資源、拋棄式目錄與清理失敗的診斷檔。
- snapshot／compare --root DIR：開發環境的前後快照（compare 從 stdin 讀開始時的快照）。
- check-config --secrets-dir DIR --root DIR、check-unresolved、check-environment --allow NAME...：
  stdin 是 compose 解析出來的設定、未解析的設定與 config --environment，都以允許清單核對。
- check-images --app-image ID --guard-image ID：Live 容器的映像等於 build 之後記錄的映像 ID。
- networks --secrets-dir DIR --network NAME SUBNET IP_RANGE（兩次）：以這次執行的識別建立並標記 Live
  的兩個網路，已存在就失敗（另一次 Live 正在執行）。取代子 make 的 ensure-net（安全審查 H1）。
- cleanup --base DIR --secrets-dir DIR --engine ID [--claimed]：只清理確認屬於這次執行的資源，最後以
  和 preflight 相同的條件確認沒有殘留；任何一步失敗都回報，並在 --base 寫入診斷檔。
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from secscan.cli.secret_files import SECRET_FILES

LIVE_PROJECT = "secscan-live"
DEV_PROJECT = "secscan"
DEV_NETWORKS = frozenset({"secscan_scan_net", "secscan_lab_net"})
LIVE_NETWORKS = frozenset({"secscan_live_scan_net", "secscan_live_lab_net"})
SECRETS_PREFIX = "secscan-live-secrets."
EXPECTED_CONTEXT = "orbstack"
# 驗證過的 compose 主版本（G0 的 S10：v5.1.2）。換主版本時重新驗證之後再放寬。
COMPOSE_MAJOR = "5"
SECRET_FILE_NAMES = frozenset(item.file_name for item in SECRET_FILES)
SECRET_ENV_NAMES = frozenset(
    {
        *(item.env_name for item in SECRET_FILES),
        *(f"{item.env_name}_FILE" for item in SECRET_FILES),
        "POSTGRES_PASSWORD",
        "POSTGRES_PASSWORD_FILE",
        "PGPASSWORD",
        "SECSCAN_OWNER_DB_PASSWORD",
        "SECSCAN_APP_DB_PASSWORD",
    }
)
# compose 自己加進 config --environment 的變數（G0 的調整 3）。
COMPOSE_ADDED = frozenset(
    {
        "COMPOSE_PROJECT_NAME",
        "DOCKER_CLI_PLUGIN_ORIGINAL_CLI_COMMAND",
        "DOCKER_CLI_PLUGIN_SOCKET",
        "PWD",
    }
)
# macOS 的 CoreFoundation 自動加上的文字編碼提示（不是秘密，也不是從 shell 帶進來的設定）。
PLATFORM_ADDED = frozenset({"__CF_USER_TEXT_ENCODING"})
ALWAYS_REFUSED = frozenset({"COMPOSE_ENV_FILES", "COMPOSE_FILE", "COMPOSE_PROFILES"})
APP_SERVICES = frozenset({"api", "runner", "worker", "runs-init"})
# 唯一允許的 bind（都唯讀）：db 的 initdb 目錄與 entrypoint wrapper（相對於 repo）、socket-proxy 的
# docker.sock（compose.yaml 的設計；runner 經由它操作容器）。
ALLOWED_BINDS = {
    "db": {
        "deploy/postgres/initdb": "/docker-entrypoint-initdb.d",
        "deploy/postgres/db-entrypoint.sh": "/usr/local/lib/secscan/db-entrypoint.sh",
    },
    "socket-proxy": {"/var/run/docker.sock": "/var/run/docker.sock"},
}
FILE_MODE = 0o600
IMAGE_FORMAT = '{{index .Config.Labels "com.docker.compose.service"}} {{.Image}}'
GATEWAY_OPTION = "com.docker.network.bridge.gateway_mode_ipv4"
# 這次執行的所有權：網路以拋棄式目錄的名稱標記（mktemp 建立，同一個 TMPDIR 之下唯一）。
RUN_LABEL = "secscan.live.run"
RUN_ID_PATTERN = re.compile(r"secscan-live-secrets\.[A-Za-z0-9]{6}")
NETWORK_FORMAT = (
    f'{{{{.Internal}}}}|{{{{index .Options "{GATEWAY_OPTION}"}}}}|'
    "{{range .IPAM.Config}}{{.Subnet}} {{.IPRange}}{{end}}|"
    f'{{{{index .Labels "{RUN_LABEL}"}}}}'
)
NETWORK_LABEL_FORMAT = f'{{{{index .Labels "{RUN_LABEL}"}}}}'
PROJECT_LABEL = "com.docker.compose.project"
PROJECT_FILTER = f"label={PROJECT_LABEL}={LIVE_PROJECT}"
# 清理的候選容器：完整的 ID、compose 專案（JSON：沒有標記是 ""，和字面的 "<no value>" 分得開）、
# 接的網路（只取這三項，不取 Env）。
CONTAINER_FORMAT = (
    f'{{{{.Id}}}}|{{{{json (index .Config.Labels "{PROJECT_LABEL}")}}}}|'
    "{{range $name, $value := .NetworkSettings.Networks}}{{$name}} {{end}}"
)
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
# 接在某個網路上的容器（含停止的）：完整的 ID。
_ON_NETWORK = ("ps", "-aq", "--no-trunc", "--filter")
# docker 的 index 在原始 JSON 上取不到值時印出的文字（網路的標記沒有值時；這裡只當成「不是這次的
# 識別」，測試的替身也使用）。
NO_VALUE = "<no value>"
DOCKER_TIMEOUT_SECONDS = 120
# 清理只用這裡的常數（make 的變數可能被覆寫）。
COMPOSE_FILE = "compose.yaml"
LIVE_COMPOSE = ("compose", "-p", LIVE_PROJECT, "-f", COMPOSE_FILE, "--profile", "app")
# down -v 會刪除的 volume 與網路：只能是 Live 的名稱（專案前綴或 LIVE_ENV 的 secscan_live_*）。
LIVE_RESOURCE_PREFIXES = (f"{LIVE_PROJECT}_", "secscan_live_")
DIAGNOSTIC_PREFIX = "secscan-live-cleanup-failed."
ENGINE_AT_START = "清理開始時：沒有清理、也沒有核對任何 Docker 資源"
ENGINE_BEFORE_DOWN = (
    "compose down 之前：已刪除 Live 網路上確認過的容器，之後停止（沒有 down、沒有刪除網路、"
    "沒有核對殘留）"
)
EXIT_OK = 0
EXIT_FAILURE = 1

type Runner = Callable[[Sequence[str]], str]
_READS_STDIN = frozenset({"compare", "check-config", "check-unresolved", "check-environment"})


class GuardError(Exception):
    """隔離檢查不通過；訊息只有名稱與數量。"""


def docker(arguments: Sequence[str]) -> str:
    """固定的 docker 指令（白名單的環境）。失敗、逾時、無法執行都轉成 GuardError（第二輪 MEDIUM-1：
    清理的每一步只記錄失敗、繼續其他獨立的步驟）；訊息只有子命令、結束碼與例外的類別。"""
    command = arguments[0]
    try:
        # 參數由這個模組組成，沒有外部輸入；docker 從 PATH 找到（白名單保留 PATH）。
        result = subprocess.run(  # noqa: S603
            ["docker", *arguments],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GuardError(f"docker {command} 逾時（{DOCKER_TIMEOUT_SECONDS}s）：無法確認") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise GuardError(f"無法執行 docker {command}（{type(exc).__name__}）：無法確認") from None
    if result.returncode != 0:
        raise GuardError(f"docker {command} 失敗（結束碼 {result.returncode}）：無法確認，停止")
    return result.stdout


# --------------------------------------------------------------------------- engine、preflight


def engine(environ: Mapping[str, str], run: Runner, expect: str | None) -> str:
    host = environ.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        raise GuardError("DOCKER_HOST 必須是本機的 unix socket")
    if run(["context", "show"]).strip() != EXPECTED_CONTEXT and not host:
        raise GuardError(f"Docker context 不是 {EXPECTED_CONTEXT}")
    version = run(["compose", "version", "--short"]).strip().removeprefix("v")
    if version.split(".", 1)[0] != COMPOSE_MAJOR:
        raise GuardError(f"docker compose 的主版本不是驗證過的 {COMPOSE_MAJOR}")
    engine_id = run(["info", "--format", "{{.ID}}"]).strip()
    if not engine_id:
        raise GuardError("取不到 Engine ID")
    if expect is not None and engine_id != expect:
        raise GuardError("Engine ID 和開始時不同：停止")
    return engine_id


def preflight(base: Path, run: Runner) -> None:
    leftovers = sorted(path.name for path in base.glob(f"{SECRETS_PREFIX}*"))
    if leftovers:
        raise GuardError(f"上一次的拋棄式目錄還在（{len(leftovers)} 個）：確認之後刪除再執行")
    diagnostics = sorted(path.name for path in base.glob(f"{DIAGNOSTIC_PREFIX}*"))
    if diagnostics:
        raise GuardError(
            f"上一次的清理失敗（{base} 中有 {len(diagnostics)} 個診斷檔）：確認並處理之後刪除"
            "診斷檔再執行"
        )
    remaining = _counts(live_resources(run))
    if remaining:
        raise GuardError(f"已有 {LIVE_PROJECT} 的資源：{remaining}；先清除再執行")


def live_resources(run: Runner) -> dict[str, list[str]]:
    """Live 的資源：preflight 與清理之後的殘留檢查用同一個條件（第二輪 HIGH 條件 5、6）。

    不只看網路：容器與 volume 以 compose 的專案標記找，volume 另外以 Live 的名稱前綴找（LIVE_ENV 的
    secscan_live_*；不是 compose 建立的也算），網路是 Live 的兩個與 secscan-live_ 開頭的。
    """
    volumes = set(run(["volume", "ls", "-q", "--filter", PROJECT_FILTER]).split())
    volumes |= {
        name
        for name in run(["volume", "ls", "-q"]).split()
        if name.startswith(LIVE_RESOURCE_PREFIXES)
    }
    return {
        "容器": run(["ps", "-aq", "--no-trunc", "--filter", PROJECT_FILTER]).split(),
        "volume": sorted(volumes),
        "網路": sorted(
            name
            for name in run(["network", "ls", "--format", "{{.Name}}"]).split()
            if name in LIVE_NETWORKS or name.startswith(f"{LIVE_PROJECT}_")
        ),
    }


def _counts(resources: Mapping[str, Sequence[str]]) -> dict[str, int]:
    return {kind: len(names) for kind, names in resources.items() if names}


# --------------------------------------------------------------------------- networks


@dataclass(frozen=True)
class NetworkSpec:
    name: str
    subnet: str
    ip_range: str


def run_id(secrets_dir: Path, base: Path | None = None) -> str:
    """這次執行的識別：拋棄式目錄的名稱。給定 base 時，目錄必須直接在 base 之下。"""
    path = os.path.normpath(secrets_dir)
    name = os.path.basename(path)
    if RUN_ID_PATTERN.fullmatch(name) is None:
        raise GuardError("拋棄式目錄的名稱不正確：無法確認這次執行的資源")
    if base is not None and os.path.dirname(path) != os.path.normpath(base):
        raise GuardError("拋棄式目錄不在這次的暫存目錄之下：無法確認這次執行的資源")
    return name


def claim_networks(run: Runner, specs: Sequence[NetworkSpec], owner: str) -> None:
    """建立 Live 的兩個網路並標記所有權（取代子 make 的 ensure-net；名稱只能是 Live 的兩個）。

    已存在就失敗：可能是另一次 Live 正在執行，不能共用、也不能在清理時刪除它的資源。
    """
    if sorted(spec.name for spec in specs) != sorted(LIVE_NETWORKS):
        raise GuardError("只能建立 Live 的兩個網路")
    for spec in specs:
        try:
            run(
                [
                    "network",
                    "create",
                    "--label",
                    f"{RUN_LABEL}={owner}",
                    "--internal",
                    "--opt",
                    f"{GATEWAY_OPTION}=isolated",
                    "--subnet",
                    spec.subnet,
                    "--ip-range",
                    spec.ip_range,
                    spec.name,
                ]
            )
        except GuardError:
            raise GuardError(
                f"無法建立網路 {spec.name}（已存在時：另一次 Live 正在執行，或上一次沒有清乾淨）"
            ) from None
        _check_network(run, spec, owner)


def _check_network(run: Runner, spec: NetworkSpec, owner: str) -> None:
    facts = run(["network", "inspect", "--format", NETWORK_FORMAT, spec.name]).strip().split("|")
    if len(facts) != len(("internal", "gateway", "ranges", "owner")):
        raise GuardError(f"無法確認網路 {spec.name} 的設定")
    internal, gateway, ranges, label = facts
    if internal != "true" or gateway != "isolated":
        raise GuardError(f"{spec.name} 不是 internal、gateway isolated 的網路")
    if ranges != f"{spec.subnet} {spec.ip_range}":
        raise GuardError(f"{spec.name} 的網段或 ip-range 不正確")
    if label != owner:
        raise GuardError(f"{spec.name} 不是這次執行建立的網路")


# --------------------------------------------------------------------------- cleanup


@dataclass
class CleanupReport:
    """清理的結果：失敗的步驟（只有步驟與名稱），以及沒有處理的、不屬於這次執行的資源。"""

    run: Runner
    failures: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def step(self, description: str, arguments: Sequence[str]) -> str | None:
        """執行一步；失敗時記錄步驟與原因（GuardError 的訊息只有子命令、結束碼與例外的類別）。"""
        try:
            return self.run(arguments)
        except GuardError as exc:
            self.failures.append(f"{description}（{exc}）")
            return None


def cleanup(
    run: Runner, base: Path, secrets_dir: str, *, engine_id: str, claimed: bool
) -> CleanupReport:
    """只清理確認屬於這次執行的資源；不屬於的不碰（M2：清理段不得使用未經驗證的外部變數）。

    claimed 是 recipe 記錄的所有權：networks 成功（兩個網路都以這次的識別建立並確認）之後才是 True。
    """
    report = CleanupReport(run)
    if not secrets_dir:
        if claimed:
            report.failures.append("記錄了所有權卻沒有拋棄式目錄：沒有清理任何東西")
        return report
    try:
        owner = run_id(Path(secrets_dir), base)
    except GuardError as exc:
        report.failures.append(f"{exc}：沒有清理任何東西")
        return report
    if _same_engine(report, engine_id, ENGINE_AT_START):
        _remove_docker_resources(report, owner, claimed=claimed, engine_id=engine_id)
    _remove_directory(report, Path(secrets_dir))
    if os.path.lexists(secrets_dir):
        report.failures.append("清理之後拋棄式目錄還在")
    return report


def _same_engine(report: CleanupReport, engine_id: str, stage: str) -> bool:
    """安全 LOW-1：確認 Engine 和開始時相同；不同或無法確認時不再碰任何 Docker 資源。

    stage 說明到這個時間點為止做了什麼（安全審查第三次的 INFO-1：人工清理時判斷用）。
    """
    try:
        engine(os.environ, report.run, engine_id)
    except GuardError as exc:
        report.failures.append(f"{exc}（{stage}）")
        return False
    return True


def _remove_docker_resources(
    report: CleanupReport, owner: str, *, claimed: bool, engine_id: str
) -> None:
    owned = _owned_networks(report, owner)
    if claimed and owned != LIVE_NETWORKS:
        # 安全 LOW-1：網路不見、被換掉或無法確認（外部變更）；stack 可能還在、也可能是別人的：
        # fail closed，不刪任何 Docker 資源（第二輪程式碼 LOW-1：仍屬於這次的網路上的容器也不刪）。
        report.failures.append(
            "這次建立的網路不見了、不再屬於這次執行或無法確認（外部變更）：沒有刪除任何 Docker 資源"
        )
    elif claimed:
        for container in _candidates(report, owned):
            report.step(f"刪除容器 {container[:12]}", ["rm", "-f", "-v", container])
        # 安全 INFO-1：down 的範圍最大，執行之前再確認一次 Engine（不同就不再碰任何資源）。
        if not _same_engine(report, engine_id, ENGINE_BEFORE_DOWN):
            return
        _compose_down(report)
        _remove_networks(report, owned)
    else:
        # 安全審查第三次的 LOW-1：沒有取得所有權的執行（networks 沒有成功）沒有啟動任何容器；
        # 網路上的容器都不是它的：不刪容器、不 down，只刪沒有任何容器的自己的網路。
        _remove_networks(report, owned)
    _check_residue(report, owner, claimed=claimed)


def _owned_networks(report: CleanupReport, owner: str) -> frozenset[str]:
    listing = report.step("列出網路", ["network", "ls", "--format", "{{.Name}}"])
    owned = set()
    for name in sorted(LIVE_NETWORKS & set((listing or "").split())):
        label = report.step(
            f"確認網路 {name} 的所有權",
            ["network", "inspect", "--format", NETWORK_LABEL_FORMAT, name],
        )
        if label is not None and label.strip() == owner:
            owned.add(name)
        elif label is not None:
            report.skipped.append(f"網路 {name}（不是這次執行建立的）")
    return frozenset(owned)


def _candidates(report: CleanupReport, owned: frozenset[str]) -> list[str]:
    """這次執行的網路上、確認屬於這次執行的容器（測試的接收端、探針、孤兒的掃描容器、guard）。

    第二輪 HIGH：以完整的 ID 去重並依 ID 排序，每個容器只刪除一次（guard 同時接在兩個網路上，兩次
    列出的是同一個 ID；同一個 ID 交給 docker rm 兩次，第二個請求可能衝突而讓清理失敗）。格式不正確的
    ID、其他 compose 專案的容器、也接在不屬於這次執行的網路上的容器都不刪除。
    """
    found: set[str] = set()
    for name in sorted(owned):
        listing = report.step(f"列出網路 {name} 上的容器", [*_ON_NETWORK, f"network={name}"])
        listed = (listing or "").split()
        malformed = [item for item in listed if CONTAINER_ID.fullmatch(item) is None]
        if malformed:
            report.failures.append(
                f"網路 {name} 上有格式不正確的容器 ID（{len(malformed)} 個）：沒有刪除"
            )
        found.update(item for item in listed if CONTAINER_ID.fullmatch(item))
    return [container for container in sorted(found) if _belongs(report, container, owned)]


def _belongs(report: CleanupReport, container: str, owned: frozenset[str]) -> bool:
    """容器屬於這次執行：inspect 回報同一個完整 ID、專案恰好是 Live 或沒有標記（精確比對）、接的
    網路全部是這次執行的網路（安全審查第二輪 LOW-2 (c)、INFO-2）。"""
    facts = report.step(
        f"確認容器 {container[:12]} 的專案與網路",
        ["inspect", "--type", "container", "--format", CONTAINER_FORMAT, container],
    )
    if facts is None:
        return False
    parts = facts.strip().split("|")
    if len(parts) != len(("id", "project", "networks")) or parts[0] != container:
        report.failures.append(f"無法確認容器 {container[:12]}：沒有刪除")
        return False
    project, attached = _label(parts[1]), set(parts[2].split())
    if project not in ("", LIVE_PROJECT):
        report.failures.append(f"Live 網路上有其他 compose 專案的容器 {container[:12]}：沒有刪除")
        return False
    if not attached or not attached <= owned:
        report.failures.append(f"容器 {container[:12]} 接在不屬於這次執行的網路上：沒有刪除")
        return False
    return True


def _label(encoded: str) -> str | None:
    """JSON 編碼的標記值；沒有標記是 ""（實測，docker 29.4）或 null（沒有 Labels 時的推論）。

    標記的值一定是字串，所以 null 只可能是沒有標記（安全審查第三次的 MEDIUM-1）。其他不是 JSON
    字串的值是 None：當成其他專案，不刪除。
    """
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return None
    if value is None:
        return ""
    return value if isinstance(value, str) else None


def _remove_networks(report: CleanupReport, owned: frozenset[str]) -> None:
    """網路確認沒有任何容器（含沒有刪除的）之後才刪除：留著的網路讓下一次的 preflight 拒絕。"""
    for name in sorted(owned):
        listing = report.step(f"確認網路 {name} 上沒有容器", [*_ON_NETWORK, f"network={name}"])
        if listing is None:
            continue
        if listing.split():
            report.failures.append(
                f"網路 {name} 上還有容器（{len(listing.split())} 個）：沒有刪除網路"
            )
            continue
        report.step(f"刪除網路 {name}", ["network", "rm", name])


def _compose_down(report: CleanupReport) -> None:
    """down -v 之前核對：專案名稱、解析出來的 volume 與網路、既有的 volume 都是 Live 的名稱。"""
    resolved = report.step(
        "解析 Live 的 compose 設定", [*LIVE_COMPOSE, "config", "--format", "json"]
    )
    existing = report.step(
        "列出 Live 專案的 volume",
        ["volume", "ls", "-q", "--filter", f"label={PROJECT_LABEL}={LIVE_PROJECT}"],
    )
    if resolved is None or existing is None:
        report.failures.append("無法核對 down -v 的對象：沒有執行 compose down")
        return
    try:
        problems = _down_problems(_json(resolved))
    except GuardError:
        problems = ["設定不是 JSON"]
    problems += [
        f"volume {name}" for name in existing.split() if not name.startswith(LIVE_RESOURCE_PREFIXES)
    ]
    if problems:
        report.failures.append(f"down -v 的對象不只 Live 的資源（{'、'.join(problems)}）：沒有執行")
        return
    report.step("compose down -v", [*LIVE_COMPOSE, "down", "-v", "--remove-orphans"])


def _down_problems(config: Mapping[str, Any]) -> list[str]:
    """down -v 的對象不是 Live 的資源（只有名稱）。形狀不是預期的 mapping 也算問題：不以例外中斷
    清理（安全審查第二輪 LOW-1）。"""
    problems = [] if config.get("name") == LIVE_PROJECT else ["專案名稱"]
    for kind in ("volumes", "networks"):
        entries = config.get(kind) or {}
        if not isinstance(entries, Mapping) or not all(
            isinstance(entry, Mapping) for entry in entries.values()
        ):
            problems.append(f"{kind} 的形狀不正確")
            continue
        for key, entry in entries.items():
            name = str(entry.get("name", f"{LIVE_PROJECT}_{key}"))
            if kind == "volumes":
                live = not entry.get("external") and name.startswith(LIVE_RESOURCE_PREFIXES)
            else:
                live = name in LIVE_NETWORKS or name.startswith(f"{LIVE_PROJECT}_")
            if not live:
                problems.append(f"{'volume' if kind == 'volumes' else '網路'} {name}")
    return problems


def _remove_directory(report: CleanupReport, path: Path) -> None:
    """拋棄式目錄：自己擁有的目錄（不是 symlink）才刪除。"""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        report.failures.append(f"無法確認拋棄式目錄（{type(exc).__name__}）：沒有刪除")
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        report.failures.append("拋棄式目錄不是自己擁有的目錄：沒有刪除")
        return
    try:
        shutil.rmtree(path)
    except OSError as exc:
        report.failures.append(f"無法刪除拋棄式目錄（{exc.strerror or type(exc).__name__}）")


def _check_residue(report: CleanupReport, owner: str, *, claimed: bool) -> None:
    """清理之後以和 preflight 相同的條件確認沒有殘留（安全 LOW-1：網路不存在也檢查容器與 volume）。

    這次沒有取得所有權、剩下的資源由另一次 Live 執行持有（它的網路）時，只記錄、不算失敗：那是正在
    執行的另一次 Live，這次沒有建立任何 compose 的資源。
    """
    try:
        remaining = live_resources(report.run)
    except GuardError:
        report.failures.append("無法確認清理之後沒有殘留")
        return
    counts = _counts(remaining)
    if not counts:
        return
    holder = None if claimed else _holder(report, owner, remaining["網路"])
    if holder is not None:
        report.skipped.append(f"另一次 Live 執行（{holder}）持有的資源 {counts}")
        return
    report.failures.append(f"清理之後還有 Live 的資源：{counts}")


def _holder(report: CleanupReport, owner: str, networks: Sequence[str]) -> str | None:
    """持有 Live 網路的另一次執行：存在的 Live 網路都標記同一個、不是這次的執行識別。"""
    labels = set()
    for name in sorted(set(networks) & LIVE_NETWORKS):
        label = report.step(
            f"確認網路 {name} 的所有權",
            ["network", "inspect", "--format", NETWORK_LABEL_FORMAT, name],
        )
        labels.add((label or "").strip())
    if len(labels) != 1:
        return None
    [label] = labels
    if label == owner or RUN_ID_PATTERN.fullmatch(label) is None:
        return None
    return label


def write_diagnostic(base: Path, secrets_dir: str, failures: Sequence[str]) -> Path:
    """清理失敗的診斷檔（0600，只有步驟與名稱）：下一次的 preflight 看到它就拒絕執行。"""
    descriptor, name = tempfile.mkstemp(prefix=DIAGNOSTIC_PREFIX, suffix=".txt", dir=base)
    lines = [
        f"時間：{datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"拋棄式目錄：{os.path.basename(os.path.normpath(secrets_dir)) or '（沒有）'}",
        "失敗的步驟：",
        *(f"- {failure}" for failure in failures),
    ]
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")
    return Path(name)


# --------------------------------------------------------------------------- snapshot


def snapshot(root: Path, run: Runner) -> dict[str, Any]:
    """開發環境的快照：只有名稱、ID、時間與檔案的中繼資料（sha256 不是內容）。"""
    containers = []
    for container_id in run(
        ["ps", "-aq", "--filter", f"label=com.docker.compose.project={DEV_PROJECT}"]
    ).split():
        containers.append(
            run(
                ["inspect", "--format", "{{.Name}} {{.Id}} {{.State.StartedAt}}", container_id]
            ).strip()
        )
    volumes = []
    for name in run(["volume", "ls", "-q"]).split():
        if name.startswith(f"{DEV_PROJECT}_") and not name.startswith("secscan_live_"):
            volumes.append(
                run(["volume", "inspect", "--format", "{{.Name}} {{.CreatedAt}}", name]).strip()
            )
    # Live 的網路（secscan_live_*）不是開發環境：殘留由 cleanup 的殘留檢查回報
    # （程式碼審查 MEDIUM-2）。
    networks = sorted(
        line
        for line in run(
            ["network", "ls", "--no-trunc", "--format", "{{.Name}} {{.ID}}"]
        ).splitlines()
        if line.split(" ", 1)[0] in DEV_NETWORKS
        or (line.startswith(f"{DEV_PROJECT}_") and not line.startswith(LIVE_RESOURCE_PREFIXES))
    )
    return {
        "containers": sorted(containers),
        "volumes": sorted(volumes),
        "networks": networks,
        "files": _file_facts(root),
    }


def _file_facts(root: Path) -> dict[str, str]:
    facts: dict[str, str] = {}
    paths = [root / ".env"]
    secrets_dir = root / "secrets"
    if secrets_dir.is_dir() and not secrets_dir.is_symlink():
        paths.extend(sorted(secrets_dir.iterdir()))
    for path in paths:
        key = path.relative_to(root).as_posix()
        try:
            info = path.lstat()
        except FileNotFoundError:
            facts[key] = "absent"
            continue
        digest = (
            hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else "-"
        )
        facts[key] = f"{stat.S_IMODE(info.st_mode):o} {info.st_size} {info.st_ino} {digest}"
    return facts


def compare(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    """不同的類別與名稱（不含值）。"""
    differences = []
    for kind in ("containers", "volumes", "networks"):
        if before.get(kind) != after.get(kind):
            differences.append(kind)
    files_before, files_after = before.get("files", {}), after.get("files", {})
    for name in sorted(set(files_before) | set(files_after)):
        if files_before.get(name) != files_after.get(name):
            differences.append(f"files:{name}")
    return differences


# --------------------------------------------------------------------------- compose config


def _repo_compose(root: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
    return loaded


def check_config(config: Mapping[str, Any], secrets_dir: Path, root: Path) -> None:
    if config.get("name") != LIVE_PROJECT:
        raise GuardError(f"compose 專案不是 {LIVE_PROJECT}")
    for key in ("configs", "include"):
        if key in config:
            raise GuardError(f"不允許頂層的 {key}")
    repo = _repo_compose(root)["services"]
    services: Mapping[str, Any] = config.get("services", {})
    _check_secrets(config.get("secrets", {}), secrets_dir, _referenced(services))
    for name, service in services.items():
        if name not in repo:
            raise GuardError(f"不認得的服務：{name}")
        _check_service(name, service, repo[name], root)


def _source(entry: object) -> str:
    return str(entry["source"]) if isinstance(entry, Mapping) else str(entry)


def _referenced(services: Mapping[str, Any]) -> set[str]:
    return {_source(entry) for service in services.values() for entry in service.get("secrets", [])}


def _check_secrets(secrets: Mapping[str, Any], secrets_dir: Path, referenced: set[str]) -> None:
    """頂層的 secret 都是七個之一（profile 之外的服務用的不會出現），而且涵蓋服務引用的每一個。"""
    if not set(secrets) <= SECRET_FILE_NAMES or not referenced <= set(secrets):
        raise GuardError("頂層的 secrets 不是預期的名稱")
    expected_dir = os.path.normpath(secrets_dir)
    for name, entry in secrets.items():
        if not set(entry) <= {"file", "name"} or "file" not in entry:
            raise GuardError(f"secret {name} 只能有 file 與 name")
        path = os.path.normpath(entry["file"])
        if os.path.dirname(path) != expected_dir or os.path.basename(path) != name:
            raise GuardError(f"secret {name} 不在這次的拋棄式目錄之下")
        _check_secret_file(Path(path), name)


def _check_secret_file(path: Path, name: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise GuardError(f"secret {name} 的檔案不存在") from None
    if not stat.S_ISREG(info.st_mode):
        raise GuardError(f"secret {name} 不是一般檔案")
    if stat.S_IMODE(info.st_mode) != FILE_MODE or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise GuardError(f"secret {name} 的權限、擁有者或連結數不正確")


def _check_service(
    name: str, service: Mapping[str, Any], repo: Mapping[str, Any], root: Path
) -> None:
    for key in ("env_file", "configs"):
        if key in service:
            raise GuardError(f"服務 {name} 不允許 {key}")
    environment = set(service.get("environment") or {})
    allowed = set(repo.get("environment") or {})
    extra = environment - allowed
    if extra:
        raise GuardError(f"服務 {name} 有不在 compose.yaml 中的環境變數（{len(extra)} 個）")
    if environment & SECRET_ENV_NAMES - {key for key in allowed if key.endswith("_FILE")}:
        raise GuardError(f"服務 {name} 的環境變數有秘密的名稱")
    mounted = {
        entry["source"] if isinstance(entry, Mapping) else entry
        for entry in service.get("secrets", [])
    }
    if mounted != set(repo.get("secrets", [])):
        raise GuardError(f"服務 {name} 掛載的 secrets 和 compose.yaml 不同")
    for volume in service.get("volumes", []):
        if volume.get("type") == "bind":
            _check_bind(name, volume, root)


def _check_bind(name: str, volume: Mapping[str, Any], root: Path) -> None:
    source = os.path.normpath(str(volume.get("source", "")))
    allowed = {
        os.path.normpath(root / relative): target
        for relative, target in ALLOWED_BINDS.get(name, {}).items()
    }
    if allowed.get(source) != volume.get("target") or not volume.get("read_only"):
        raise GuardError(f"服務 {name} 有不允許的 bind 掛載")


def check_unresolved(config: Mapping[str, Any]) -> None:
    for name, service in config.get("services", {}).items():
        if "env_file" in service:
            raise GuardError(f"服務 {name} 有 env_file")
    if "include" in config:
        raise GuardError("不允許 include")


def check_environment(listing: str, allowed: Iterable[str]) -> None:
    names = {line.split("=", 1)[0] for line in listing.splitlines() if "=" in line}
    refused = names & (SECRET_ENV_NAMES | ALWAYS_REFUSED)
    if refused:
        raise GuardError(f"compose 的環境有不允許的變數：{sorted(refused)}")
    unknown = names - set(allowed) - COMPOSE_ADDED - PLATFORM_ADDED
    if unknown:
        raise GuardError(f"compose 的環境有不在允許清單的變數：{sorted(unknown)}")


def check_images(run: Runner, app_image: str, guard_image: str) -> None:
    expected = dict.fromkeys(APP_SERVICES, app_image) | {"guard": guard_image}
    seen = set()
    for container_id in run(["ps", "-aq", "--filter", PROJECT_FILTER]).split():
        service, image = run(["inspect", "--format", IMAGE_FORMAT, container_id]).split()
        if service in expected:
            seen.add(service)
            if image != expected[service]:
                raise GuardError(f"服務 {service} 的映像不是 build 之後記錄的映像")
    missing = (APP_SERVICES - {"runs-init"} | {"guard"}) - seen
    if missing:
        raise GuardError(f"找不到這些服務的容器：{sorted(missing)}")


# --------------------------------------------------------------------------- CLI


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="env_guard")
    commands = parser.add_subparsers(dest="command", required=True)
    engine_parser = commands.add_parser("engine")
    engine_parser.add_argument("--expect")
    commands.add_parser("preflight").add_argument("--base", type=Path, required=True)
    for name in ("snapshot", "compare"):
        commands.add_parser(name).add_argument("--root", type=Path, required=True)
    config_parser = commands.add_parser("check-config")
    config_parser.add_argument("--secrets-dir", type=Path, required=True)
    config_parser.add_argument("--root", type=Path, required=True)
    commands.add_parser("check-unresolved")
    commands.add_parser("check-environment").add_argument("--allow", nargs="*", default=[])
    images = commands.add_parser("check-images")
    images.add_argument("--app-image", required=True)
    images.add_argument("--guard-image", required=True)
    networks = commands.add_parser("networks")
    networks.add_argument("--secrets-dir", type=Path, required=True)
    networks.add_argument(
        "--network", nargs=3, action="append", required=True, metavar=("NAME", "SUBNET", "RANGE")
    )
    cleanup_parser = commands.add_parser("cleanup")
    cleanup_parser.add_argument("--base", type=Path, required=True)
    cleanup_parser.add_argument("--secrets-dir", required=True)
    cleanup_parser.add_argument("--engine", required=True)
    cleanup_parser.add_argument("--claimed", action="store_true")
    return parser


def _json(text: str) -> dict[str, Any]:
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        raise GuardError("輸入不是 JSON（compose 失敗？）") from None
    if not isinstance(loaded, dict):
        raise GuardError("輸入不是 JSON 物件")
    return loaded


def run_command(args: argparse.Namespace, stdin: str, run: Runner) -> str:
    """執行一個子命令，回傳要印出的文字（只有名稱、ID 或 JSON 快照）。"""
    command = args.command
    if command == "engine":
        return engine(os.environ, run, args.expect)
    if command == "preflight":
        preflight(args.base, run)
        return "preflight ok"
    if command == "snapshot":
        return json.dumps(snapshot(args.root, run), sort_keys=True)
    if command == "compare":
        differences = compare(_json(stdin), snapshot(args.root, run))
        if differences:
            raise GuardError(f"開發環境的快照前後不同：{differences}")
        return "開發環境的快照前後相同"
    if command == "check-config":
        check_config(_json(stdin), args.secrets_dir, args.root)
    elif command == "check-unresolved":
        check_unresolved(_json(stdin))
    elif command == "check-environment":
        check_environment(stdin, args.allow)
    elif command == "networks":
        specs = [NetworkSpec(*item) for item in args.network]
        claim_networks(run, specs, run_id(args.secrets_dir))
    elif command == "cleanup":
        report = cleanup(
            run, args.base, args.secrets_dir, engine_id=args.engine, claimed=args.claimed
        )
        return _cleanup_result(report, args.base, args.secrets_dir)
    else:
        check_images(run, args.app_image, args.guard_image)
    return f"{command} ok"


def _cleanup_result(report: CleanupReport, base: Path, secrets_dir: str) -> str:
    skipped = f"；沒有處理（不屬於這次執行）：{'、'.join(report.skipped)}" if report.skipped else ""
    if not report.failures:
        return f"cleanup ok{skipped}"
    try:
        where = f"診斷檔：{write_diagnostic(base, secrets_dir, report.failures)}"
    except OSError as exc:
        where = f"無法寫入診斷檔（{exc.strerror or type(exc).__name__}）"
    raise GuardError(
        f"清理沒有完成（{len(report.failures)} 項：{'；'.join(report.failures)}）{skipped}；{where}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    # 只有讀取 compose 輸出或快照的子命令讀 stdin（其他子命令不讀，避免等待終端的輸入）。
    stdin = sys.stdin.read() if args.command in _READS_STDIN else ""
    try:
        output = run_command(args, stdin, docker)
    except GuardError as exc:
        sys.stderr.write(f"env_guard {args.command}：{exc}\n")
        return EXIT_FAILURE
    except OSError as exc:
        # 讀檔、建目錄等失敗：只輸出例外的類別（不輸出 traceback 與路徑以外的內容）。
        sys.stderr.write(f"env_guard {args.command}：無法存取檔案（{type(exc).__name__}）\n")
        return EXIT_FAILURE
    except KeyboardInterrupt:
        # 安全 INFO-4：清理被中斷（例如第二次 Ctrl-C）也留下診斷檔，下一次的 preflight 拒絕執行。
        sys.stderr.write(f"env_guard {args.command}：被中斷\n")
        if args.command == "cleanup":
            _record_interruption(args.base, args.secrets_dir, "清理被中斷")
        return EXIT_FAILURE
    except Exception as exc:
        # 安全審查第三次的 INFO-2：程式本身的錯誤照樣以 traceback 結束（重新 raise），但清理先留下
        # 診斷檔（不吞掉錯誤：BLE 只允許重新 raise 的 handler）。
        if args.command == "cleanup":
            reason = f"清理發生未預期的錯誤（{type(exc).__name__}）"
            _record_interruption(args.base, args.secrets_dir, reason)
        raise
    sys.stdout.write(f"{output}\n")
    return EXIT_OK


def _record_interruption(base: Path, secrets_dir: str, reason: str) -> None:
    try:
        where = write_diagnostic(base, secrets_dir, [f"{reason}：沒有完成，殘留由人工確認"])
    except OSError as exc:
        sys.stderr.write(f"無法寫入診斷檔（{type(exc).__name__}）\n")
        return
    sys.stderr.write(f"診斷檔：{where}\n")


if __name__ == "__main__":
    sys.exit(main())
