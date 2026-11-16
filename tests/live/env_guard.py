"""Live 的隔離檢查（T23b-b2；docs/DECISIONS.md §32；計畫 §3.1、§3.1.1）。

make test-live-runner 在白名單的環境（LIVE_PROC_ENV：env -i 加上允許的變數）中，以
`uv run --locked python -I tests/live/env_guard.py <子命令>` 執行；recipe 只負責串接，判斷都在這裡。
只輸出名稱與數量，不輸出任何值（設定、秘密、.env 的內容都不印出）。

子命令：
- engine [--expect ID]：DOCKER_HOST 只能是本機的 unix socket；context 是 orbstack；compose 是
  驗證過的主版本；印出 Engine ID，給定 --expect 時必須相同（開始時、up 之前、結束時各確認一次）。
- preflight --base DIR：拒絕已存在的 secscan-live 資源與舊的拋棄式目錄（上一次沒有清乾淨）。
- snapshot --root DIR／compare --root DIR：開發環境的快照（容器的名稱、ID、StartedAt；volume 的
  名稱、CreatedAt；網路；.env 與 secrets/* 的 mode、size、inode、sha256），compare 從 stdin 讀開始
  時的快照。
- check-config --secrets-dir DIR --root DIR：stdin 是 `config --format json`。頂層 secret 只有
  {file, name}，檔案都在這次的拋棄式目錄之下、是 0600 的一般檔案、擁有者是自己、只有一個連結；
  各服務的 environment 鍵與 secrets 不超過 repo 的 compose.yaml；沒有 configs、include；bind 的來源
  只允許 db 的 initdb 目錄與 wrapper。
- check-unresolved：stdin 是 `config --no-env-resolution --format json`：沒有任何服務有 env_file。
- check-environment --allow NAME...：stdin 是 `config --environment`：變數名稱是精確的允許清單
  （recipe 傳入的名稱，加上 compose 自己加上的幾個），秘密的名稱與 COMPOSE_ENV_FILES 一律拒絕。
- check-images --app-image ID --guard-image ID：Live 容器的映像等於 build 之後記錄的映像 ID。
- networks --network NAME SUBNET IP_RANGE（兩次）：建立並檢查 Live 的兩個網路（internal、gateway
  isolated、固定的網段）。取代子 make 的 ensure-net：Live 的 recipe 不呼叫 $(MAKE)（安全審查 H1：
  含 $(MAKE) 的行在 make -n、-q、-t 下仍會執行）。

只用標準函式庫、yaml 與 secscan.cli.secret_files（以 -I 執行，不 import tests 與工作目錄的模組）。
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
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
NETWORK_FORMAT = (
    f'{{{{.Internal}}}}|{{{{index .Options "{GATEWAY_OPTION}"}}}}|'
    "{{range .IPAM.Config}}{{.Subnet}} {{.IPRange}}{{end}}"
)
PROJECT_PATTERN = re.compile(r"secscan-live[a-z0-9-]*")
EXIT_OK = 0
EXIT_FAILURE = 1

type Runner = Callable[[Sequence[str]], str]
_READS_STDIN = frozenset({"compare", "check-config", "check-unresolved", "check-environment"})


class GuardError(Exception):
    """隔離檢查不通過；訊息只有名稱與數量。"""


def docker(arguments: Sequence[str]) -> str:
    """固定的 docker 指令（白名單的環境）；失敗視為無法確認。"""
    # 參數由這個模組組成，沒有外部輸入；docker 從 PATH 找到（白名單保留 PATH）。
    result = subprocess.run(  # noqa: S603
        ["docker", *arguments],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise GuardError(f"docker {arguments[0]} 失敗：無法確認，停止")
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
    label = f"label=com.docker.compose.project={LIVE_PROJECT}"
    found = {
        "容器": run(["ps", "-aq", "--filter", label]).split(),
        "volume": run(["volume", "ls", "-q", "--filter", label]).split(),
        "網路": [
            name
            for name in run(["network", "ls", "--format", "{{.Name}}"]).split()
            if name in LIVE_NETWORKS or name.startswith(f"{LIVE_PROJECT}_")
        ],
    }
    remaining = {kind: len(names) for kind, names in found.items() if names}
    if remaining:
        raise GuardError(f"已有 {LIVE_PROJECT} 的資源：{remaining}；先清除再執行")


# --------------------------------------------------------------------------- networks


@dataclass(frozen=True)
class NetworkSpec:
    name: str
    subnet: str
    ip_range: str


def ensure_networks(run: Runner, specs: Sequence[NetworkSpec]) -> None:
    """Live 的兩個網路（取代子 make 的 ensure-net；名稱只能是 Live 的兩個）。"""
    if sorted(spec.name for spec in specs) != sorted(LIVE_NETWORKS):
        raise GuardError("只能建立 Live 的兩個網路")
    existing = set(run(["network", "ls", "--format", "{{.Name}}"]).split())
    for spec in specs:
        if spec.name not in existing:
            run(
                [
                    "network",
                    "create",
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
        _check_network(run, spec)


def _check_network(run: Runner, spec: NetworkSpec) -> None:
    facts = run(["network", "inspect", "--format", NETWORK_FORMAT, spec.name]).strip().split("|")
    if len(facts) != len(("internal", "gateway", "ranges")):
        raise GuardError(f"無法確認網路 {spec.name} 的設定")
    internal, gateway, ranges = facts
    if internal != "true" or gateway != "isolated":
        raise GuardError(f"{spec.name} 不是 internal、gateway isolated 的網路")
    if ranges != f"{spec.subnet} {spec.ip_range}":
        raise GuardError(f"{spec.name} 的網段或 ip-range 不正確")


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
    networks = sorted(
        line
        for line in run(
            ["network", "ls", "--no-trunc", "--format", "{{.Name}} {{.ID}}"]
        ).splitlines()
        if line.split(" ", 1)[0] in DEV_NETWORKS or line.startswith(f"{DEV_PROJECT}_")
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
    label = f"label=com.docker.compose.project={LIVE_PROJECT}"
    expected = dict.fromkeys(APP_SERVICES, app_image) | {"guard": guard_image}
    seen = set()
    for container_id in run(["ps", "-aq", "--filter", label]).split():
        service, image = run(["inspect", "--format", IMAGE_FORMAT, container_id]).split()
        if service in expected:
            seen.add(service)
            if image != expected[service]:
                raise GuardError(f"服務 {service} 的映像不是 build 之後記錄的映像")
    missing = (APP_SERVICES - {"runs-init"} | {"guard"}) - seen
    if missing:
        raise GuardError(f"找不到這些服務的容器：{sorted(missing)}")


# --------------------------------------------------------------------------- Live 的 pytest


def live_session_problems(environ: Mapping[str, str]) -> list[str]:
    """Live 的 pytest 開始時的環境（tests/live/conftest.py 的 pytest_sessionstart；R1、修正 17）。

    回傳有問題的變數名稱（不含值）：專案必須是 secscan-live（shell 中殘留的 secscan 會讓測試操作
    開發的專案）；拋棄式目錄必須是 mktemp 建立的那一個；環境中不得有任何秘密的名稱。
    """
    problems = []
    if PROJECT_PATTERN.fullmatch(environ.get("SECSCAN_LIVE_PROJECT", "")) is None:
        problems.append("SECSCAN_LIVE_PROJECT")
    secrets_dir = environ.get("SECSCAN_LIVE_SECRETS_DIR", "")
    if not os.path.basename(os.path.normpath(secrets_dir)).startswith(SECRETS_PREFIX):
        problems.append("SECSCAN_LIVE_SECRETS_DIR")
    problems.extend(sorted(name for name in environ if name in SECRET_ENV_NAMES))
    return problems


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
    commands.add_parser("networks").add_argument(
        "--network", nargs=3, action="append", required=True, metavar=("NAME", "SUBNET", "RANGE")
    )
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
        ensure_networks(run, [NetworkSpec(*item) for item in args.network])
    else:
        check_images(run, args.app_image, args.guard_image)
    return f"{command} ok"


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    # 只有讀取 compose 輸出或快照的子命令讀 stdin（其他子命令不讀，避免等待終端的輸入）。
    stdin = sys.stdin.read() if args.command in _READS_STDIN else ""
    try:
        output = run_command(args, stdin, docker)
    except GuardError as exc:
        sys.stderr.write(f"env_guard {args.command}：{exc}\n")
        return EXIT_FAILURE
    sys.stdout.write(f"{output}\n")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
