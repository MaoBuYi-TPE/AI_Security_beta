"""tests/live/env_guard.py 的清理測試共用的有狀態 docker 替身與 helper（不連 daemon）。

替身的狀態：網路（名稱、所有權的標記、Network ID）、容器（完整的 ID、專案、接的網路的名稱與 Network
ID、是否停止）、volume（名稱與專案標記）、compose 建立的網路、Engine ID。替身的規則：

- docker rm 收到重複的 ID（同一次呼叫中重複，或之前已經刪除過）時失敗：同一次呼叫的衝突是審查者依
  docker CLI 與 daemon 的原始碼推論的行為，沒有以真的 Docker 驗證；「之前已經刪除過」比真的
  `rm -f`（忽略不存在的 ID）嚴格，所以同一個容器被刪兩次（不論是否在同一次呼叫）一定測得出來；
- inspect 以 JSON 回報專案標記（沒有標記是 ""），接的網路以「名稱=Network ID」回報；
- network inspect、network rm 以完整的 ID 優先、再以名稱解析（和 daemon 相同；實測以 ID 解析）；
  network inspect 以 JSON 回報標記；同名、同標記、被換掉的網路是另一個 ID（G1c）；
- ps 的 network= 比對容器設定中的網路名稱，或 Network ID 的前綴（和 daemon 的 filter 相同；以名稱
  比對已不存在的網路是依原始碼的推論）；不帶 -a 時不列出停止的容器；
- 網路上還有容器（含停止的）時 network rm 失敗；
- compose down 刪除 secscan-live 專案的容器、volume 與 compose 建立的網路（不刪 external 的網路）。
"""

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from tests.live import env_guard
from tests.live.env_guard import CleanupReport, GuardError, cleanup

OWNER = "secscan-live-secrets.Abc123"
OTHER = "secscan-live-secrets.Other1"
ENGINE = "engine-1"
LIVE = "secscan-live"
SCAN = "secscan_live_scan_net"
LAB = "secscan_live_lab_net"
COMPOSE_NETWORKS = ("secscan-live_default", "secscan-live_control_net", "secscan-live_docker_net")
LIVE_CONFIG = {
    "name": LIVE,
    "volumes": {
        "db_data": {"name": "secscan-live_db_data"},
        "runs": {"name": "secscan_live_runs"},
    },
    "networks": {
        "scan_net": {"name": SCAN, "external": True},
        "default": {"name": "secscan-live_default"},
    },
}


def cid(name: str) -> str:
    """完整的容器 ID（64 個十六進位字元）。"""
    return hashlib.sha256(name.encode()).hexdigest()


def nid(name: str, owner: str = OWNER, generation: int = 0) -> str:
    """完整的 Network ID：同名、同標記、不同代（被換掉的網路）的 ID 不同。"""
    return hashlib.sha256(f"network:{name}:{owner}:{generation}".encode()).hexdigest()


# 這次執行建立的兩個網路（所有權紀錄的預設內容）。
OURS = {SCAN: nid(SCAN), LAB: nid(LAB)}
GUARD = cid("guard")
RECEIVER = cid("receiver")
ORPHAN = cid("orphan-scan")


def container(
    name: str,
    *networks: str,
    project: str = LIVE,
    stopped: bool = False,
    attached: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """attached：接的網路的名稱與 Network ID（預設是替身中同名網路目前的 ID）。"""
    item = {"id": cid(name), "project": project, "networks": list(networks), "stopped": stopped}
    return item if attached is None else {**item, "attached": dict(attached)}


def stack() -> list[dict[str, Any]]:
    """Live 的 stack：guard 同時接在兩個 Live 網路上，其他服務只接 compose 建立的網路。"""
    return [
        container("api", "secscan-live_default", "secscan-live_control_net"),
        container("db", "secscan-live_default", "secscan-live_control_net"),
        container("runner", "secscan-live_control_net", "secscan-live_docker_net"),
        container("worker", "secscan-live_control_net"),
        container("socket-proxy", "secscan-live_docker_net"),
        container("guard", SCAN, LAB),
    ]


def probes() -> list[dict[str, Any]]:
    """測試在 Live 網路上建立的容器：接收端（lab_net）與停止的孤兒掃描容器（scan_net）。"""
    return [
        container("receiver", LAB, project=""),
        container("orphan-scan", SCAN, project="", stopped=True),
    ]


class CleanupDocker:
    """有狀態的 docker 替身（規則見模組的 docstring）。

    networks：名稱 → 所有權的標記（"" 是沒有標記）；network_ids 覆寫 Network ID（預設是
    nid(名稱, 標記)）。
    fail 列出的動作回傳失敗：例如 "compose down"、"compose config"、"network rm"、"volume ls"、
    "ps"、"inspect"、"info"，或 "rm <ID>"。
    """

    def __init__(
        self,
        *,
        networks: dict[str, str] | None = None,
        network_ids: dict[str, str] | None = None,
        containers: Iterable[dict[str, Any]] | None = None,
        volumes: dict[str, str] | None = None,
        compose_networks: Iterable[str] = COMPOSE_NETWORKS,
        config: object = None,
        fail: Iterable[str] = (),
        engine_id: str = ENGINE,
        listings: dict[str, str] | None = None,
        facts: dict[str, str] | None = None,
    ) -> None:
        self.networks = (
            dict.fromkeys(env_guard.LIVE_NETWORKS, OWNER) if networks is None else dict(networks)
        )
        self.network_ids = {name: nid(name, label) for name, label in self.networks.items()}
        self.network_ids.update(network_ids or {})
        chosen = [*stack(), *probes()] if containers is None else containers
        self.containers = [self._attach(dict(item)) for item in chosen]
        self.volumes = (
            {"secscan-live_db_data": LIVE, "secscan_live_runs": LIVE}
            if volumes is None
            else dict(volumes)
        )
        self.compose_networks = list(compose_networks)
        self.config = LIVE_CONFIG if config is None else config
        self.fail = set(fail)
        self.engine_id = engine_id
        self.listings = listings or {}
        self.facts = facts or {}
        self.calls: list[list[str]] = []
        self.deleted: set[str] = set()

    def _attach(self, item: dict[str, Any]) -> dict[str, Any]:
        names = item["networks"]
        current = {name: self.network_ids.get(name, nid(name, "compose")) for name in names}
        return {"attached": current, **item}

    def __call__(self, arguments: Sequence[str]) -> str:
        args = list(arguments)
        self.calls.append(args)
        if self._actions(args) & self.fail:
            raise GuardError("docker 失敗")
        if args[0] == "compose":
            return self._compose(args)
        handlers: dict[str, Callable[[], str]] = {
            "context": lambda: "orbstack\n",
            "info": lambda: f"{self.engine_id}\n",
            "ps": lambda: self._ps(args),
            "inspect": lambda: self._inspect(args[-1]),
            "rm": lambda: self._rm(args[1:]),
            "network": lambda: self._network(args[1], args[-1]),
            "volume": lambda: self._volumes(args),
        }
        return handlers[args[0]]()

    @staticmethod
    def _actions(args: list[str]) -> set[str]:
        if args[0] == "compose":
            verb = next((word for word in ("down", "config", "version") if word in args), "")
            return {f"compose {verb}"}
        return {args[0], " ".join(args[:2]), f"{args[0]} {args[-1]}"}

    def _compose(self, args: list[str]) -> str:
        if "version" in args:
            return "5.1.2\n"
        if "config" in args:
            return self.config if isinstance(self.config, str) else json.dumps(self.config)
        assert "down" in args, args
        self.containers = [item for item in self.containers if item["project"] != LIVE]
        self.volumes = {name: project for name, project in self.volumes.items() if project != LIVE}
        self.compose_networks = []
        return ""

    def _ps(self, args: list[str]) -> str:
        selector = args[-1]
        if selector.startswith("network="):
            value = selector.removeprefix("network=")
            key = self._resolve(value) or value
            if key in self.listings:
                return self.listings[key]
            chosen = [
                item
                for item in self.containers
                if value in item["attached"]
                or any(network.startswith(value) for network in item["attached"].values())
            ]
        else:
            assert selector == env_guard.PROJECT_FILTER, selector
            chosen = [item for item in self.containers if item["project"] == LIVE]
        everything = "-aq" in args
        return "".join(f"{item['id']}\n" for item in chosen if everything or not item["stopped"])

    def _inspect(self, identifier: str) -> str:
        if identifier in self.facts:
            return self.facts[identifier]
        found = [item for item in self.containers if item["id"] == identifier]
        if not found:
            raise GuardError("No such container")
        [item] = found
        pairs = " ".join(f"{name}={network}" for name, network in item["attached"].items())
        return f"{item['id']}|{json.dumps(item['project'])}|{pairs} \n"

    def _rm(self, args: list[str]) -> str:
        identifiers = [item for item in args if not item.startswith("-")]
        self.containers = [item for item in self.containers if item["id"] not in identifiers]
        repeated = len(identifiers) != len(set(identifiers)) or self.deleted & set(identifiers)
        self.deleted |= set(identifiers)
        if repeated:
            raise GuardError("removal of container is already in progress")
        return ""

    def _resolve(self, reference: str) -> str | None:
        """完整的 ID 優先，再以名稱解析。"""
        by_id = [name for name, network in self.network_ids.items() if network == reference]
        return by_id[0] if by_id else (reference if reference in self.networks else None)

    def _network(self, verb: str, reference: str) -> str:
        if verb == "ls":
            return "".join(f"{item}\n" for item in [*self.networks, *self.compose_networks])
        name = self._resolve(reference)
        if name is None:
            raise GuardError("No such network")
        network = self.network_ids[name]
        if verb == "inspect":
            label = self.networks[name]
            labels = {env_guard.RUN_LABEL: label} if label else {}
            return f"{network}|{name}|{json.dumps(labels)}\n"
        assert verb == "rm", verb
        if any(network in item["attached"].values() for item in self.containers):
            raise GuardError("network has active endpoints")
        del self.networks[name], self.network_ids[name]
        return ""

    def _volumes(self, args: list[str]) -> str:
        labelled = env_guard.PROJECT_FILTER in args
        return "".join(
            f"{name}\n" for name, project in self.volumes.items() if not labelled or project == LIVE
        )

    def removed(self) -> list[str]:
        return [call[-1] for call in self.calls if call[:1] == ["rm"]]

    def destructive(self) -> list[list[str]]:
        return [
            call
            for call in self.calls
            if call[:1] == ["rm"] or call[:2] == ["network", "rm"] or "down" in call
        ]

    def ids(self) -> set[str]:
        return {item["id"] for item in self.containers}


def write_record(
    directory: Path,
    networks: Mapping[str, str],
    *,
    claimed: bool,
    changes: Mapping[str, object] | None = None,
) -> None:
    """所有權紀錄（env_guard networks 寫入的格式；以字面的 JSON 寫，不用 env_guard 的寫入函式）。
    changes 覆寫或加上欄位（不可信的紀錄）。"""
    record = {
        "engine": ENGINE,
        "owner": OWNER,
        "labels": {env_guard.RUN_LABEL: OWNER},
        "networks": dict(networks),
        "claimed": claimed,
    }
    path = directory / env_guard.CLAIM_FILE
    path.write_text(json.dumps(record | dict(changes or {})), encoding="utf-8")
    path.chmod(0o600)


def _run_dir(
    tmp_path: Path, networks: Mapping[str, str] | None = OURS, *, claimed: bool = True
) -> Path:
    """拋棄式目錄與所有權紀錄（networks 是 None：沒有紀錄；兩個網路都在才可能是 claimed）。"""
    directory = tmp_path / OWNER
    directory.mkdir(mode=0o700)
    (directory / "db_password").write_text("disposable", encoding="ascii")
    if networks is not None:
        both = set(networks) == env_guard.LIVE_NETWORKS
        write_record(directory, networks, claimed=claimed and both)
    return directory


def _clean(
    tmp_path: Path,
    docker: CleanupDocker,
    *,
    claimed: bool = True,
    engine_id: str = ENGINE,
    networks: Mapping[str, str] | None = OURS,
) -> CleanupReport:
    directory = _run_dir(tmp_path, networks, claimed=claimed)
    report = cleanup(docker, tmp_path, str(directory), engine_id=engine_id, claimed=claimed)
    assert not directory.exists()
    return report


def _has(report: CleanupReport, message: str) -> bool:
    return any(message in failure for failure in report.failures)
