"""tests/live/env_guard.py 的清理（G1 審查 M2、MEDIUM-1、2；第二輪的 HIGH、MEDIUM-1、安全 LOW-1）。

docker 以有狀態的替身取代（不連 daemon）：網路與所有權的標記、容器（完整的 ID、專案、接的網路、
是否停止）、volume（名稱與專案標記）、compose 建立的網路、Engine ID。替身的規則：

- docker rm 收到重複的 ID 時失敗：審查者依 docker CLI 與 daemon 的原始碼推論的行為（第二個刪除請求
  衝突），沒有以真的 Docker 驗證；替身照最嚴格的推論失敗，去重是否有效才測得出來；
- 網路上還有容器（含停止的）時 network rm 失敗；ps 不帶 -a 時不列出停止的容器；
- compose down 刪除 secscan-live 專案的容器、volume 與 compose 建立的網路（不刪 external 的網路）。
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.live import env_guard
from tests.live.env_guard import CleanupReport, GuardError, cleanup, write_diagnostic

OWNER = "secscan-live-secrets.Abc123"
OTHER = "secscan-live-secrets.Other1"
ENGINE = "engine-1"
USAGE_ERROR = 2  # argparse 的用法錯誤
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


GUARD = cid("guard")
RECEIVER = cid("receiver")
ORPHAN = cid("orphan-scan")


def container(
    name: str, *networks: str, project: str = LIVE, stopped: bool = False
) -> dict[str, Any]:
    return {"id": cid(name), "project": project, "networks": list(networks), "stopped": stopped}


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

    fail 列出的動作回傳失敗：例如 "compose down"、"compose config"、"network rm"、"volume ls"、
    "ps"、"inspect"、"info"，或 "rm <ID>"。
    """

    def __init__(
        self,
        *,
        networks: dict[str, str] | None = None,
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
        chosen = [*stack(), *probes()] if containers is None else containers
        self.containers = [dict(item) for item in chosen]
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
            name = selector.removeprefix("network=")
            if name in self.listings:
                return self.listings[name]
            chosen = [item for item in self.containers if name in item["networks"]]
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
        project = item["project"] or env_guard.NO_VALUE
        return f"{item['id']}|{project}|{' '.join(item['networks'])} \n"

    def _rm(self, args: list[str]) -> str:
        identifiers = [item for item in args if not item.startswith("-")]
        self.containers = [item for item in self.containers if item["id"] not in identifiers]
        if len(identifiers) != len(set(identifiers)):
            raise GuardError("removal of container is already in progress")
        return ""

    def _network(self, verb: str, name: str) -> str:
        if verb == "ls":
            return "".join(f"{item}\n" for item in [*self.networks, *self.compose_networks])
        if name not in self.networks:
            raise GuardError("No such network")
        if verb == "inspect":
            return f"{self.networks[name] or env_guard.NO_VALUE}\n"
        assert verb == "rm", verb
        if any(name in item["networks"] for item in self.containers):
            raise GuardError("network has active endpoints")
        del self.networks[name]
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


def _run_dir(tmp_path: Path) -> Path:
    directory = tmp_path / OWNER
    directory.mkdir(mode=0o700)
    (directory / "db_password").write_text("disposable", encoding="ascii")
    return directory


def _clean(
    tmp_path: Path, docker: CleanupDocker, *, claimed: bool = True, engine_id: str = ENGINE
) -> CleanupReport:
    directory = _run_dir(tmp_path)
    report = cleanup(docker, tmp_path, str(directory), engine_id=engine_id, claimed=claimed)
    assert not directory.exists()
    return report


def _has(report: CleanupReport, message: str) -> bool:
    return any(message in failure for failure in report.failures)


# --------------------------------------------------------------------------- 去重與所有權（HIGH）


def test_an_owned_run_is_removed_completely_with_each_container_once(tmp_path: Path) -> None:
    """guard 接在兩個網路上、接收端、停止的孤兒掃描容器：每個只刪除一次，依 ID 排序。"""
    docker = CleanupDocker()

    report = _clean(tmp_path, docker)

    assert report.failures == []
    assert report.skipped == []
    assert docker.removed() == sorted([GUARD, RECEIVER, ORPHAN])
    assert all(call == ["rm", "-f", "-v", call[-1]] for call in docker.calls if call[0] == "rm")
    assert [*env_guard.LIVE_COMPOSE, "down", "-v", "--remove-orphans"] in docker.calls
    assert (docker.networks, docker.containers, docker.volumes) == ({}, [], {})
    # guard 在兩個網路上各列出一次：只 inspect 一次、只刪一次。
    inspected = [call for call in docker.calls if call[:1] == ["inspect"] and call[-1] == GUARD]
    assert len(inspected) == 1


def test_the_fake_refuses_duplicate_ids_positive_control() -> None:
    """替身遇到重複的 ID 會失敗：上一個測試通過，代表清理真的去重了。"""
    docker = CleanupDocker()

    with pytest.raises(GuardError, match="already in progress"):
        docker(["rm", "-f", "-v", GUARD, GUARD])


def test_the_removal_order_does_not_depend_on_the_listing_order(tmp_path: Path) -> None:
    forward = CleanupDocker()
    backward = CleanupDocker(containers=reversed([*stack(), *probes()]))

    for name, docker in (("forward", forward), ("backward", backward)):
        (tmp_path / name).mkdir()
        _clean(tmp_path / name, docker)

    assert forward.removed() == backward.removed() == sorted([GUARD, RECEIVER, ORPHAN])


def test_stopped_containers_are_listed_and_removed(tmp_path: Path) -> None:
    """ps 一律帶 -a：停止的容器（替身不帶 -a 時不列出）也找得到、刪得掉。"""
    docker = CleanupDocker()

    _clean(tmp_path, docker)

    listings = [call for call in docker.calls if call[:1] == ["ps"]]
    assert listings
    assert all(call[:3] == ["ps", "-aq", "--no-trunc"] for call in listings)
    assert ORPHAN in docker.removed()


def test_malformed_and_empty_ids_never_reach_docker_rm(tmp_path: Path) -> None:
    malformed = ("c-short", "Z" * 64)
    listing = f"\n{malformed[0]}\n{RECEIVER}\n{malformed[1]}\n\n"
    # inspect 對格式不正確的 ID 也回報「屬於這次執行」：只有格式檢查擋得住（空轉檢查 55d）。
    facts = {item: f"{item}||{LAB} \n" for item in malformed}
    docker = CleanupDocker(listings={LAB: listing}, facts=facts)

    report = _clean(tmp_path, docker)

    inspected = {call[-1] for call in docker.calls if call[:1] == ["inspect"]}
    assert not inspected & set(malformed)
    assert all(env_guard.CONTAINER_ID.fullmatch(identifier) for identifier in docker.removed())
    assert sorted(docker.removed()) == sorted([GUARD, RECEIVER, ORPHAN])
    assert _has(report, "格式不正確的容器 ID（2 個）")
    # 網路上列得到（格式不正確的）容器：網路不刪除，下一次的 preflight 會拒絕。
    assert LAB in docker.networks
    assert _has(report, f"網路 {LAB} 上還有容器")


@pytest.mark.parametrize(
    "facts",
    [f"{cid('someone-else')}||{LAB} \n", "garbage\n", f"{RECEIVER}|x|{LAB}|extra\n"],
    ids=["other-id", "garbage", "extra-field"],
)
def test_a_container_that_cannot_be_confirmed_is_not_removed(tmp_path: Path, facts: str) -> None:
    docker = CleanupDocker(facts={RECEIVER: facts})

    report = _clean(tmp_path, docker)

    assert RECEIVER not in docker.removed()
    assert RECEIVER in docker.ids()
    assert _has(report, f"無法確認容器 {RECEIVER[:12]}")


def test_containers_of_another_project_are_never_removed(tmp_path: Path) -> None:
    dev = container("dev-runner", SCAN, project="secscan")
    docker = CleanupDocker(containers=[*stack(), dev])

    report = _clean(tmp_path, docker)

    assert dev["id"] not in docker.removed()
    assert dev["id"] in docker.ids()
    assert _has(report, f"其他 compose 專案的容器 {dev['id'][:12]}")
    assert SCAN in docker.networks


def test_a_container_also_on_a_network_not_owned_by_this_run_is_never_removed(
    tmp_path: Path,
) -> None:
    """接在開發的網路上（或另一次執行的網路上）的容器：不刪除，網路也留著。"""
    bridge = container("bridge", SCAN, "secscan_scan_net", project="")
    docker = CleanupDocker(containers=[*stack(), bridge])

    report = _clean(tmp_path, docker)

    assert bridge["id"] not in docker.removed()
    assert _has(report, f"容器 {bridge['id'][:12]} 接在不屬於這次執行的網路上")
    assert SCAN in docker.networks


# ----------------------------------------------------------------- 所有權的狀態（安全 LOW-1）


def test_networks_of_another_run_are_left_alone(tmp_path: Path) -> None:
    """並行：網路與 stack 都是另一次執行的（這次沒有取得所有權）。只刪自己的拋棄式目錄。"""
    others = dict.fromkeys(env_guard.LIVE_NETWORKS, OTHER)
    docker = CleanupDocker(networks=others)

    report = _clean(tmp_path, docker, claimed=False)

    assert report.failures == []
    assert [item for item in report.skipped if OTHER in item]
    assert docker.destructive() == []
    assert docker.networks == others
    assert len(docker.containers) == len(stack()) + len(probes())


def test_networks_taken_over_after_the_claim_fail_closed(tmp_path: Path) -> None:
    """記錄了所有權，網路卻是另一次執行的：外部變更，不刪任何東西、不宣稱完成。"""
    docker = CleanupDocker(networks=dict.fromkeys(env_guard.LIVE_NETWORKS, OTHER))

    report = _clean(tmp_path, docker, claimed=True)

    assert _has(report, "外部變更")
    assert _has(report, "清理之後還有 Live 的資源")
    assert docker.destructive() == []


def test_networks_missing_after_the_claim_fail_closed(tmp_path: Path) -> None:
    """安全 LOW-1：這次的網路被刪除（例如 prune），stack 還在：不 down、不刪容器，以失敗回報。"""
    docker = CleanupDocker(networks={})

    report = _clean(tmp_path, docker, claimed=True)

    assert _has(report, "外部變更")
    assert _has(report, "清理之後還有 Live 的資源")
    assert docker.destructive() == []
    assert len(docker.containers) == len(stack()) + len(probes())


def test_networks_missing_without_a_claim_still_checks_containers_and_volumes(
    tmp_path: Path,
) -> None:
    docker = CleanupDocker(networks={}, containers=[container("db", "secscan-live_default")])

    report = _clean(tmp_path, docker, claimed=False)

    assert _has(report, "清理之後還有 Live 的資源")
    assert docker.destructive() == []


def test_nothing_created_and_nothing_left_is_clean(tmp_path: Path) -> None:
    """沒有取得所有權、也沒有任何 Live 的資源（例如網段衝突，network create 失敗）：清理完成。"""
    docker = CleanupDocker(networks={}, containers=[], volumes={}, compose_networks=())

    report = _clean(tmp_path, docker, claimed=False)

    assert (report.failures, report.skipped) == ([], [])


def test_a_partial_claim_removes_only_its_own_network(tmp_path: Path) -> None:
    """scan_net 建立了、lab_net 已經是另一次執行的：只刪自己的網路與上面的容器。"""
    probe = container("probe", SCAN, project="")
    docker = CleanupDocker(
        networks={SCAN: OWNER, LAB: OTHER}, containers=[probe], volumes={}, compose_networks=()
    )

    report = _clean(tmp_path, docker, claimed=False)

    assert report.failures == []
    assert docker.removed() == [probe["id"]]
    assert docker.networks == {LAB: OTHER}
    assert not [call for call in docker.calls if "down" in call]


def test_an_unlabelled_live_network_left_behind_is_reported(tmp_path: Path) -> None:
    """所有權不明（沒有標記）的 Live 網路：不刪除，以失敗回報（不當成另一次執行持有）。"""
    docker = CleanupDocker(
        networks={SCAN: OWNER, LAB: ""}, containers=[], volumes={}, compose_networks=()
    )

    report = _clean(tmp_path, docker, claimed=False)

    assert docker.networks == {LAB: ""}
    assert _has(report, "清理之後還有 Live 的資源")


def test_a_live_volume_without_the_compose_label_is_residue(tmp_path: Path) -> None:
    """殘留不只看網路與專案標記：Live 名稱的 volume（compose down 不會刪）也算。"""
    docker = CleanupDocker(
        volumes={"secscan-live_db_data": LIVE, "secscan_live_extra": "", "secscan_db_data": "x"}
    )

    report = _clean(tmp_path, docker)

    assert docker.volumes == {"secscan_live_extra": "", "secscan_db_data": "x"}
    assert _has(report, "'volume': 1")


# --------------------------------------------------------------------------- Engine（安全 LOW-1）


@pytest.mark.parametrize(
    ("docker", "engine_id"),
    [(CleanupDocker(), "engine-2"), (CleanupDocker(fail=["info"]), ENGINE)],
    ids=["different-engine", "unreachable-engine"],
)
def test_an_engine_that_cannot_be_confirmed_leaves_every_docker_resource_alone(
    tmp_path: Path, docker: CleanupDocker, engine_id: str
) -> None:
    report = _clean(tmp_path, docker, engine_id=engine_id)

    assert _has(report, "沒有清理、也沒有核對任何 Docker 資源")
    assert {call[0] for call in docker.calls} <= {"context", "compose", "info"}
    assert docker.destructive() == []


# --------------------------------------------------------------------------- 失敗（MEDIUM-1、2）


@pytest.mark.parametrize(
    ("docker", "message"),
    [
        (CleanupDocker(config="not json"), "down -v"),
        (CleanupDocker(fail=["compose config"]), "無法核對"),
        (CleanupDocker(fail=["volume ls"]), "無法核對"),
        (CleanupDocker(fail=["compose down"]), "compose down -v"),
        (CleanupDocker(fail=["network rm"]), "刪除網路"),
        (CleanupDocker(fail=[f"rm {GUARD}"]), f"刪除容器 {GUARD[:12]}"),
        (CleanupDocker(fail=["ps"]), "列出網路"),
        (CleanupDocker(fail=["network ls"]), "列出網路"),
        (CleanupDocker(fail=["network inspect"]), "所有權"),
        (CleanupDocker(fail=["inspect"]), "確認容器"),
    ],
    ids=[
        "config-not-json",
        "config-fails",
        "volumes-fail",
        "down-fails",
        "network-rm-fails",
        "rm-fails",
        "ps-fails",
        "network-ls-fails",
        "network-inspect-fails",
        "inspect-fails",
    ],
)
def test_every_failed_step_is_reported(tmp_path: Path, docker: CleanupDocker, message: str) -> None:
    report = _clean(tmp_path, docker)

    assert _has(report, message), report.failures


def test_one_failed_removal_does_not_stop_the_other_independent_steps(tmp_path: Path) -> None:
    """MEDIUM-1：接收端刪不掉時，其他容器、compose down、空的網路照常處理；它的網路留著。"""
    docker = CleanupDocker(fail=[f"rm {RECEIVER}"])

    report = _clean(tmp_path, docker)

    assert sorted(docker.removed()) == sorted([GUARD, RECEIVER, ORPHAN])
    assert ORPHAN not in docker.ids()
    assert GUARD not in docker.ids()
    assert [call for call in docker.calls if "down" in call]
    assert docker.networks == {LAB: OWNER}
    assert _has(report, f"刪除容器 {RECEIVER[:12]}")
    assert _has(report, f"網路 {LAB} 上還有容器")


def test_a_failed_down_reports_the_remaining_resources(tmp_path: Path) -> None:
    docker = CleanupDocker(fail=["compose down"])

    report = _clean(tmp_path, docker)

    assert _has(report, "compose down -v")
    assert _has(report, "清理之後還有 Live 的資源")
    assert _has(report, "'容器': 5")
    assert _has(report, "'volume': 2")


def test_down_is_not_run_when_the_residue_cannot_be_confirmed(tmp_path: Path) -> None:
    """compose config 失敗：不 down，stack 還在，以失敗回報（不宣稱完成）。"""
    docker = CleanupDocker(fail=["compose config"])

    report = _clean(tmp_path, docker)

    assert not [call for call in docker.calls if "down" in call]
    assert _has(report, "清理之後還有 Live 的資源")


@pytest.mark.parametrize(
    ("changes", "volumes"),
    [
        ({"name": "secscan"}, None),
        ({"volumes": {"db_data": {"name": "secscan_db_data"}}}, None),
        ({"volumes": {"db_data": {"name": "secscan-live_db_data", "external": True}}}, None),
        ({"networks": {"scan_net": {"name": "secscan_scan_net"}}}, None),
        ({}, {"secscan_live_runs": LIVE, "secscan_db_data": LIVE}),
    ],
    ids=["dev-project", "dev-volume", "external-volume", "dev-network", "existing-dev-volume"],
)
def test_down_runs_only_when_every_target_is_a_live_resource(
    tmp_path: Path, changes: dict[str, Any], volumes: dict[str, str] | None
) -> None:
    """M2（HIGH）：down -v 之前核對專案、解析出來的 volume 與網路、既有的 volume。"""
    docker = CleanupDocker(config={**LIVE_CONFIG, **changes}, volumes=volumes)

    report = _clean(tmp_path, docker)

    assert not [call for call in docker.calls if "down" in call]
    assert _has(report, "down -v 的對象不只 Live 的資源")


# --------------------------------------------------------------------------- 拋棄式目錄


def test_cleanup_without_a_directory_touches_nothing(tmp_path: Path) -> None:
    docker = CleanupDocker()

    unclaimed = cleanup(docker, tmp_path, "", engine_id=ENGINE, claimed=False)
    claimed = cleanup(docker, tmp_path, "", engine_id=ENGINE, claimed=True)

    assert unclaimed.failures == []
    assert [failure for failure in claimed.failures if "沒有拋棄式目錄" in failure]
    assert docker.calls == []


def test_cleanup_refuses_a_directory_it_cannot_attribute(tmp_path: Path) -> None:
    other = tmp_path / "elsewhere" / OWNER
    other.mkdir(parents=True)
    docker = CleanupDocker()

    report = cleanup(docker, tmp_path, str(other), engine_id=ENGINE, claimed=True)

    assert report.failures
    assert docker.calls == []
    assert other.exists()


def test_a_symlinked_directory_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep").write_text("keep", encoding="ascii")
    (tmp_path / OWNER).symlink_to(target)

    report = cleanup(
        CleanupDocker(), tmp_path, str(tmp_path / OWNER), engine_id=ENGINE, claimed=True
    )

    assert _has(report, "自己擁有的目錄")
    assert (target / "keep").exists()


def test_a_directory_that_cannot_be_removed_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = _run_dir(tmp_path)

    def refuse(_path: object) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(shutil, "rmtree", refuse)

    report = cleanup(CleanupDocker(), tmp_path, str(directory), engine_id=ENGINE, claimed=True)

    assert _has(report, "無法刪除拋棄式目錄")
    assert _has(report, "拋棄式目錄還在")


def test_a_directory_that_cannot_be_inspected_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MEDIUM-1：lstat 的 OSError（例如沒有權限）只記錄，不以 traceback 中斷。"""
    directory = _run_dir(tmp_path)
    original = Path.lstat

    def refuse(path: Path) -> os.stat_result:
        if path == directory:
            raise PermissionError(13, "Permission denied")
        return original(path)

    monkeypatch.setattr(Path, "lstat", refuse)

    report = cleanup(CleanupDocker(), tmp_path, str(directory), engine_id=ENGINE, claimed=True)

    assert _has(report, "無法確認拋棄式目錄（PermissionError）")
    assert directory.exists()


def test_an_already_removed_directory_is_fine(tmp_path: Path) -> None:
    docker = CleanupDocker()

    report = cleanup(docker, tmp_path, str(tmp_path / OWNER), engine_id=ENGINE, claimed=True)

    assert report.failures == []


def test_the_diagnostic_lists_steps_and_names_only(tmp_path: Path) -> None:
    path = write_diagnostic(tmp_path, str(tmp_path / OWNER), ["compose down -v", "刪除網路 x"])

    text = path.read_text(encoding="utf-8")
    assert path.name.startswith(env_guard.DIAGNOSTIC_PREFIX)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert OWNER in text
    assert "- compose down -v" in text


# --------------------------------------------------------------------------- docker()（MEDIUM-1）


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (subprocess.TimeoutExpired(["docker", "rm"], 120), "逾時"),
        (FileNotFoundError(2, "No such file or directory"), "FileNotFoundError"),
        (PermissionError(13, "Permission denied"), "PermissionError"),
        (UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"), "UnicodeDecodeError"),
    ],
    ids=["timeout", "missing-docker", "permission", "not-utf8"],
)
def test_docker_errors_become_guard_errors_without_their_arguments(
    monkeypatch: pytest.MonkeyPatch, error: Exception, message: str
) -> None:
    def broken(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise error

    monkeypatch.setattr(subprocess, "run", broken)

    with pytest.raises(GuardError) as caught:
        env_guard.docker(["rm", "-f", "-v", "argument-not-in-message"])

    text = str(caught.value)
    assert message in text
    assert "docker rm" in text
    assert "argument-not-in-message" not in text
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__


def test_a_failing_docker_command_reports_its_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 125, "", "daemon error with details")

    monkeypatch.setattr(subprocess, "run", failing)

    with pytest.raises(GuardError, match="結束碼 125") as caught:
        env_guard.docker(["network", "rm", "x"])

    assert "daemon error" not in str(caught.value)


def test_a_timeout_during_cleanup_is_reported_with_a_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """MEDIUM-1 的端到端：真的 docker() 遇到逾時：其他步驟照常、寫入診斷檔、沒有 traceback。"""
    docker = CleanupDocker()
    directory = _run_dir(tmp_path)

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if "down" in argv:
            raise subprocess.TimeoutExpired(argv, env_guard.DOCKER_TIMEOUT_SECONDS)
        try:
            return subprocess.CompletedProcess(argv, 0, docker(argv[1:]), "")
        except GuardError:
            return subprocess.CompletedProcess(argv, 1, "", "error")

    monkeypatch.setattr(subprocess, "run", fake_run)

    code = env_guard.main(
        [
            *("cleanup", "--base", str(tmp_path), "--secrets-dir", str(directory)),
            *("--engine", ENGINE, "--claimed"),
        ]
    )

    err = capsys.readouterr().err
    [diagnostic] = tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")
    assert code == env_guard.EXIT_FAILURE
    assert "逾時" in err
    assert "Traceback" not in err
    assert "compose down -v" in diagnostic.read_text(encoding="utf-8")
    assert GUARD not in docker.ids()
    assert not directory.exists()


# --------------------------------------------------------------------------- CLI


def _cleanup_argv(base: Path, directory: Path, *extra: str) -> list[str]:
    return ["cleanup", "--base", str(base), "--secrets-dir", str(directory), *extra]


def test_the_cleanup_cli_reports_success_and_what_it_left_alone(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    directory = _run_dir(tmp_path)
    docker = CleanupDocker(
        networks={SCAN: OWNER, LAB: OTHER}, containers=[], volumes={}, compose_networks=()
    )
    monkeypatch.setattr(env_guard, "docker", docker)

    code = env_guard.main(_cleanup_argv(tmp_path, directory, "--engine", ENGINE))

    out = capsys.readouterr().out
    assert code == env_guard.EXIT_OK
    assert out.startswith("cleanup ok")
    assert LAB in out
    assert list(tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")) == []


def test_the_cleanup_cli_fails_and_keeps_a_diagnostic(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    directory = _run_dir(tmp_path)
    monkeypatch.setattr(env_guard, "docker", CleanupDocker(fail=["compose down"]))

    code = env_guard.main(_cleanup_argv(tmp_path, directory, "--engine", ENGINE, "--claimed"))

    err = capsys.readouterr().err
    [diagnostic] = tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")
    assert code == env_guard.EXIT_FAILURE
    assert "清理沒有完成" in err
    assert str(diagnostic) in err
    assert "compose down -v" in diagnostic.read_text(encoding="utf-8")


def test_the_cleanup_cli_still_fails_when_the_diagnostic_cannot_be_written(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(env_guard, "docker", CleanupDocker(fail=["network ls"]))
    base = tmp_path / "gone"

    code = env_guard.main(_cleanup_argv(base, base / OWNER, "--engine", ENGINE, "--claimed"))

    assert code == env_guard.EXIT_FAILURE
    assert "無法寫入診斷檔" in capsys.readouterr().err


def test_the_cleanup_cli_requires_the_engine(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as caught:
        env_guard.main(_cleanup_argv(tmp_path, tmp_path / OWNER))

    assert caught.value.code == USAGE_ERROR
