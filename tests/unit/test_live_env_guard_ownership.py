"""tests/live/env_guard.py 的所有權紀錄與 Network ID（G1c；剩餘風險 25）。

所有權以 networks 寫進拋棄式目錄的紀錄為準：Engine、預期的標記、network create 回傳的 Network ID。
清理以 ID inspect、以 ID 列出容器與刪除網路；名稱與標記只是輔助的核對。這裡是正反案例：同名同標記
的網路被換掉、不同的執行個體（含識別碰撞）、沒有取得所有權、部分建立失敗、紀錄缺少或不可信，以及
preflight 偵測已停止、沒有標記、以名稱引用 Live 網路的容器。docker 以有狀態的替身取代（不連 daemon；
tests/unit/live_cleanup_fake.py）。
"""

import json
import os
import stat
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.live import env_guard
from tests.live.env_guard import GuardError, NetworkSpec, claim_networks, cleanup, read_claim
from tests.unit.live_cleanup_fake import (
    ENGINE,
    LAB,
    OTHER,
    OURS,
    OWNER,
    SCAN,
    CleanupDocker,
    _clean,
    _has,
    _run_dir,
    cid,
    container,
    nid,
    probes,
    stack,
    write_record,
)

SPECS = {
    SCAN: NetworkSpec(SCAN, "10.89.9.0/24", "10.89.9.0/25"),
    LAB: NetworkSpec(LAB, "10.89.10.0/24", "10.89.10.0/25"),
}


class CreatingDocker(CleanupDocker):
    """network create 回傳新的 Network ID（同名同標記也是新的 ID）；建立時的 inspect 回報設定。"""

    def __init__(self, *, create_output: str | None = None, **changes: Any) -> None:
        empty: dict[str, Any] = {"containers": [], "volumes": {}, "compose_networks": ()}
        super().__init__(networks={}, **(empty | changes))
        self.create_output = create_output
        self.generation = 0

    def __call__(self, arguments: Sequence[str]) -> str:
        args = list(arguments)
        if args[:2] == ["network", "create"]:
            self.calls.append(args)
            name, label = args[-1], args[args.index("--label") + 1].split("=", 1)[1]
            if self._actions(args) & self.fail or name in self.networks:
                raise GuardError("network with name already exists")
            self.generation += 1
            self.networks[name] = label
            self.network_ids[name] = nid(name, label, self.generation)
            return self.create_output or f"{self.network_ids[name]}\n"
        if args[:4] == ["network", "inspect", "--format", env_guard.NETWORK_FORMAT]:
            self.calls.append(args)
            network_id, name, labels = self._network("inspect", args[-1]).strip().split("|", 2)
            spec = SPECS[name]
            return f"{network_id}|{name}|true|isolated|{spec.subnet} {spec.ip_range}|{labels}\n"
        return super().__call__(arguments)

    def start_stack(self) -> None:
        """compose up 與測試的探針：接在目前的兩個網路上。"""
        self.containers = [self._attach(dict(item)) for item in [*stack(), *probes()]]


def _directory(tmp_path: Path) -> Path:
    directory = tmp_path / OWNER
    directory.mkdir(mode=0o700)
    return directory


def _claim(docker: CleanupDocker, directory: Path) -> None:
    claim_networks(docker, list(SPECS.values()), directory, ENGINE)


def _network_calls(docker: CleanupDocker, verb: str) -> list[str]:
    return [call[-1] for call in docker.calls if call[:2] == ["network", verb]]


# --------------------------------------------------------------------------- 建立與紀錄


def test_the_claim_records_the_engine_labels_and_the_ids_network_create_returned(
    tmp_path: Path,
) -> None:
    docker = CreatingDocker()
    directory = _directory(tmp_path)

    _claim(docker, directory)

    claim = read_claim(directory)
    assert claim is not None
    assert (claim.engine, claim.owner, claim.claimed) == (ENGINE, OWNER, True)
    assert claim.networks == docker.network_ids
    raw = json.loads((directory / env_guard.CLAIM_FILE).read_text(encoding="utf-8"))
    assert raw["labels"] == {env_guard.RUN_LABEL: OWNER}
    assert stat.S_IMODE((directory / env_guard.CLAIM_FILE).stat().st_mode) == 0o600
    assert sorted(os.listdir(directory)) == [env_guard.CLAIM_FILE]
    # 以 network create 回傳的 ID 核對，不以名稱。
    assert _network_calls(docker, "inspect") == [docker.network_ids[SCAN], docker.network_ids[LAB]]


def test_a_partial_creation_records_only_what_was_created(tmp_path: Path) -> None:
    """lab_net 建立失敗：紀錄只有 scan_net 的 ID，沒有 claimed。"""
    docker = CreatingDocker(fail=[f"network {LAB}"])
    directory = _directory(tmp_path)

    with pytest.raises(GuardError, match=LAB):
        _claim(docker, directory)

    claim = read_claim(directory)
    assert claim is not None
    assert (claim.networks, claim.claimed) == ({SCAN: docker.network_ids[SCAN]}, False)


def test_a_create_without_a_full_id_is_not_recorded(tmp_path: Path) -> None:
    docker = CreatingDocker(create_output="0123abcd\n")
    directory = _directory(tmp_path)

    with pytest.raises(GuardError, match="完整 ID"):
        _claim(docker, directory)

    claim = read_claim(directory)
    assert claim is not None
    assert (claim.networks, claim.claimed) == ({}, False)


def test_the_engine_is_confirmed_before_anything_is_created(tmp_path: Path) -> None:
    docker = CreatingDocker(engine_id="engine-2")
    directory = _directory(tmp_path)

    with pytest.raises(GuardError, match="Engine ID"):
        _claim(docker, directory)

    assert _network_calls(docker, "create") == []
    assert read_claim(directory) is None


def test_an_existing_record_is_never_reused(tmp_path: Path) -> None:
    docker = CreatingDocker()
    directory = _directory(tmp_path)
    write_record(directory, {}, claimed=False)

    with pytest.raises(GuardError, match="已經有所有權紀錄"):
        _claim(docker, directory)

    assert _network_calls(docker, "create") == []


@pytest.mark.parametrize("kind", ["group-readable", "symlink"])
def test_a_directory_that_is_not_private_is_refused(tmp_path: Path, kind: str) -> None:
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    directory = tmp_path / OWNER
    if kind == "symlink":
        directory.symlink_to(target)
    else:
        directory.mkdir()
        directory.chmod(0o750)
    docker = CreatingDocker()

    with pytest.raises((GuardError, OSError)):
        _claim(docker, directory)

    assert _network_calls(docker, "create") == []
    assert os.listdir(target) == []


def test_the_networks_cli_requires_the_engine(tmp_path: Path) -> None:
    networks = ("--network", SCAN, "10.89.9.0/24", "10.89.9.0/25")
    with pytest.raises(SystemExit):
        env_guard.main(["networks", "--secrets-dir", str(tmp_path / OWNER), *networks])


# --------------------------------------------------------------------------- 正向：以 ID 清理


def test_a_claimed_run_is_cleaned_up_by_the_ids_it_recorded(tmp_path: Path) -> None:
    """networks 寫的紀錄交給 cleanup：stack、探針、兩個網路都清除；網路以 ID 刪除。"""
    docker = CreatingDocker(volumes={"secscan-live_db_data": "secscan-live"})
    directory = _directory(tmp_path)
    _claim(docker, directory)
    ids = dict(docker.network_ids)
    docker.start_stack()

    report = cleanup(docker, tmp_path, str(directory), engine_id=ENGINE, claimed=True)

    assert (report.failures, report.skipped) == ([], [])
    assert (docker.networks, docker.containers, docker.volumes) == ({}, [], {})
    assert sorted(_network_calls(docker, "rm")) == sorted(ids.values())
    listed = [call[-1] for call in docker.calls if call[:2] == ["ps", "-aq"]]
    assert {f"network={network}" for network in ids.values()} <= set(listed)
    assert not directory.exists()


# --------------------------------------------------------------------------- 同名同標記被換掉


def _replaced() -> dict[str, str]:
    """同名、同標記、不同代的網路（ID 和紀錄的不同）。"""
    return {SCAN: nid(SCAN, OWNER, 1), LAB: nid(LAB, OWNER, 1)}


def _external() -> dict[str, Any]:
    """換上來的網路上的外部容器（沒有標記，接在新的 ID 上）。"""
    return container("external", SCAN, LAB, project="", attached=_replaced())


def test_a_same_name_same_label_replacement_is_never_touched(tmp_path: Path) -> None:
    docker = CleanupDocker(network_ids=_replaced(), containers=[_external(), *stack()])

    report = _clean(tmp_path, docker, claimed=True)

    assert docker.destructive() == []
    assert _has(report, "外部變更")
    assert _has(report, "沒有刪除任何 Docker 資源")
    assert docker.network_ids == _replaced()
    assert cid("external") in docker.ids()
    # 換上來的網路不是用名稱 inspect 而接受的：只以紀錄的 ID inspect。
    inspected = {call[-1] for call in docker.calls if call[:2] == ["network", "inspect"]}
    assert set(OURS.values()) <= inspected
    assert not inspected & set(_replaced().values())


def test_a_replacement_is_not_removed_without_a_claim_either(tmp_path: Path) -> None:
    docker = CleanupDocker(network_ids=_replaced(), containers=[], volumes={}, compose_networks=())

    report = _clean(tmp_path, docker, claimed=False, networks={SCAN: OURS[SCAN]})

    assert docker.destructive() == []
    assert docker.network_ids == _replaced()
    assert _has(report, f"確認網路 {SCAN} 的所有權")
    assert _has(report, "清理之後還有 Live 的資源")


# --------------------------------------------------------------------------- 不同的執行個體


@pytest.mark.parametrize("label", [OTHER, OWNER], ids=["other-run", "colliding-run-id"])
def test_another_instance_is_isolated_without_a_claim(tmp_path: Path, label: str) -> None:
    """另一次執行持有兩個網路（不同的識別，或碰撞成相同的識別）：這次沒有建立任何網路，不碰它的
    網路與容器（剩餘風險 25 ②：以前以標記判斷時，相同的識別會刪掉它空的網路）。"""
    theirs = {SCAN: nid(SCAN, label, 5), LAB: nid(LAB, label, 5)}
    guard = container("their-guard", SCAN, LAB, project="secscan-live", attached=theirs)
    docker = CleanupDocker(
        networks=dict.fromkeys((SCAN, LAB), label),
        network_ids=theirs,
        containers=[guard],
        volumes={},
        compose_networks=(),
    )

    report = _clean(tmp_path, docker, claimed=False, networks={})

    assert docker.destructive() == []
    assert docker.network_ids == theirs
    if label == OTHER:
        assert report.failures == []
        assert [item for item in report.skipped if OTHER in item]
    else:
        # 相同的識別、不同的 ID：不據以歸屬給別人（不算完成），但也不刪除。
        assert _has(report, "清理之後還有 Live 的資源")


def test_without_a_claim_only_the_recorded_network_ids_are_removed(tmp_path: Path) -> None:
    """scan_net 是這次建立的；lab_net 是另一次執行（相同的識別）建立的空網路：只刪紀錄中的 ID。"""
    theirs = nid(LAB, OWNER, 5)
    docker = CleanupDocker(
        network_ids={LAB: theirs}, containers=[], volumes={}, compose_networks=()
    )

    report = _clean(tmp_path, docker, claimed=False, networks={SCAN: OURS[SCAN]})

    assert docker.destructive() == [["network", "rm", OURS[SCAN]]]
    assert docker.network_ids == {LAB: theirs}
    assert _has(report, "清理之後還有 Live 的資源")


# --------------------------------------------------------------------------- 紀錄缺少或不可信


@pytest.mark.parametrize(
    ("networks", "record_claimed"),
    [(None, False), ({SCAN: OURS[SCAN]}, False), (OURS, False)],
    ids=["no-record", "partial-record", "record-not-claimed"],
)
def test_the_claimed_flag_without_a_complete_record_fails_closed(
    tmp_path: Path, networks: dict[str, str] | None, record_claimed: bool
) -> None:
    directory = _run_dir(tmp_path, networks, claimed=record_claimed)
    docker = CleanupDocker()

    report = cleanup(docker, tmp_path, str(directory), engine_id=ENGINE, claimed=True)

    assert docker.destructive() == []
    assert _has(report, "所有權紀錄不完整")
    assert _has(report, "清理之後還有 Live 的資源")


def test_a_missing_directory_with_a_claim_fails_closed(tmp_path: Path) -> None:
    docker = CleanupDocker()

    report = cleanup(docker, tmp_path, str(tmp_path / OWNER), engine_id=ENGINE, claimed=True)

    assert docker.destructive() == []
    assert _has(report, "所有權紀錄不完整")


BAD_RECORDS: dict[str, tuple[dict[str, Any], str]] = {
    "other-engine": ({"engine": "engine-2"}, "識別或 Engine"),
    "other-owner": (
        {"owner": OTHER, "labels": {env_guard.RUN_LABEL: OTHER}},
        "識別或 Engine",
    ),
    "unexpected-labels": ({"labels": {env_guard.RUN_LABEL: OTHER}}, "內容不正確"),
    "extra-key": ({"note": "x"}, "欄位不正確"),
    "short-id": ({"networks": {SCAN: "abc", LAB: OURS[LAB]}}, "內容不正確"),
    "duplicate-ids": ({"networks": {SCAN: OURS[SCAN], LAB: OURS[SCAN]}}, "內容不正確"),
    "dev-network": ({"networks": {"secscan_scan_net": OURS[SCAN], LAB: OURS[LAB]}}, "內容不正確"),
    "claimed-with-one": ({"networks": {SCAN: OURS[SCAN]}}, "內容不正確"),
    "claimed-not-bool": ({"claimed": "yes"}, "內容不正確"),
}


@pytest.mark.parametrize("case", sorted(BAD_RECORDS))
def test_a_record_that_cannot_be_trusted_deletes_nothing(tmp_path: Path, case: str) -> None:
    changes, message = BAD_RECORDS[case]
    directory = _run_dir(tmp_path, None)
    write_record(directory, OURS, claimed=True, changes=changes)
    docker = CleanupDocker()

    report = cleanup(docker, tmp_path, str(directory), engine_id=ENGINE, claimed=True)

    assert docker.destructive() == []
    assert _has(report, message)
    assert _has(report, "沒有刪除任何 Docker 資源")
    assert not directory.exists()


@pytest.mark.parametrize("kind", ["not-json", "too-large", "symlink"])
def test_an_unreadable_record_deletes_nothing(tmp_path: Path, kind: str) -> None:
    directory = _run_dir(tmp_path, None)
    record = directory / env_guard.CLAIM_FILE
    if kind == "symlink":
        # 連結的目標是一份有效、claimed 的紀錄：跟隨 symlink 就會刪除。
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        write_record(elsewhere, OURS, claimed=True)
        record.symlink_to(elsewhere / env_guard.CLAIM_FILE)
    else:
        size = 1 if kind == "not-json" else env_guard.CLAIM_MAX_BYTES + 1
        record.write_text("{" * size, encoding="utf-8")
    docker = CleanupDocker()

    report = cleanup(docker, tmp_path, str(directory), engine_id=ENGINE, claimed=True)

    assert docker.destructive() == []
    assert _has(report, "無法確認所有權")


def test_a_fifo_record_does_not_hang_the_cleanup(tmp_path: Path) -> None:
    """紀錄的位置是 FIFO：以 O_NONBLOCK 開啟、不是一般檔案就拒絕（另一個程序加上 timeout 執行：
    卡住時是 timeout 失敗，不會卡住整個 pytest）。"""
    directory = _run_dir(tmp_path, None)
    os.mkfifo(directory / env_guard.CLAIM_FILE, 0o600)
    code = (
        "import importlib.util, sys\n"
        "from pathlib import Path\n"
        "spec = importlib.util.spec_from_file_location('guard', sys.argv[1])\n"
        "guard = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(guard)\n"
        "try:\n"
        "    guard.read_claim(Path(sys.argv[2]))\n"
        "except guard.GuardError as exc:\n"
        "    print('refused', exc)\n"
    )

    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code, env_guard.__file__, str(directory)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr[-500:]
    assert "refused 所有權紀錄不是自己擁有的一般檔案" in result.stdout


class ResolvingByName(CleanupDocker):
    """以 ID 解析時回應同名的另一個網路（例如 daemon 的解析規則改變）：回報的 ID 和紀錄的不同。"""

    def _resolve(self, reference: str) -> str | None:
        for name, network in OURS.items():
            if reference == network and name in self.networks:
                return name
        return super()._resolve(reference)


def test_a_network_reported_with_another_id_is_not_trusted(tmp_path: Path) -> None:
    """以紀錄的 ID inspect，回報的卻是同名、同標記的另一個網路：ID 不同就不接受（不只看名稱與
    標記），不刪除任何東西。"""
    docker = ResolvingByName(network_ids=_replaced(), containers=[_external(), *stack()])

    report = _clean(tmp_path, docker, claimed=True)

    assert docker.destructive() == []
    assert _has(report, "ID、名稱或標記和所有權紀錄不同")
    assert docker.network_ids == _replaced()


# --------------------------------------------------------------------------- 容器的 Network ID


def test_a_container_on_an_older_network_with_the_same_name_is_not_removed(
    tmp_path: Path,
) -> None:
    """剩餘風險 25 ③：以名稱引用 Live 網路、但 Network ID 是舊網路的容器不是這次的：不刪除；它讓
    清理以失敗回報（殘留），下一次的 preflight 也會拒絕。"""
    stale = container("stale", SCAN, project="", stopped=True, attached={SCAN: nid(SCAN, OTHER, 9)})
    mixed = container(
        "mixed", SCAN, LAB, project="", attached={SCAN: OURS[SCAN], LAB: nid(LAB, OWNER, 9)}
    )
    docker = CleanupDocker(containers=[*stack(), stale, mixed])

    report = _clean(tmp_path, docker)

    assert stale["id"] not in docker.removed()
    assert mixed["id"] not in docker.removed()
    assert _has(report, f"容器 {mixed['id'][:12]} 接在不屬於這次執行的網路上")
    assert _has(report, "清理之後還有 Live 的資源")
    # 候選以 Network ID 列出：只以名稱引用舊網路的容器根本不是候選（不 inspect；空轉檢查 65e）。
    inspected = {call[-1] for call in docker.calls if call[:1] == ["inspect"]}
    assert stale["id"] not in inspected
    assert mixed["id"] in inspected


@pytest.mark.parametrize(
    "networks",
    [f"{LAB}=", LAB, f"{LAB}={OURS[LAB]} {LAB}={OURS[LAB]}", f"={OURS[LAB]}"],
    ids=["empty-id", "no-id", "repeated", "no-name"],
)
def test_a_container_whose_network_ids_cannot_be_confirmed_is_not_removed(
    tmp_path: Path, networks: str
) -> None:
    receiver = cid("receiver")
    docker = CleanupDocker(facts={receiver: f'{receiver}|""|{networks} \n'})

    report = _clean(tmp_path, docker)

    assert receiver not in docker.removed()
    assert _has(report, f"無法確認容器 {receiver[:12]}")


# --------------------------------------------------------------------------- preflight


def test_preflight_refuses_a_stopped_unlabelled_container_on_a_removed_live_network(
    tmp_path: Path,
) -> None:
    """網路已經刪掉，容器仍以名稱引用它（重建同名的網路之後啟動就會接上）：拒絕執行，不自動清理。"""
    stale = container("stale", LAB, project="", stopped=True, attached={LAB: nid(LAB, OTHER, 2)})
    docker = CleanupDocker(networks={}, containers=[stale], volumes={}, compose_networks=())

    with pytest.raises(GuardError, match="secscan-live 的資源") as caught:
        env_guard.preflight(tmp_path, docker)

    assert "'容器': 1" in str(caught.value)
    assert "引用 Live 網路" in str(caught.value)
    assert docker.destructive() == []
    assert ["ps", "-aq", "--no-trunc", "--filter", f"network={LAB}"] in docker.calls


def test_preflight_ignores_stopped_containers_on_development_networks_positive_control(
    tmp_path: Path,
) -> None:
    dev = container("dev", "secscan_scan_net", project="", stopped=True)
    docker = CleanupDocker(networks={}, containers=[dev], volumes={}, compose_networks=())

    env_guard.preflight(tmp_path, docker)

    assert docker.destructive() == []
