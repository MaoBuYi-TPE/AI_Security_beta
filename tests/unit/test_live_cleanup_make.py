"""Live 的清理經由 make 的完整流程（第二輪 G1：HIGH 的去重、安全 LOW-1 的所有權與 Engine）。

以 repo 的 Makefile 實際執行 make test-live-runner；docker 是 tests/unit/test_live_isolation_make.py
的有狀態替身：stack 的容器有完整的 ID、接在實際的網路上（guard 同時接 scan_net 與 lab_net），
docker rm 收到重複的 ID（同一次呼叫中重複，或之前已經刪除過）時失敗（同一次呼叫的衝突是審查者依
原始碼推論的行為，未以真的 Docker 驗證；「之前已經刪除過」比真的 rm -f 嚴格）。破壞性的情境只用
假的 docker，不連 Docker daemon、不建立任何資源。

另外以 compose.yaml 與 Makefile 的靜態對照，確認 Live 的 compose 不會用到開發的具名 volume（資料庫
審查 INFO-4）。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
"""

import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.live import env_guard
from tests.unit.test_live_isolation_make import MAKEFILE, ROOT, Hostile, _cid

STACK = {"api", "db", "runner", "worker", "socket-proxy", "guard"}
GUARD = _cid("guard")


@pytest.fixture
def hostile(tmp_path: Path) -> Hostile:
    return Hostile(tmp_path)


def _disposable_dirs(hostile: Hostile) -> list[str]:
    """留下的拋棄式目錄（診斷檔不算）。"""
    return sorted(path.name for path in hostile.tmpdir.glob(f"{env_guard.SECRETS_PREFIX}*"))


def _removed(hostile: Hostile) -> list[str]:
    return [argv[-1] for argv in hostile.docker_argvs() if argv[:1] == ["rm"]]


def _destructive_after_up(hostile: Hostile) -> list[list[str]]:
    """stack 啟動之後的破壞性呼叫（rm、network rm、compose down）。"""
    argvs = hostile.docker_argvs()
    [up] = [index for index, argv in enumerate(argvs) if argv[-3:] == ["up", "-d", "--wait"]]
    return [
        argv
        for argv in argvs[up:]
        if argv[:1] == ["rm"]
        or argv[:2] == ["network", "rm"]
        or (argv[:1] == ["compose"] and "down" in argv)
    ]


def _cleanup_call(hostile: Hostile) -> list[str]:
    [call] = [
        call["argv"]
        for call in hostile.calls()
        if call["tool"] == "uv" and "cleanup" in call["argv"]
    ]
    return list(call)


def test_each_container_is_removed_exactly_once(hostile: Hostile) -> None:
    """HIGH：guard 接在兩個 Live 網路上，替身遇到重複的 ID 就失敗；接收端與停止的掃描容器也都
    只刪一次。"""
    receiver, orphan = _cid("c-receiver"), _cid("c-orphan")
    hostile.set_scenario(
        extra_containers=[
            {"id": receiver, "project": "", "networks": ["secscan_live_lab_net"]},
            {"id": orphan, "project": "", "networks": ["secscan_live_scan_net"]},
        ]
    )

    result = hostile.make()

    succeeded = result.returncode == 0
    assert succeeded, hostile.redact(result.stderr[-1500:])
    removed = _removed(hostile)
    assert removed == sorted([GUARD, receiver, orphan])
    assert all(
        argv == ["rm", "-f", "-v", argv[-1]]
        for argv in hostile.docker_argvs()
        if argv[:1] == ["rm"]
    )
    assert hostile.docker_state()["containers"] == []
    assert hostile.docker_state()["networks"] == {}
    assert hostile.diagnostics() == []


def _fake_rm(hostile: Hostile, *identifiers: str) -> subprocess.CompletedProcess[str]:
    # 固定的假 docker（暫存目錄中的腳本），只更新它自己的 JSON 狀態。
    return subprocess.run(  # noqa: S603
        [str(hostile.bin / "docker"), "rm", "-f", "-v", *identifiers],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_the_fake_docker_refuses_duplicate_ids_positive_control(hostile: Hostile) -> None:
    """上一個測試通過，代表每個容器只刪除一次：同一個 ID 在同一次呼叫中重複，或之前已經刪除過，
    替身都失敗。"""
    receiver = _cid("c-receiver")
    hostile.set_docker_state(
        containers=[
            {"id": GUARD, "project": "secscan-live", "networks": ["secscan_live_scan_net"]},
            {"id": receiver, "project": "", "networks": ["secscan_live_lab_net"]},
        ]
    )

    duplicated = _fake_rm(hostile, GUARD, GUARD)
    first = _fake_rm(hostile, receiver)
    again = _fake_rm(hostile, receiver)

    assert duplicated.returncode != 0
    assert "already in progress" in duplicated.stderr
    assert first.returncode == 0
    assert again.returncode != 0


def test_the_cleanup_gets_the_engine_and_the_claim(hostile: Hostile) -> None:
    """安全 LOW-1：清理以開始時的 Engine 核對；兩個網路都建立並確認之後才記錄所有權。"""
    assert hostile.make().returncode == 0
    argv = _cleanup_call(hostile)

    assert argv[argv.index("--engine") + 1] == "engine-1"
    assert "--claimed" in argv


@pytest.mark.parametrize("where", ["command-line", "environment"])
def test_the_claim_and_the_engine_cannot_be_injected(hostile: Hostile, where: str) -> None:
    """安全 INFO-7：命令列或環境的 claimed=1、engine=… 都無效（recipe 一開始就重設，之後才
    設定）。"""
    hostile.set_scenario(taken=["secscan_live_scan_net"])
    injected = {"claimed": "1", "engine": "engine-injected"}

    if where == "command-line":
        result = hostile.make(*(f"{name}={value}" for name, value in injected.items()))
    else:
        result = hostile.make(**injected)

    assert result.returncode != 0
    argv = _cleanup_call(hostile)
    assert "--claimed" not in argv
    assert argv[argv.index("--engine") + 1] == "engine-1"


def test_a_failed_claim_is_not_recorded_as_ownership(hostile: Hostile) -> None:
    """另一次 Live 先建立了網路：這次沒有取得所有權，清理不帶 --claimed（不把別人的資源當成
    自己的）。"""
    hostile.set_scenario(taken=["secscan_live_scan_net"])

    result = hostile.make()

    assert result.returncode != 0
    argv = _cleanup_call(hostile)
    assert "--claimed" not in argv
    assert argv[argv.index("--engine") + 1] == "engine-1"
    assert _disposable_dirs(hostile) == []


def test_networks_that_vanish_after_the_claim_fail_closed(hostile: Hostile) -> None:
    """安全 LOW-1：stack 啟動之後網路被刪除（例如 prune）：不 down、不刪容器、不宣稱完成。"""
    hostile.set_scenario(networks_vanish=True)

    result = hostile.make()

    assert result.returncode != 0
    assert _destructive_after_up(hostile) == []
    assert {item["service"] for item in hostile.docker_state()["containers"]} == STACK
    [diagnostic] = hostile.diagnostics()
    text = diagnostic.read_text(encoding="utf-8")
    assert "外部變更" in text
    assert "清理之後還有 Live 的資源" in text
    assert "cleanup ok" not in result.stdout
    assert _disposable_dirs(hostile) == []


def test_a_same_name_same_label_replacement_is_never_touched(hostile: Hostile) -> None:
    """G1c：stack 啟動之後，兩個網路被換成同名、同標記、不同 ID 的網路（上面有外部的容器）：所有權
    紀錄的 Network ID 對不上，不刪任何 Docker 資源、不宣稱完成。"""
    hostile.set_scenario(networks_replaced=True)

    result = hostile.make()

    assert result.returncode != 0
    assert _destructive_after_up(hostile) == []
    state = hostile.docker_state()
    assert _cid("external") in {item["id"] for item in state["containers"]}
    assert set(state["networks"]) == {"secscan_live_scan_net", "secscan_live_lab_net"}
    assert not set(state["network_ids"].values()) & set(state["created"].values())
    [diagnostic] = hostile.diagnostics()
    assert "外部變更" in diagnostic.read_text(encoding="utf-8")
    assert _disposable_dirs(hostile) == []


def test_a_partial_claim_removes_only_its_own_network_by_id(hostile: Hostile) -> None:
    """G1c：scan_net 建立了、lab_net 被搶先（部分建立失敗）：只以紀錄的 ID 刪除自己的 scan_net。"""
    hostile.set_scenario(taken=["secscan_live_lab_net"])

    result = hostile.make()

    assert result.returncode != 0
    argvs = hostile.docker_argvs()
    removed = [argv[2:] for argv in argvs if argv[:2] == ["network", "rm"]]
    assert removed == [[hostile.docker_state()["created"]["secscan_live_scan_net"]]]
    assert not [argv for argv in argvs if argv[:1] == ["rm"] or "down" in argv]
    assert "--claimed" not in _cleanup_call(hostile)
    assert hostile.docker_state()["networks"] == {}
    assert hostile.diagnostics() == []


def test_an_engine_change_leaves_every_docker_resource_alone(hostile: Hostile) -> None:
    """安全 LOW-1：結束之前 Engine 換了（例如切換 context）：清理不碰任何 Docker 資源。"""
    hostile.set_scenario(engine_changes=True)

    result = hostile.make()

    assert result.returncode != 0
    assert _destructive_after_up(hostile) == []
    assert {item["service"] for item in hostile.docker_state()["containers"]} == STACK
    [diagnostic] = hostile.diagnostics()
    assert "沒有清理、也沒有核對任何 Docker 資源" in diagnostic.read_text(encoding="utf-8")
    assert _disposable_dirs(hostile) == []


# --- compose 的具名 volume 與 LIVE_ENV（資料庫審查 INFO-4）--------------------------------------

NAME_VARIABLE = re.compile(r"\$\{(?P<variable>[A-Z_]+)(?::-[^}]*)?\}")


def _live_env() -> dict[str, str]:
    match = re.search(r"^override LIVE_ENV := ((?:.*\\\n)*.*)$", MAKEFILE, flags=re.MULTILINE)
    assert match is not None
    items = match.group(1).replace("\\\n", " ").split()
    return dict(item.split("=", 1) for item in items)


def _volume_problems(volumes: Mapping[str, Any], live_env: Mapping[str, str]) -> list[str]:
    """Live 的 compose 會用到非 Live 名稱的 volume（只回傳 volume 的鍵）。

    沒有 name 的 volume 在 Live 是 secscan-live_<鍵>（專案前綴）；name 只能是 ${VAR:-預設}，而且
    LIVE_ENV 把 VAR 設成 Live 的名稱。固定的名稱或 LIVE_ENV 沒有涵蓋的變數，Live 的 up 會掛上開發的
    volume（down -v 有核對，但 up 已經用了它）。
    """
    problems = []
    for key, volume in volumes.items():
        name = (volume or {}).get("name")
        if name is None:
            continue
        match = NAME_VARIABLE.fullmatch(str(name))
        value = live_env.get(match.group("variable"), "") if match else ""
        if not value.startswith(env_guard.LIVE_RESOURCE_PREFIXES):
            problems.append(key)
    return problems


def test_every_named_volume_is_redirected_for_live() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))

    assert _volume_problems(compose["volumes"], _live_env()) == []
    # 涵蓋的不是空集合：compose 確實有以變數命名的 volume。
    assert [key for key, volume in compose["volumes"].items() if (volume or {}).get("name")]


@pytest.mark.parametrize(
    "volume",
    [
        {"name": "${SECSCAN_NEW_VOLUME:-secscan_new}"},
        {"name": "secscan_fixed"},
        {"name": "${SECSCAN_RUNS_VOLUME:-secscan_runs}-copy"},
    ],
    ids=["variable-not-in-live-env", "fixed-name", "suffix"],
)
def test_a_volume_live_would_share_with_development_is_caught(volume: dict[str, str]) -> None:
    """正向對照：新增的 volume 忘了加進 LIVE_ENV，或名稱固定時，上一個測試會失敗。"""
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))

    assert _volume_problems({**compose["volumes"], "added": volume}, _live_env()) == ["added"]
