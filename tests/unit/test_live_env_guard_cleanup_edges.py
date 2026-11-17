"""tests/live/env_guard.py 的清理：第二輪重新審查的補強（程式碼 LOW-1；安全 LOW-1、LOW-2 (c)、
INFO-1、INFO-2、INFO-4）。

替身（CleanupDocker）與 helper 沿用 tests/unit/test_live_env_guard_cleanup.py：不連 daemon。
"""

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.live import env_guard
from tests.live.env_guard import GuardError
from tests.unit.test_live_env_guard_cleanup import (
    ENGINE,
    GUARD,
    LAB,
    LIVE_CONFIG,
    OTHER,
    OWNER,
    RECEIVER,
    SCAN,
    CleanupDocker,
    _clean,
    _has,
    _run_dir,
    container,
    stack,
)


def test_the_fake_refuses_duplicate_ids_positive_control() -> None:
    """替身在同一次呼叫中重複、或之前已刪除過同一個 ID 時都失敗：上一個測試通過，代表每個容器
    只刪除一次（不論是否在同一次呼叫中）。"""
    docker = CleanupDocker()

    with pytest.raises(GuardError, match="already in progress"):
        docker(["rm", "-f", "-v", GUARD, GUARD])
    docker(["rm", "-f", "-v", RECEIVER])
    with pytest.raises(GuardError, match="already in progress"):
        docker(["rm", "-f", "-v", RECEIVER])


def test_a_partly_vanished_claim_deletes_nothing(tmp_path: Path) -> None:
    """程式碼 LOW-1：記錄了所有權，lab_net 卻不見了（外部變更）：仍屬於這次的 scan_net 上的容器也
    不刪除，不 down、不刪網路，以失敗回報。"""
    docker = CleanupDocker(networks={SCAN: OWNER})

    report = _clean(tmp_path, docker, claimed=True)

    assert _has(report, "沒有刪除任何 Docker 資源")
    assert _has(report, "清理之後還有 Live 的資源")
    assert docker.destructive() == []
    assert docker.networks == {SCAN: OWNER}


def test_without_a_claim_containers_on_its_own_network_are_not_removed(tmp_path: Path) -> None:
    """安全審查第三次的 LOW-1：沒有取得所有權的執行沒有啟動任何容器，網路上的容器都不是它的：
    不刪容器、不 down，網路也留著（fail closed）。"""
    probe = container("probe", SCAN, project="")
    docker = CleanupDocker(
        networks={SCAN: OWNER, LAB: OTHER}, containers=[probe], volumes={}, compose_networks=()
    )

    report = _clean(tmp_path, docker, claimed=False)

    assert docker.destructive() == []
    assert docker.networks == {SCAN: OWNER, LAB: OTHER}
    assert _has(report, f"網路 {SCAN} 上還有容器")


def test_without_a_claim_even_both_own_networks_are_not_brought_down(tmp_path: Path) -> None:
    """兩個網路都標記這次的識別、卻沒有記錄所有權（例如 networks 與 claimed=1 之間被中斷，或
    剩餘風險 25 的識別碰撞）：stack 不是這次啟動的，不刪容器、不 down。"""
    docker = CleanupDocker()

    report = _clean(tmp_path, docker, claimed=False)

    assert docker.destructive() == []
    assert _has(report, "上還有容器")


def test_a_container_also_on_an_unrelated_live_style_network_is_not_removed(
    tmp_path: Path,
) -> None:
    """安全 LOW-2 (c)：接在這次的網路與任意的 secscan-live_* 網路上：不刪除（接的網路必須全部屬於
    這次執行）。"""
    odd = container("odd", LAB, "secscan-live_evil", project="")
    docker = CleanupDocker(containers=[*stack(), odd])

    report = _clean(tmp_path, docker)

    assert odd["id"] not in docker.removed()
    assert _has(report, f"容器 {odd['id'][:12]} 接在不屬於這次執行的網路上")
    assert LAB in docker.networks


@pytest.mark.parametrize("project", ["<no value>", "secscan-live ", " "])
def test_project_labels_are_compared_exactly(tmp_path: Path, project: str) -> None:
    """安全 INFO-2：專案標記以 JSON 精確比對：字面的 "<no value>"、多了空白的 Live 都不算。"""
    odd = container("odd", LAB, project=project)
    docker = CleanupDocker(containers=[*stack(), odd])

    report = _clean(tmp_path, docker)

    assert odd["id"] not in docker.removed()
    assert _has(report, f"其他 compose 專案的容器 {odd['id'][:12]}")


def test_a_null_project_label_means_no_label(tmp_path: Path) -> None:
    """安全審查第三次的 MEDIUM-1：沒有 Labels 的容器，json 可能輸出 null（推論；實測缺少 key 時是
    ""）。標記的值一定是字串，null 只可能是沒有標記：接收端照常刪除。"""
    docker = CleanupDocker(facts={RECEIVER: f"{RECEIVER}|null|{LAB} \n"})

    report = _clean(tmp_path, docker)

    assert RECEIVER in docker.removed()
    assert report.failures == []


def test_containers_are_inspected_as_containers(tmp_path: Path) -> None:
    """安全 INFO-2：inspect 帶 --type container（64 碼的 ID 不會被解析成其他種類的物件）。"""
    docker = CleanupDocker()

    _clean(tmp_path, docker)

    inspected = [call for call in docker.calls if call[:1] == ["inspect"]]
    assert inspected
    assert all(call[1:3] == ["--type", "container"] for call in inspected)


class SwitchingEngine(CleanupDocker):
    """第一次 info 之後回報另一個 Engine（例如清理期間切換了 context）。"""

    def __call__(self, arguments: Sequence[str]) -> str:
        result = super().__call__(arguments)
        if list(arguments[:1]) == ["info"]:
            self.engine_id = "engine-2"
        return result


def test_the_engine_is_confirmed_again_before_compose_down(tmp_path: Path) -> None:
    """安全 INFO-1：清理開始之後 Engine 換了：不 down、不刪網路，之後也不再核對（會打到別的
    Engine）。"""
    docker = SwitchingEngine()

    report = _clean(tmp_path, docker)

    assert _has(report, "compose down 之前：已刪除 Live 網路上確認過的容器，之後停止")
    assert not [call for call in docker.calls if "down" in call]
    assert not [call for call in docker.calls if call[:2] == ["network", "rm"]]
    last_info = max(index for index, call in enumerate(docker.calls) if call[:1] == ["info"])
    assert docker.calls[last_info + 1 :] == []


@pytest.mark.parametrize(
    "changes",
    [
        {"volumes": {"runs": None}},
        {"volumes": ["runs"]},
        {"networks": {"default": "secscan-live_default"}},
    ],
    ids=["volume-null", "volumes-list", "network-string"],
)
def test_an_unexpected_compose_config_shape_is_reported_not_raised(
    tmp_path: Path, changes: dict[str, Any]
) -> None:
    """安全 LOW-1：compose 的 JSON 形狀不是預期的 mapping：記為問題、不 down，清理繼續（網路、
    拋棄式目錄、殘留檢查），不以例外中斷。"""
    docker = CleanupDocker(config={**LIVE_CONFIG, **changes})

    report = _clean(tmp_path, docker)

    assert not [call for call in docker.calls if "down" in call]
    assert _has(report, "形狀不正確")
    assert _has(report, "清理之後還有 Live 的資源")


def test_an_interrupted_cleanup_leaves_a_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """安全 INFO-4：清理被中斷（例如第二次 Ctrl-C）：留下診斷檔、以失敗結束、沒有 traceback。"""
    directory = _run_dir(tmp_path)
    docker = CleanupDocker()

    def interrupted(arguments: Sequence[str]) -> str:
        if "down" in arguments:
            raise KeyboardInterrupt
        return docker(arguments)

    monkeypatch.setattr(env_guard, "docker", interrupted)

    code = env_guard.main(
        [
            *("cleanup", "--base", str(tmp_path), "--secrets-dir", str(directory)),
            *("--engine", ENGINE, "--claimed"),
        ]
    )

    err = capsys.readouterr().err
    [diagnostic] = tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")
    assert code == env_guard.EXIT_FAILURE
    assert "被中斷" in err
    assert "Traceback" not in err
    assert "清理被中斷" in diagnostic.read_text(encoding="utf-8")


def test_an_unexpected_error_in_cleanup_leaves_a_diagnostic_and_is_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """安全審查第三次的 INFO-2：程式本身的錯誤照樣以 traceback 結束（不吞掉），但先留下診斷檔。"""
    directory = _run_dir(tmp_path)
    docker = CleanupDocker()

    def broken(arguments: Sequence[str]) -> str:
        if "config" in arguments:
            raise TypeError("程式本身的錯誤")
        return docker(arguments)

    monkeypatch.setattr(env_guard, "docker", broken)

    with pytest.raises(TypeError):
        env_guard.main(
            [
                *("cleanup", "--base", str(tmp_path), "--secrets-dir", str(directory)),
                *("--engine", ENGINE, "--claimed"),
            ]
        )

    [diagnostic] = tmp_path.glob(f"{env_guard.DIAGNOSTIC_PREFIX}*")
    assert "未預期的錯誤（TypeError）" in diagnostic.read_text(encoding="utf-8")
