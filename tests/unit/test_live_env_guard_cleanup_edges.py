"""tests/live/env_guard.py 的清理：第二輪重新審查的補強（程式碼 LOW-1；安全 LOW-1、LOW-2 (c)、
INFO-1、INFO-2、INFO-4）。

替身（CleanupDocker）與 helper 沿用 tests/unit/test_live_env_guard_cleanup.py：不連 daemon。
"""

from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from tests.live import env_guard
from tests.unit.test_live_env_guard_cleanup import (
    ENGINE,
    LAB,
    LIVE_CONFIG,
    OWNER,
    SCAN,
    CleanupDocker,
    _clean,
    _has,
    _run_dir,
    container,
    stack,
)


def test_a_partly_vanished_claim_deletes_nothing(tmp_path: Path) -> None:
    """程式碼 LOW-1：記錄了所有權，lab_net 卻不見了（外部變更）：仍屬於這次的 scan_net 上的容器也
    不刪除，不 down、不刪網路，以失敗回報。"""
    docker = CleanupDocker(networks={SCAN: OWNER})

    report = _clean(tmp_path, docker, claimed=True)

    assert _has(report, "沒有刪除任何 Docker 資源")
    assert _has(report, "清理之後還有 Live 的資源")
    assert docker.destructive() == []
    assert docker.networks == {SCAN: OWNER}


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

    assert _has(report, "compose down 之前")
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
