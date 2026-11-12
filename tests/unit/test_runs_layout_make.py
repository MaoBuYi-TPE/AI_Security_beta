"""make runs-layout-migrate 的主機端檢查（EVID-12；docs/DECISIONS.md §30.13）。

以 repo 的 Makefile 在 pytest 的暫存目錄中實際執行 target；docker 是放在暫存目錄、加到 PATH 最前面
的假執行檔（依情境回應、記下每次呼叫），不連 Docker。env 與 docker-check 以 -o 略過（不碰 .env）。

- 以和 make up 相同的 compose 設定解析實際的 runs volume；解析失敗不退回預設名稱。
- volume 的 compose 標籤必須是這個 project 的 runs；api、worker、runner 沒有在跑；沒有任何容器
  （含已停止的）使用它；任何 docker 指令失敗都視為無法確認。
- 不通過時不呼叫 compose run；通過時以 --no-deps 在 runner 容器內執行，並傳入 --expect-volume。
"""

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
RUN = "migrate-runs-layout"

_FAKE_DOCKER = """#!{python}
import json, os, sys
args = sys.argv[1:]
scenario = json.loads(open(os.environ["FAKE_DOCKER_SCENARIO"]).read())
with open(os.environ["FAKE_DOCKER_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
def reply(key, default=""):
    value = scenario.get(key, default)
    if value is None:
        sys.exit(1)
    sys.stdout.write(value)
    sys.exit(0)
if args[:1] == ["compose"]:
    if "config" in args:
        reply("config")
    if "ps" in args:
        reply("running")
    if "run" in args:
        sys.exit(0)
if args[:2] == ["volume", "ls"]:
    reply("volumes")
if args[:2] == ["volume", "inspect"]:
    labels = scenario.get("labels", {{}})
    if args[-1] not in labels:
        sys.exit(1)
    sys.stdout.write(labels[args[-1]] + "\\n")
    sys.exit(0)
if args[:1] == ["ps"]:
    if scenario.get("ps_fails"):
        sys.exit(1)
    users = scenario.get("users", [])
    if "-a" not in args:
        users = [user for user in users if user.endswith("Up")]
    sys.stdout.write("".join(user + "\\n" for user in users))
    sys.exit(0)
sys.exit(2)
"""


def _config(project: str = "secscan", volume: str | None = "secscan_runs") -> str:
    volumes: dict[str, Any] = {} if volume is None else {"runs": {"name": volume}}
    services = {"runs-init": {"image": "secscan:dev", "network_mode": "none"}}
    return json.dumps({"name": project, "services": services, "volumes": volumes})


def _scenario(**changes: Any) -> dict[str, Any]:
    scenario: dict[str, Any] = {
        "config": _config(),
        "volumes": "secscan_db_data\nsecscan_runs\n",
        "labels": {"secscan_runs": "secscan runs"},
        "running": "",
        "users": [],
    }
    return scenario | changes


def _make(tmp_path: Path, scenario: dict[str, Any], *extra: str) -> tuple[int, str, list[Any]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker = bin_dir / "docker"
    docker.write_text(_FAKE_DOCKER.format(python=sys.executable), encoding="utf-8")
    python = bin_dir / "python"
    python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
    for script in (docker, python):
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    (tmp_path / "scenario.json").write_text(json.dumps(scenario), encoding="utf-8")
    log = tmp_path / "docker.log"
    log.write_text("", encoding="utf-8")
    make = shutil.which("make")
    assert make is not None, "需要 make"
    result = subprocess.run(  # noqa: S603 - 固定的 make 與 Makefile；docker 是假的執行檔
        [
            make,
            "--no-print-directory",
            "-f",
            str(MAKEFILE),
            "-o",
            "env",
            "-o",
            "docker-check",
            "COMPOSE=docker compose",
            "UV_RUN=",
            *extra,
            "runs-layout-migrate",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "HOME": str(tmp_path),
            "LC_ALL": "C.UTF-8",
            "FAKE_DOCKER_SCENARIO": str(tmp_path / "scenario.json"),
            "FAKE_DOCKER_LOG": str(log),
        },
    )
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    return result.returncode, result.stdout + result.stderr, calls


def _ran(calls: list[Any]) -> list[Any]:
    return [call for call in calls if call[:1] == ["compose"] and "run" in call]


def _volumes_touched(calls: list[Any]) -> set[str]:
    touched = set()
    for call in calls:
        if call[:2] == ["volume", "inspect"]:
            touched.add(call[-1])
        if call[:1] == ["ps"]:
            touched.add(call[call.index("--filter") + 1].removeprefix("volume="))
    return touched


def test_a_checked_volume_is_migrated_in_the_runner_container(tmp_path: Path) -> None:
    code, output, calls = _make(tmp_path, _scenario())

    assert code == 0, output
    [run] = _ran(calls)
    assert run[run.index("run") :] == [
        "run",
        "--rm",
        "--no-deps",
        "runner",
        "secscan-admin",
        RUN,
        "--expect-volume",
        "secscan_runs",
    ]
    assert run[:4] == ["compose", "-f", "compose.yaml", "--profile"]
    [config] = [call for call in calls if "config" in call]
    assert config[-4:] == ["config", "runs-init", "--format", "json"]


def test_dry_run_is_passed_to_the_command(tmp_path: Path) -> None:
    code, output, calls = _make(tmp_path, _scenario(), "DRY_RUN=1")

    assert code == 0, output
    [run] = _ran(calls)
    assert run[-1] == "--dry-run"


def test_a_custom_volume_name_from_env_is_the_one_checked_and_migrated(tmp_path: Path) -> None:
    """.env 指定非預設的名稱、預設的 volume 也同時存在：只檢查與搬移實際使用的那一個。"""
    scenario = _scenario(
        config=_config(volume="custom_runs"),
        volumes="secscan_runs\ncustom_runs\n",
        labels={"secscan_runs": "secscan runs", "custom_runs": "secscan runs"},
    )

    code, output, calls = _make(tmp_path, scenario)

    assert code == 0, output
    assert _volumes_touched(calls) == {"custom_runs"}
    [run] = _ran(calls)
    assert run[-2:] == ["--expect-volume", "custom_runs"]


@pytest.mark.parametrize(
    "changes",
    [
        {"config": _config(project="renamed")},
        {"labels": {"secscan_runs": "other runs"}},
        {"labels": {"secscan_runs": "secscan data"}},
        {"labels": {"secscan_runs": " "}},
    ],
    ids=["project-renamed", "other-project", "other-volume", "no-labels"],
)
def test_a_volume_from_another_deployment_is_refused(
    tmp_path: Path, changes: dict[str, Any]
) -> None:
    """compose 的 project name 改了，或 volume 不是由這個 project 的 runs 建立：拒絕。"""
    code, output, calls = _make(tmp_path, _scenario(**changes))

    assert code != 0
    assert "拒絕搬移" in output
    assert _ran(calls) == []


@pytest.mark.parametrize(
    "changes",
    [
        {"config": None},
        {"config": "not json"},
        {"config": _config(volume=None)},
        {"config": json.dumps({"services": {}, "volumes": {"runs": {"name": "secscan_runs"}}})},
        {"config": _config(volume="-bad name")},
    ],
    ids=["config-fails", "not-json", "no-volume", "no-project", "bad-name"],
)
def test_an_unresolved_volume_never_falls_back_to_the_default(
    tmp_path: Path, changes: dict[str, Any]
) -> None:
    code, output, calls = _make(tmp_path, _scenario(**changes))

    assert code != 0
    assert "拒絕搬移" in output
    assert _volumes_touched(calls) == set()
    assert _ran(calls) == []


def test_a_missing_volume_needs_no_migration(tmp_path: Path) -> None:
    code, output, calls = _make(tmp_path, _scenario(volumes="secscan_db_data\n", labels={}))

    assert code == 0, output
    assert "不存在" in output
    assert _ran(calls) == []


@pytest.mark.parametrize(
    "users",
    [
        ["secscan-run-6f1c2d3e-4b5a-4c6d-8e7f-001122334455 Up"],
        ["secscan-worker-1 Exited (0) 2 days ago"],
        ["secscan-runner-run-1a2b Created"],
    ],
    ids=["scan-container", "stopped-worker", "stopped-admin-command"],
)
def test_any_container_using_the_volume_blocks_the_migration(
    tmp_path: Path, users: list[str]
) -> None:
    """審查的反例：還有一次性掃描容器，或已停止的容器（重新啟動時會以舊設定掛載根目錄）。"""
    code, output, calls = _make(tmp_path, _scenario(users=users))

    assert code != 0
    assert users[0].split()[0] in output
    assert _ran(calls) == []
    [ps] = [call for call in calls if call[:1] == ["ps"]]
    assert "-a" in ps


@pytest.mark.parametrize(
    "changes",
    [
        {"ps_fails": True},
        {"volumes": None},
        {"running": None},
        {"labels": {}},
    ],
    ids=["ps-fails", "volume-ls-fails", "compose-ps-fails", "inspect-fails"],
)
def test_a_failing_docker_command_is_not_a_pass(tmp_path: Path, changes: dict[str, Any]) -> None:
    code, output, calls = _make(tmp_path, _scenario(**changes))

    assert code != 0
    assert "拒絕搬移" in output
    assert _ran(calls) == []


@pytest.mark.parametrize("service", ["api", "worker", "runner"])
def test_running_services_block_the_migration(tmp_path: Path, service: str) -> None:
    code, output, calls = _make(tmp_path, _scenario(running=f"guard\n{service}\n"))

    assert code != 0
    assert "make down" in output
    assert _ran(calls) == []
