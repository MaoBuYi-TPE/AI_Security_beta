"""runs volume 的掛載範圍與 runs-init 的設定（EVID-10；docs/DECISIONS.md §30.13）。

- 只有 runner 與 runs-init 掛載 volume 的根目錄；worker 只以 subpath 唯讀掛載 active/；其他服務
  不掛載。
- runs-init 是獨立、最小的服務：不使用 x-app，沒有環境變數、金鑰、網路與多餘的掛載。
- make runs-layout-migrate 和 make up 使用同一組 compose 設定（APP_COMPOSE），解析出來的 volume 和
  RUNNER_RUNS_VOLUME 使用同一個運算式。
實際的行為（掛載、volume 的標籤、up --wait 對一次性服務的處理）已由 Docker 驗證確認（2026-11-11，
docs/DECISIONS.md §30.13）；compose 設定中的秘密由 test_compose_secrets 檢查。
"""

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_TEXT = (ROOT / "compose.yaml").read_text(encoding="utf-8")
# yaml.safe_load 會展開 YAML 的 merge（<<: *app），檢查的是合併之後的設定。
COMPOSE: dict[str, Any] = yaml.safe_load(COMPOSE_TEXT)
SERVICES: dict[str, dict[str, Any]] = COMPOSE["services"]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
RUNS_INIT_KEYS = {
    "image",
    "pull_policy",
    "profiles",
    "user",
    "read_only",
    "cap_drop",
    "security_opt",
    "network_mode",
    "restart",
    "pids_limit",
    "mem_limit",
    "command",
    "volumes",
}


def _runs_mounts(service: dict[str, Any]) -> list[object]:
    mounts: list[object] = []
    for volume in service.get("volumes", []):
        source = volume.get("source") if isinstance(volume, dict) else str(volume).split(":")[0]
        if source == "runs":
            mounts.append(volume)
    return mounts


def _recipe(target: str) -> str:
    """target 的完整 recipe（以 tab 開頭的連續幾行）。"""
    lines = MAKEFILE.splitlines()
    [index] = [i for i, line in enumerate(lines) if line.startswith(f"{target}:")]
    recipe: list[str] = []
    for line in lines[index + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line)
    return "\n".join(recipe)


def test_only_the_runner_and_runs_init_mount_the_volume_root() -> None:
    mounts = {name: _runs_mounts(service) for name, service in SERVICES.items()}

    assert {name for name, found in mounts.items() if found} == {"runner", "runs-init", "worker"}
    assert mounts["runner"] == ["runs:/runs"]
    assert mounts["runs-init"] == ["runs:/runs"]
    assert mounts["worker"] == [
        {
            "type": "volume",
            "source": "runs",
            "target": "/runs",
            "read_only": True,
            "volume": {"subpath": "active", "nocopy": True},
        }
    ]


def test_runs_init_is_a_minimal_standalone_service() -> None:
    service = SERVICES["runs-init"]

    assert set(service) == RUNS_INIT_KEYS
    assert service["network_mode"] == "none"
    assert service["read_only"] is True
    assert service["restart"] == "no"
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["volumes"] == ["runs:/runs"]
    assert service["command"] == ["secscan-admin", "init-runs-layout"]
    assert service["profiles"] == ["app"]
    assert int(str(service["user"]).split(":")[0]) != 0
    for key in ("environment", "env_file", "secrets", "cap_add", "privileged", "devices"):
        assert key not in service


def test_runs_init_does_not_merge_the_app_anchor() -> None:
    """YAML 的 merge 會連同以後加進 x-app 的設定一起繼承，所以 runs-init 不使用 <<: *app。"""
    block = re.search(r"\n  runs-init:\n(?P<body>(?:    .*\n|\n)+?)  \S", COMPOSE_TEXT)

    assert block is not None
    assert "<<" not in block.group("body")
    assert "*app" not in block.group("body")


def test_the_runner_and_the_worker_wait_for_runs_init() -> None:
    for name in ("runner", "worker"):
        assert SERVICES[name]["depends_on"]["runs-init"] == {
            "condition": "service_completed_successfully"
        }


def test_the_volume_name_and_the_runner_setting_use_the_same_expression() -> None:
    expression = COMPOSE["volumes"]["runs"]["name"]

    assert expression == SERVICES["runner"]["environment"]["RUNNER_RUNS_VOLUME"]
    assert expression == "${SECSCAN_RUNS_VOLUME:-secscan_runs}"


def test_up_down_and_the_migration_share_the_app_compose() -> None:
    assert "\nAPP_COMPOSE = $(COMPOSE) -f $(DB_FILE) --profile app\n" in MAKEFILE
    assert _recipe("up") == "\t$(APP_COMPOSE) up -d --wait"
    assert _recipe("down") == "\t$(APP_COMPOSE) down"
    migrate = _recipe("runs-layout-migrate")
    assert "$(APP_COMPOSE) config runs-init --format json" in migrate
    assert "$(APP_COMPOSE) ps --status running --services" in migrate
    assert "$(APP_COMPOSE) run --rm --no-deps runner secscan-admin migrate-runs-layout" in migrate
    # 不覆寫環境變數、不另外指定 project，也不退回預設的 volume 名稱。
    assert " -p " not in migrate
    assert "SECSCAN_RUNS_VOLUME" not in migrate
    assert "secscan_runs" not in migrate


def test_the_migration_checks_every_container_using_the_volume() -> None:
    migrate = _recipe("runs-layout-migrate")

    assert 'docker ps -a --filter "volume=$$volume"' in migrate
    assert "com.docker.compose.project" in migrate
    assert "com.docker.compose.volume" in migrate
    assert '[ "$$labels" = "$$project runs" ]' in migrate
    assert '--expect-volume "$$volume"' in migrate


def test_only_the_migration_skips_runs_init() -> None:
    """--no-deps 會略過 runs-init：只有文件化的搬移指令使用。"""
    lines = [
        line
        for line in MAKEFILE.splitlines()
        if "--no-deps" in line and not line.lstrip().startswith("#")
    ]

    assert len(lines) == 1
    assert "migrate-runs-layout" in lines[0]


def test_the_live_stack_starts_the_whole_app_profile() -> None:
    """Live 的 stack 以 --profile app 啟動全部服務，所以也會執行 runs-init（§30.13）。"""
    assert (
        "LIVE_COMPOSE = $(LIVE_ENV) $(COMPOSE) -p $(LIVE_PROJECT) -f $(DB_FILE) --profile app"
        in (MAKEFILE)
    )
    assert "&& $(LIVE_COMPOSE) up -d --wait \\" in _recipe("test-live-runner")
