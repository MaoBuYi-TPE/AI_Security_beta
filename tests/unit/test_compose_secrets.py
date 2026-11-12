"""compose 設定中的秘密：只出現在需要它的服務自己的 environment（docs/DECISIONS.md §30.13 的 F1）。

docker compose config 即使只查詢一個服務，也會輸出全部頂層的 x-*，而且是替換變數之後的值。
make runs-layout-migrate 以 config runs-init --format json 解析 runs volume，所以秘密放在 x-* 就會
出現在那份輸出中（Docker 驗證發現 x-app-env 的 DB_PASSWORD）。

- 靜態檢查（yaml.safe_load 會展開 merge）：頂層的 x-*、volumes、networks 都不引用秘密；每個服務只在
  environment 中引用自己需要的秘密（最小權限，延伸 KEY-02）；api、runner、worker 的 DB 連線設定
  不變。
- 實際解析：以真的 docker compose CLI、暫存的 project directory 與虛構的秘密執行 config。不讀 repo
  的 .env（project directory 與 --env-file 都指向暫存目錄），也不連 Docker daemon（DOCKER_HOST
  指向不存在的 socket）；失敗訊息只有變數或服務的名稱，不含值。沒有安裝 docker compose 時 skip，
  靜態檢查仍然執行。
"""

import json
import os
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from secscan.cli.runs_volume import parse
from tests.isolation import BLOCKED_DOCKER_HOST

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "compose.yaml"
COMPOSE_TEXT = COMPOSE_FILE.read_text(encoding="utf-8")
COMPOSE: dict[str, Any] = yaml.safe_load(COMPOSE_TEXT)
SERVICES: dict[str, dict[str, Any]] = COMPOSE["services"]
APP_SERVICES = ("api", "runner", "worker")

# 必須來自 .env（${VAR:?…}，沒有預設值）的變數，就是 compose 中的全部秘密。
SECRET_VARIABLES = frozenset(
    {
        "DB_PASSWORD",
        "DB_ADMIN_PASSWORD",
        "TEST_DB_PASSWORD",
        "SECRET_ENCRYPTION_KEYS",
        "CONTENT_ENCRYPTION_KEYS",
        "EVIDENCE_ENCRYPTION_KEYS",
    }
)
# 每個服務可以取得的秘密；沒列出的服務（runs-init、guard、socket-proxy）一個都沒有。
SERVICE_SECRETS: dict[str, set[str]] = {
    "db": {"DB_ADMIN_PASSWORD", "DB_PASSWORD"},
    "db-test": {"TEST_DB_PASSWORD"},
    "api": {"DB_PASSWORD", "SECRET_ENCRYPTION_KEYS", "CONTENT_ENCRYPTION_KEYS"},
    "runner": {"DB_PASSWORD", "SECRET_ENCRYPTION_KEYS", "EVIDENCE_ENCRYPTION_KEYS"},
    "worker": {"DB_PASSWORD", "CONTENT_ENCRYPTION_KEYS"},
}
REQUIRED = "請先執行 make env 產生 .env"
# api、runner、worker 連 DB 的設定（移動 DB_PASSWORD 之前就是這些值）。
DATABASE_SETTINGS = {
    "DB_HOST": "db",
    "DB_PORT": "5432",
    "DB_NAME": "${DB_NAME:-secscan}",
    "DB_USER": "${DB_USER:-secscan_app}",
    "DB_PASSWORD": f"${{DB_PASSWORD:?{REQUIRED}}}",
}
_REFERENCE = re.compile(r"\$\{([A-Z0-9_]+)")


def _secrets(node: object) -> set[str]:
    """node 之中引用的秘密變數。"""
    text = json.dumps(node, ensure_ascii=False)
    return {name for name in _REFERENCE.findall(text) if name in SECRET_VARIABLES}


def test_the_required_variables_are_exactly_the_known_secrets() -> None:
    """新增必填的變數時，必須在這裡分類並決定哪些服務可以取得。"""
    assert set(re.findall(r"\$\{([A-Z0-9_]+):\?", COMPOSE_TEXT)) == SECRET_VARIABLES


@pytest.mark.parametrize("section", sorted(key for key in COMPOSE if key != "services"))
def test_no_top_level_section_references_a_secret(section: str) -> None:
    assert _secrets(COMPOSE[section]) == set()


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_each_service_references_only_its_own_secrets(name: str) -> None:
    service = SERVICES[name]
    outside = {key: value for key, value in service.items() if key != "environment"}

    assert _secrets(service.get("environment", {})) == SERVICE_SECRETS.get(name, set())
    assert _secrets(outside) == set()


@pytest.mark.parametrize("name", APP_SERVICES)
def test_app_services_keep_their_database_connection(name: str) -> None:
    environment = SERVICES[name]["environment"]

    assert {key: environment.get(key) for key in DATABASE_SETTINGS} == DATABASE_SETTINGS


def test_the_database_creates_the_role_the_app_services_use() -> None:
    """db 初始化時建立的角色、密碼與資料庫，和 api、runner、worker 連線用的是同一組運算式。"""
    environment = SERVICES["db"]["environment"]

    assert environment["SECSCAN_APP_DB_USER"] == DATABASE_SETTINGS["DB_USER"]
    assert environment["SECSCAN_APP_DB_PASSWORD"] == DATABASE_SETTINGS["DB_PASSWORD"]
    assert environment["SECSCAN_APP_DB_NAME"] == DATABASE_SETTINGS["DB_NAME"]


# --- 以真的 docker compose 解析（虛構的秘密、暫存的 project directory、不連 daemon）-------------


def _environment(home: str) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": home,
        "LC_ALL": "C.UTF-8",
        "DOCKER_HOST": BLOCKED_DOCKER_HOST,
    }


def _compose_command() -> list[str]:
    cli = shutil.which("docker")
    if cli is None:
        pytest.skip("沒有安裝 docker CLI")
    command = [cli, "compose"]
    # 固定的指令，沒有外部輸入；compose 是 docker CLI 的 plugin，要從 HOME 底下找到。
    probe = subprocess.run(  # noqa: S603
        [*command, "version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env=_environment(os.environ.get("HOME", "")),
    )
    if probe.returncode != 0:
        pytest.skip("沒有 docker compose")
    return command


@pytest.fixture
def fake_project(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """只含虛構秘密的 .env；compose 只從 project directory 讀 .env，不會讀到 repo 的 .env。"""
    canaries = {
        name: f"canary-{name.lower().replace('_', '-')}-{secrets.token_hex(8)}"
        for name in sorted(SECRET_VARIABLES)
    }
    env_file = tmp_path / ".env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in canaries.items()), encoding="utf-8")
    return tmp_path, canaries


def _config(project_dir: Path, *services: str) -> dict[str, Any]:
    """和 make runs-layout-migrate 相同的 compose 設定（-f compose.yaml --profile app）。

    project directory 與 --env-file 都指向暫存目錄：只讀虛構的 .env，雙重確保不會讀到 repo 的 .env。
    """
    # 固定的 docker compose 與 repo 的 compose.yaml；project directory 是 pytest 的暫存目錄。
    result = subprocess.run(  # noqa: S603
        [
            *_compose_command(),
            "--project-directory",
            str(project_dir),
            "--env-file",
            str(project_dir / ".env"),
            "-f",
            str(COMPOSE_FILE),
            "--profile",
            "app",
            "config",
            *services,
            "--format",
            "json",
        ],
        cwd=project_dir,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env=_environment(os.environ.get("HOME", "")),
    )
    assert result.returncode == 0, result.stderr
    config: dict[str, Any] = json.loads(result.stdout)
    return config


def _leaked(node: object, canaries: dict[str, str]) -> set[str]:
    text = json.dumps(node, ensure_ascii=False)
    return {name for name, value in canaries.items() if value in text}


def test_the_config_used_by_the_migration_contains_no_secret(
    fake_project: tuple[Path, dict[str, str]],
) -> None:
    project_dir, canaries = fake_project
    config = _config(project_dir, "runs-init")

    assert _leaked(config, canaries) == set()
    assert parse(json.dumps(config)) == ("secscan", "secscan_runs")


def test_runs_init_resolves_to_the_minimal_service(
    fake_project: tuple[Path, dict[str, str]],
) -> None:
    project_dir, _ = fake_project
    service = _config(project_dir, "runs-init")["services"]["runs-init"]

    assert service["network_mode"] == "none"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["user"] == "10001:10001"
    assert service["restart"] == "no"
    assert service["command"] == ["secscan-admin", "init-runs-layout"]
    mounts = [(m["type"], m["source"], m["target"]) for m in service["volumes"]]
    assert mounts == [("volume", "runs", "/runs")]
    for key in ("environment", "env_file", "secrets", "cap_add", "privileged", "devices"):
        assert key not in service, key
    for key in ("ports", "networks", "tmpfs", "depends_on"):
        assert key not in service, key


def test_each_resolved_service_gets_only_its_own_secrets(
    fake_project: tuple[Path, dict[str, str]],
) -> None:
    project_dir, canaries = fake_project
    config = _config(project_dir)

    for section, value in config.items():
        if section != "services":
            assert _leaked(value, canaries) == set(), section
    for name, service in config["services"].items():
        assert _leaked(service, canaries) == SERVICE_SECRETS.get(name, set()), name
    for name in APP_SERVICES:
        environment = config["services"][name]["environment"]
        # 先算成布林值：失敗時 pytest 不會印出密碼的值（萬一讀到的不是虛構的 .env）。
        uses_the_fake_password = environment.get("DB_PASSWORD") == canaries["DB_PASSWORD"]
        assert uses_the_fake_password, name
        assert environment["DB_HOST"] == "db", name
        assert environment["DB_PORT"] == "5432", name
        assert environment["DB_NAME"] == "secscan", name
        assert environment["DB_USER"] == "secscan_app", name
