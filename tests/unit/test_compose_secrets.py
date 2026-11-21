"""compose secrets（CSEC-01、CSEC-02、CSEC-11；T23b-b2，docs/DECISIONS.md §32）。

秘密不再以環境變數傳入容器：頂層的 secrets 都是 `file:`（make secrets 由 .env 產生 secrets/），
每個服務以 `secrets:` 只掛載自己需要的那幾個（/run/secrets/<名稱>，唯讀），environment 只有
`*_FILE` 的路徑。

- 靜態檢查（yaml.safe_load 會展開 merge）：分配矩陣、`*_FILE` 的對應、對照表（cli/secret_files.py）
  與 compose 完全一致；environment 與頂層的 x-* 都沒有秘密的名稱、值或插值；沒有 include、
  extends.file、configs、env_file。
- 實際解析：以真的 docker compose CLI、暫存的 project directory 與 canary 執行 config（只在用戶端
  解析，不連 Docker daemon：DOCKER_HOST 指向不存在的 socket）。canary 同時放在 .env 與秘密檔：真正
  會發生的回歸是有人把 ${DB_PASSWORD} 插值回來，只有 .env 的 canary 抓得到。正向對照：
  config --environment 必須含 .env 的 canary（證明 canary 確實載入）。失敗訊息只有名稱，不含值。
  沒有安裝 docker compose 時 skip，靜態檢查仍然執行。

這些都不是容器部署的驗收：實際的掛載與容器內的讀取在 G3 的 Live（CSEC-L1、L2）驗證。

PYTEST_DONT_REWRITE：這個模組處理秘密、canary、環境變數或設定錯誤；不改寫 assert，失敗時只顯示
原始碼與（只有名稱的）訊息，不顯示運算元的值（G1 審查）。
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
from secscan.cli.secret_files import CONTAINER_SECRETS_DIR, SECRET_FILES
from secscan.migrations.credentials import DEFAULT_OWNER_USER
from tests.isolation import BLOCKED_DOCKER_HOST

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "compose.yaml"
COMPOSE_TEXT = COMPOSE_FILE.read_text(encoding="utf-8")
COMPOSE: dict[str, Any] = yaml.safe_load(COMPOSE_TEXT)
SERVICES: dict[str, dict[str, Any]] = COMPOSE["services"]
APP_SERVICES = ("api", "runner", "worker")
SECRETS_DIR_VARIABLE = "SECSCAN_SECRETS_DIR"
REQUIRED = "請以 make 執行（Makefile 設定 SECSCAN_SECRETS_DIR）"
FILE_NAMES = frozenset(item.file_name for item in SECRET_FILES)
# 主機上 .env 的名稱，以及 b2 之前 compose 傳給容器的名稱：environment 一個都不能有。
SECRET_NAMES = frozenset(
    {
        *(item.env_name for item in SECRET_FILES),
        "POSTGRES_PASSWORD",
        "SECSCAN_OWNER_DB_PASSWORD",
        "SECSCAN_APP_DB_PASSWORD",
    }
)
# 分配矩陣（計畫 §2.2）：每個服務掛載的秘密；沒列出的服務（runs-init、guard、socket-proxy）沒有。
SERVICE_SECRETS: dict[str, set[str]] = {
    "db": {"db_admin_password", "db_owner_password", "db_password"},
    "db-test": {"test_db_password"},
    "api": {"db_password", "secret_encryption_keys", "content_encryption_keys"},
    "runner": {"db_password", "secret_encryption_keys", "evidence_encryption_keys"},
    "worker": {"db_password", "content_encryption_keys"},
}
# 每個 *_FILE 指向的秘密。
FILE_SETTINGS: dict[str, dict[str, str]] = {
    "db": {
        "POSTGRES_PASSWORD_FILE": "db_admin_password",
        "SECSCAN_OWNER_DB_PASSWORD_FILE": "db_owner_password",
        "SECSCAN_APP_DB_PASSWORD_FILE": "db_password",
    },
    "db-test": {"POSTGRES_PASSWORD_FILE": "test_db_password"},
    "api": {
        "DB_PASSWORD_FILE": "db_password",
        "SECRET_ENCRYPTION_KEYS_FILE": "secret_encryption_keys",
        "CONTENT_ENCRYPTION_KEYS_FILE": "content_encryption_keys",
    },
    "runner": {
        "DB_PASSWORD_FILE": "db_password",
        "SECRET_ENCRYPTION_KEYS_FILE": "secret_encryption_keys",
        "EVIDENCE_ENCRYPTION_KEYS_FILE": "evidence_encryption_keys",
    },
    "worker": {
        "DB_PASSWORD_FILE": "db_password",
        "CONTENT_ENCRYPTION_KEYS_FILE": "content_encryption_keys",
    },
}
# api、runner、worker 連 DB 的設定（密碼改成 DB_PASSWORD_FILE 之外，和 b2 之前相同）。
DATABASE_SETTINGS = {
    "DB_HOST": "db",
    "DB_PORT": "5432",
    "DB_NAME": "${DB_NAME:-secscan}",
    "DB_USER": "${DB_USER:-secscan_app}",
}
_INTERPOLATION = re.compile(r"\$\{([A-Za-z0-9_]+)")


def _path(name: str) -> str:
    return f"{CONTAINER_SECRETS_DIR}/{name}"


def _secret_like(name: str) -> bool:
    """名稱看起來是秘密（不分大小寫）：PASSWORD 或 ENCRYPTION_KEYS，但不是 *_FILE 的路徑設定。"""
    upper = name.upper()
    return ("PASSWORD" in upper or "ENCRYPTION_KEYS" in upper) and not upper.endswith("_FILE")


# --- 靜態檢查 ----------------------------------------------------------------------------------


def test_the_top_level_secrets_are_the_seven_files() -> None:
    expected = {
        name: {"file": f"${{{SECRETS_DIR_VARIABLE}:?{REQUIRED}}}/{name}"} for name in FILE_NAMES
    }

    assert COMPOSE["secrets"] == expected


def test_the_secrets_directory_is_the_only_required_variable() -> None:
    """D16：沒有設定或是空字串時，compose 在解析階段就失敗，不會退回開發的 ./secrets。"""
    assert set(re.findall(r"\$\{([A-Z0-9_]+):\?", COMPOSE_TEXT)) == {SECRETS_DIR_VARIABLE}
    assert f"${{{SECRETS_DIR_VARIABLE}:-" not in COMPOSE_TEXT
    assert f"${{{SECRETS_DIR_VARIABLE}-" not in COMPOSE_TEXT


def test_the_mapping_table_matches_compose() -> None:
    """CSEC-11：.env 的名稱、secrets/ 的檔名、容器內的路徑只定義在 cli/secret_files.py。"""
    assert set(COMPOSE["secrets"]) == FILE_NAMES
    assert len(FILE_NAMES) == len(SECRET_FILES) == 7
    for item in SECRET_FILES:
        assert item.container_path == _path(item.file_name)
    for name in APP_SERVICES:
        environment = SERVICES[name]["environment"]
        for item in SECRET_FILES:
            setting = f"{item.env_name}_FILE"
            if setting in environment:
                assert environment[setting] == item.container_path, (name, setting)


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_each_service_mounts_only_its_own_secrets(name: str) -> None:
    mounted = SERVICES[name].get("secrets", [])

    assert all(isinstance(entry, str) for entry in mounted)
    assert set(mounted) == SERVICE_SECRETS.get(name, set())
    assert len(mounted) == len(set(mounted))


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_file_settings_point_at_mounted_secrets(name: str) -> None:
    environment = SERVICES[name].get("environment", {})
    files = {key: value for key, value in environment.items() if key.endswith("_FILE")}

    assert files == {key: _path(value) for key, value in FILE_SETTINGS.get(name, {}).items()}
    for value in files.values():
        assert value.removeprefix(f"{CONTAINER_SECRETS_DIR}/") in SERVICE_SECRETS[name]


@pytest.mark.parametrize("name", sorted(SERVICES))
def test_no_environment_carries_a_secret(name: str) -> None:
    environment = SERVICES[name].get("environment", {})
    text = json.dumps(environment, ensure_ascii=False)

    assert {key for key in environment if _secret_like(key)} == set()
    assert {key for key in environment if key.upper() in SECRET_NAMES} == set()
    assert {ref for ref in _INTERPOLATION.findall(text) if _secret_like(ref)} == set()


@pytest.mark.parametrize("section", sorted(key for key in COMPOSE if key.startswith("x-")))
def test_no_extension_section_carries_secrets(section: str) -> None:
    text = json.dumps(COMPOSE[section], ensure_ascii=False)

    assert "secrets" not in COMPOSE[section]
    assert {ref for ref in _INTERPOLATION.findall(text) if _secret_like(ref)} == set()
    assert "/run/secrets" not in text


def test_the_app_role_password_is_shared_by_the_database_and_the_app_services() -> None:
    """保留 b2 之前的不變式：initdb 建立的應用程式角色，和 api、runner、worker 使用同一個密碼檔；
    owner 的密碼檔只給 db。"""
    db = SERVICES["db"]["environment"]

    assert db["SECSCAN_APP_DB_PASSWORD_FILE"] == _path("db_password")
    assert db["SECSCAN_OWNER_DB_PASSWORD_FILE"] == _path("db_owner_password")
    assert db["SECSCAN_OWNER_DB_USER"] == f"${{DB_OWNER_USER:-{DEFAULT_OWNER_USER}}}"
    assert db["SECSCAN_APP_DB_USER"] == DATABASE_SETTINGS["DB_USER"]
    assert db["SECSCAN_APP_DB_NAME"] == DATABASE_SETTINGS["DB_NAME"]
    for name in APP_SERVICES:
        environment = SERVICES[name]["environment"]
        assert environment["DB_PASSWORD_FILE"] == _path("db_password"), name
        assert {key: environment.get(key) for key in DATABASE_SETTINGS} == DATABASE_SETTINGS


@pytest.mark.parametrize("name", APP_SERVICES)
def test_app_services_never_see_the_owner_or_the_superuser(name: str) -> None:
    """ROLE-07（不分大小寫）：environment 與 secrets 都沒有 owner、admin 的秘密。"""
    service = SERVICES[name]
    names = [*service.get("environment", {}), *service.get("secrets", [])]

    assert [entry for entry in names if "owner" in entry.lower() or "admin" in entry.lower()] == []


def test_no_service_loads_other_configuration() -> None:
    """修正 16：不得以 include、extends.file、configs、env_file 載入其他的設定或秘密。"""
    assert "include" not in COMPOSE
    assert "configs" not in COMPOSE
    for name, service in SERVICES.items():
        for key in ("env_file", "configs"):
            assert key not in service, (name, key)
        extends = service.get("extends")
        assert not (isinstance(extends, dict) and "file" in extends), name


# --- 以真的 docker compose 解析（canary、暫存的 project directory、不連 daemon）-------------------


def _environment(home: str, **extra: str) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": home,
        "LC_ALL": "C.UTF-8",
        "DOCKER_HOST": BLOCKED_DOCKER_HOST,
        **extra,
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


class FakeProject:
    """暫存的 project directory：.env 與秘密檔都是 canary（兩者不同），不讀 repo 的 .env。"""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.secrets_dir = root / "secrets"
        self.secrets_dir.mkdir(mode=0o700)
        # 只放秘密的名稱：DB_OWNER_USER 等角色名稱本來就會插值進 db 的設定，不是秘密。
        self.env_canaries = {name: f"env-{secrets.token_hex(12)}" for name in sorted(SECRET_NAMES)}
        self.file_canaries = {name: f"file-{secrets.token_hex(12)}" for name in sorted(FILE_NAMES)}
        (root / ".env").write_text(
            "".join(f"{key}={value}\n" for key, value in self.env_canaries.items()),
            encoding="utf-8",
        )
        for name, value in self.file_canaries.items():
            path = self.secrets_dir / name
            path.write_text(value, encoding="ascii")
            path.chmod(0o600)

    def canaries(self) -> dict[str, str]:
        return self.env_canaries | self.file_canaries

    def run(self, *args: str, secrets_dir: str | None) -> subprocess.CompletedProcess[str]:
        """和 make up 相同的設定（-f compose.yaml --profile app）。

        project directory 與 --env-file 都指向暫存目錄：只讀 canary 的 .env，不會讀到 repo 的 .env。
        """
        extra = {} if secrets_dir is None else {SECRETS_DIR_VARIABLE: secrets_dir}
        # 固定的 docker compose 與 repo 的 compose.yaml；project directory 是 pytest 的暫存目錄。
        return subprocess.run(  # noqa: S603
            [
                *_compose_command(),
                "--project-directory",
                str(self.root),
                "--env-file",
                str(self.root / ".env"),
                "-f",
                str(COMPOSE_FILE),
                "--profile",
                "app",
                "--profile",
                "test",
                "config",
                *args,
            ],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
            env=_environment(os.environ.get("HOME", ""), **extra),
        )

    def config(self, *args: str) -> str:
        result = self.run(*args, secrets_dir=str(self.secrets_dir))
        assert result.returncode == 0, _leaked(result.stderr, self.canaries())
        return result.stdout


@pytest.fixture
def project(tmp_path: Path) -> FakeProject:
    return FakeProject(tmp_path)


def _leaked(text: str, canaries: dict[str, str]) -> set[str]:
    """只回傳名稱：失敗時 pytest 不會印出 canary 的值。"""
    return {name for name, value in canaries.items() if value in text}


def test_config_contains_no_secret_values(project: FakeProject) -> None:
    canaries = project.canaries()

    assert _leaked(project.config(), canaries) == set()
    assert _leaked(project.config("--format", "json"), canaries) == set()
    for name in sorted(SERVICES):
        assert _leaked(project.config(name), canaries) == set(), name


def test_the_environment_listing_loads_the_canaries_positive_control(
    project: FakeProject,
) -> None:
    """正向對照：.env 的 canary 確實載入了（config --environment 會輸出插值用的整個環境）。

    方案 A 下這個指令仍會輸出 .env 的值（剩餘風險 3）；這裡只用來證明上一個測試不會空轉。
    """
    listing = project.config("--environment")

    assert _leaked(listing, project.env_canaries) == set(project.env_canaries)
    assert _leaked(listing, project.file_canaries) == set()


def test_secret_files_resolve_under_the_given_directory(project: FakeProject) -> None:
    config = json.loads(project.config("--format", "json"))
    files = {name: entry["file"] for name, entry in config["secrets"].items()}

    assert files == {name: str(project.secrets_dir / name) for name in FILE_NAMES}


def test_runs_init_still_resolves_the_runs_volume(project: FakeProject) -> None:
    config = json.loads(project.config("runs-init", "--format", "json"))

    assert parse(json.dumps(config)) == ("secscan", "secscan_runs")
    assert _leaked(json.dumps(config), project.canaries()) == set()


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_config_fails_without_the_secrets_directory(
    project: FakeProject, value: str | None
) -> None:
    """D16：不會退回開發的 ./secrets。"""
    result = project.run(secrets_dir=value)

    assert result.returncode != 0
    assert SECRETS_DIR_VARIABLE in result.stderr
    assert _leaked(result.stdout + result.stderr, project.canaries()) == set()
