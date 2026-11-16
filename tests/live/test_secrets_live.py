"""T23b-b2 的 live 驗收：compose secrets 與 Live 的隔離（CSEC-L1 到 L6；make test-live-secrets）。

只在 make test-live-runner 建立的獨立 stack 上執行（ENABLE_LIVE_LAB_TESTS=1）。這次的秘密都是 recipe
以 generate-secret-files 產生的拋棄式值（SECSCAN_LIVE_SECRETS_DIR）：測試讀它們做精確的比對，
它們就是 canary。開發的 .env 與 secrets/ 一律不讀。

- 洩漏偵測：canary 的完整值，以及每一段長度 10 的子字串（hex 不分大小寫；修正 13）。
- 正向對照：同一個偵測器在每個容器的 /run/secrets 偵測到的，恰好是分配矩陣的那幾個 canary。
- 失敗時不印出秘密：先算成名稱或數量再 assert（pytest 會印出 assert 的運算元）。
"""

import json
import os
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest
import yaml

from secscan.cli.secret_files import SECRET_FILES
from tests.live.support import PROJECT, container, docker

pytestmark = [pytest.mark.live]

ROOT = Path(__file__).resolve().parents[2]
COMPOSE: dict[str, Any] = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
SERVICES = ("api", "runner", "worker", "db", "guard", "socket-proxy")
APP_SERVICES = ("api", "runner", "worker")
MARKER = "/var/lib/postgresql/secscan-initdb-incomplete"
WINDOW = 10
DEBUG_LEVELS = {f"debug{level}" for level in range(1, 6)}
# 服務程序的名稱（/proc/1/comm）。
PROGRAMS = {
    "api": "uvicorn",
    "runner": "secscan-admin",
    "worker": "secscan-admin",
    "db": "postgres",
}
_SUPERUSER_PSQL = (
    'PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" psql -h 127.0.0.1 -U postgres -d postgres '
    '-At -F "|" -q -v ON_ERROR_STOP=1'
)


def _canaries() -> dict[str, str]:
    directory = Path(os.environ["SECSCAN_LIVE_SECRETS_DIR"])
    return {
        item.file_name: (directory / item.file_name).read_text(encoding="ascii")
        for item in SECRET_FILES
    }


def _found(text: str, canaries: dict[str, str]) -> set[str]:
    """text 含哪些 canary（完整的值或任何一段長度 WINDOW 的子字串）；只回傳名稱。"""
    lowered = text.lower()
    found = set()
    for name, value in canaries.items():
        fragments = {value[i : i + WINDOW].lower() for i in range(len(value) - WINDOW + 1)}
        if any(fragment in lowered for fragment in fragments):
            found.add(name)
    return found


def _inspect(service: str) -> dict[str, Any]:
    [details] = json.loads(docker("inspect", container(service)))
    return dict(details)


def _env_names(entries: Iterable[str]) -> set[str]:
    return {entry.split("=", 1)[0] for entry in entries}


def _expected_secrets(service: str) -> set[str]:
    return set(COMPOSE["services"][service].get("secrets", []))


# --- CSEC-L1：docker inspect ---------------------------------------------------------------------


@pytest.mark.parametrize("service", SERVICES)
def test_the_container_configuration_holds_no_secret(service: str) -> None:
    canaries = _canaries()
    details = _inspect(service)
    environment = details["Config"]["Env"] or []
    image = json.loads(docker("image", "inspect", details["Image"]))[0]
    allowed = set(COMPOSE["services"][service].get("environment", {})) | _env_names(
        image["Config"]["Env"] or []
    )

    leaked = _found(json.dumps(details), canaries)
    unexpected = _env_names(environment) - allowed
    assert leaked == set()
    assert unexpected == set()
    for key, value in COMPOSE["services"][service].get("environment", {}).items():
        if key.endswith("_FILE"):
            assert f"{key}={value}" in environment, key


@pytest.mark.parametrize("service", SERVICES)
def test_secret_mounts_are_exactly_the_matrix_from_the_disposable_directory(service: str) -> None:
    directory = os.path.normpath(os.environ["SECSCAN_LIVE_SECRETS_DIR"])
    mounts = [
        mount
        for mount in _inspect(service)["Mounts"]
        if str(mount.get("Destination", "")).startswith("/run/secrets/")
    ]

    names = {mount["Destination"].removeprefix("/run/secrets/") for mount in mounts}
    assert names == _expected_secrets(service)
    for mount in mounts:
        assert mount["RW"] is False
        assert os.path.dirname(os.path.normpath(mount["Source"])) == directory


# --- CSEC-L2：長期執行的服務程序 -----------------------------------------------------------------


def _exec(service: str, script: str) -> subprocess.CompletedProcess[str]:
    # 固定的 docker 指令與這個檔案寫死的 shell；結果只在測試程序中計算，不印出。
    return subprocess.run(  # noqa: S603
        ["docker", "exec", container(service), "sh", "-c", script],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.mark.parametrize("service", ["api", "runner", "worker", "db"])
def test_the_service_process_environment_holds_no_secret(service: str) -> None:
    """只以 PID 1 為證據：子程序的 environ 會被程序標題覆寫（G0 的調整 9）。"""
    canaries = _canaries()
    environ = _exec(service, "tr '\\0' '\\n' < /proc/1/environ")
    command = _exec(service, "tr '\\0' ' ' < /proc/1/cmdline; echo; cat /proc/1/comm")

    names = {line.split("=", 1)[0] for line in environ.stdout.splitlines() if "=" in line}
    leaked = _found(environ.stdout, canaries)
    assert environ.returncode == 0
    assert len(environ.stdout) > 0
    assert leaked == set()
    expected = {"PGDATA"} if service == "db" else {"DB_PASSWORD_FILE"}
    assert expected <= names
    assert command.returncode == 0
    assert PROGRAMS[service] in command.stdout
    assert _found(command.stdout, canaries) == set()


def test_the_socket_proxy_environment_holds_no_secret() -> None:
    """socket-proxy 的映像沒有 shell：以 Config.Env 為證據。"""
    environment = _inspect("socket-proxy")["Config"]["Env"] or []

    assert _found("\n".join(environment), _canaries()) == set()


@pytest.mark.parametrize("service", APP_SERVICES)
def test_a_maintenance_command_sees_only_file_settings(service: str) -> None:
    names = docker(
        "exec",
        container(service),
        "python",
        "-c",
        "import os; print('\\n'.join(sorted(os.environ)))",
    ).split()

    assert not [name for name in names if name.endswith(("_PASSWORD", "_ENCRYPTION_KEYS"))]
    assert "DB_PASSWORD_FILE" in names


@pytest.mark.parametrize("service", ["api", "runner", "worker", "db"])
def test_the_mounted_secrets_are_the_disposable_values_positive_control(service: str) -> None:
    """正向對照：/run/secrets 的檔名恰好是矩陣；內容和拋棄式的值逐一精確相同，偵測器全部抓得到。"""
    canaries = _canaries()
    listing = _exec(service, "ls /run/secrets")
    names = set(listing.stdout.split())
    contents = {name: _exec(service, f"cat /run/secrets/{name}").stdout for name in names}

    assert names == _expected_secrets(service)
    matches = {name for name, value in contents.items() if value == canaries[name]}
    assert matches == names
    assert _found("\n".join(contents.values()), canaries) == names


# --- CSEC-L3：db 的初始化 ------------------------------------------------------------------------


def test_the_database_was_initialised_through_the_wrapper() -> None:
    """D21：wrapper 建立標記、00-begin.sh 確認、99-end.sh 刪除；healthy 之後標記不存在。"""
    logs = docker("logs", container("db"))
    steps = [
        "secscan db-entrypoint: first initialisation, marker created",
        "secscan initdb: started (marker present)",
        "secscan initdb: completed (marker removed)",
    ]
    positions = [logs.find(step) for step in steps]

    assert all(position >= 0 for position in positions)
    assert positions == sorted(positions)
    assert _found(logs, _canaries()) == set()
    assert _exec("db", f"test ! -e {MARKER}").returncode == 0


def test_both_roles_log_in_with_scram_using_the_mounted_files() -> None:
    script = (
        'for pair in "$SECSCAN_OWNER_DB_USER:$SECSCAN_OWNER_DB_PASSWORD_FILE" '
        '"$SECSCAN_APP_DB_USER:$SECSCAN_APP_DB_PASSWORD_FILE"; do '
        'user="${pair%%:*}"; file="${pair#*:}"; '
        'PGPASSWORD="$(cat "$file")" psql -h 127.0.0.1 -U "$user" -d "$SECSCAN_APP_DB_NAME" -At '
        "-c 'SELECT system_user' || exit 1; done"
    )

    result = _exec("db", script)

    assert result.returncode == 0
    lines = result.stdout.splitlines()
    assert len(lines) == 2
    assert all(line.startswith("scram-sha-256:") for line in lines)


# --- CSEC-L4、L5：compose 的設定與 Live 的隔離 ----------------------------------------


def _compose(*args: str) -> subprocess.CompletedProcess[str]:
    # 固定的 docker compose 與 repo 的 compose.yaml；環境是 recipe 的白名單環境。
    return subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker",
            "compose",
            "-p",
            PROJECT,
            "-f",
            "compose.yaml",
            "--profile",
            "app",
            "config",
            *args,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env=dict(os.environ),
    )


def test_the_compose_configuration_holds_no_secret() -> None:
    result = _compose()
    resolved = _compose("--format", "json")

    assert result.returncode == 0
    assert _found(result.stdout, _canaries()) == set()
    files = {entry["file"] for entry in json.loads(resolved.stdout)["secrets"].values()}
    directory = os.path.normpath(os.environ["SECSCAN_LIVE_SECRETS_DIR"])
    assert {os.path.dirname(os.path.normpath(path)) for path in files} == {directory}


def test_the_compose_environment_has_no_secret_names() -> None:
    listing = _compose("--environment").stdout
    names = {line.split("=", 1)[0] for line in listing.splitlines() if "=" in line}
    secret_names = {item.env_name for item in SECRET_FILES}

    assert not names & secret_names
    assert "COMPOSE_ENV_FILES" not in names
    assert os.environ["SECSCAN_LIVE_PROJECT"] == "secscan-live"


@pytest.mark.parametrize("service", SERVICES)
def test_no_container_records_an_env_file(service: str) -> None:
    """S10 (e) 沒有看到這個 label；有的話必須是空的（執行期的偵測）。"""
    labels = _inspect(service)["Config"]["Labels"] or {}

    assert labels.get("com.docker.compose.project.environment_file", "") == ""


@pytest.mark.parametrize("missing", ["DB_PASSWORD_FILE", "DB_OWNER_PASSWORD_FILE"])
def test_the_migration_does_not_fall_back_to_the_env_file(missing: str) -> None:
    """修正 17：少給一個 *_FILE 時失敗，不會從開發的 .env 補上（-x dotenv=off）。"""
    directory = os.environ["SECSCAN_LIVE_SECRETS_DIR"]
    child = {
        **os.environ,
        "DB_PORT": "55434",
        "DB_PASSWORD_FILE": f"{directory}/db_password",
        "DB_OWNER_PASSWORD_FILE": f"{directory}/db_owner_password",
        "SECRET_ENCRYPTION_KEYS_FILE": f"{directory}/secret_encryption_keys",
        "EVIDENCE_ENCRYPTION_KEYS_FILE": f"{directory}/evidence_encryption_keys",
        "CONTENT_ENCRYPTION_KEYS_FILE": f"{directory}/content_encryption_keys",
    }
    del child[missing]
    # 固定的 alembic 指令；只確認結束碼，輸出不印出。
    result = subprocess.run(
        ["uv", "run", "--locked", "alembic", "-x", "dotenv=off", "current"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env=child,
    )

    assert result.returncode != 0
    assert _found(result.stdout + result.stderr, _canaries()) == set()


# --- CSEC-L6：有效的 log 設定（D20；F1）----------------------------------------


def test_no_debug_logging_is_in_effect() -> None:
    statement = (
        "SELECT name || '=' || setting FROM pg_settings "
        "WHERE name IN ('log_min_messages', 'client_min_messages');\n"
        "SELECT 'file:' || name FROM pg_file_settings "
        "WHERE name IN ('log_min_messages', 'client_min_messages');\n"
        "SELECT 'role:' || array_to_string(setconfig, ',') FROM pg_db_role_setting "
        "WHERE array_to_string(setconfig, ',') ~ '(log|client)_min_messages';\n"
    )
    output = docker("exec", "-i", container("db"), "sh", "-c", _SUPERUSER_PSQL, stdin=statement)
    lines = [line for line in output.splitlines() if line]

    settings = dict(line.split("=", 1) for line in lines if "=" in line and ":" not in line)
    assert set(settings) == {"log_min_messages", "client_min_messages"}
    assert not {value.lower() for value in settings.values()} & DEBUG_LEVELS
    assert [line for line in lines if line.startswith(("file:", "role:"))] == []
