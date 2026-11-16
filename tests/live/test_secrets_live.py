"""T23b-b2 的 live 驗收：compose secrets 與 Live 的隔離（CSEC-L1 到 L6；make test-live-secrets）。

只在 make test-live-runner 建立的獨立 stack 上執行（ENABLE_LIVE_LAB_TESTS=1）。這次的秘密都是 recipe
以 generate-secret-files 產生的拋棄式值（SECSCAN_LIVE_SECRETS_DIR）：測試讀它們做精確的比對，
它們就是 canary。開發的 .env 與 secrets/ 一律不讀。

- 洩漏偵測：canary 的完整值，以及每一段長度 10 的子字串（hex 不分大小寫；修正 13）。
- 正向對照：同一個偵測器在每個容器的 /run/secrets 偵測到的，恰好是分配矩陣的那幾個 canary；每個
  負向的斷言都有證明輸入真的被讀到的對照（G1 審查 MEDIUM-5、L5）。
- 失敗時不印出秘密（G1 審查 L4）：PYTEST_DONT_REWRITE（這個模組不改寫 assert，失敗時只顯示原始碼與
  訊息，不顯示運算元的值）；先算成名稱、數量或布林值再 assert，訊息只有名稱。
"""

import json
import os
import subprocess
from collections.abc import Iterable, Mapping
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
# 服務程序的名稱（/proc/1/comm；程式碼審查 LOW-4：個別確認）。
PROGRAMS = {
    "api": "uvicorn",
    "runner": "secscan-admin",
    "worker": "secscan-admin",
    "db": "postgres",
}
# Live 的 alembic 缺少設定時的固定訊息（APP_ENV 沒有設定，是 prod），以及連線失敗的例外名稱。
MISSING_APP_PASSWORD = "prod 環境必須設定 DB_PASSWORD"
MISSING_OWNER_PASSWORD = "缺少 DB_OWNER_PASSWORD"
CONNECTION_ERROR = "MigrationConnectionError"
# PostgreSQL 的伺服器 log 寫到 stderr：讀得到它，才證明 stderr 也被檢查了（程式碼審查 MEDIUM-4）。
SERVER_READY = "database system is ready to accept connections"
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
    missing = [
        key
        for key, value in COMPOSE["services"][service].get("environment", {}).items()
        if key.endswith("_FILE") and f"{key}={value}" not in environment
    ]
    assert leaked == set(), sorted(leaked)
    assert unexpected == set(), sorted(unexpected)
    assert missing == [], missing


@pytest.mark.parametrize("service", SERVICES)
def test_secret_mounts_are_exactly_the_matrix_from_the_disposable_directory(service: str) -> None:
    directory = os.path.normpath(os.environ["SECSCAN_LIVE_SECRETS_DIR"])
    mounts = [
        mount
        for mount in _inspect(service)["Mounts"]
        if str(mount.get("Destination", "")).startswith("/run/secrets/")
    ]

    names = {mount["Destination"].removeprefix("/run/secrets/") for mount in mounts}
    writable = sorted(mount["Destination"] for mount in mounts if mount["RW"] is not False)
    elsewhere = sorted(
        mount["Destination"]
        for mount in mounts
        if os.path.dirname(os.path.normpath(mount["Source"])) != directory
    )
    assert names == _expected_secrets(service), sorted(names ^ _expected_secrets(service))
    assert writable == [], writable
    assert elsewhere == [], elsewhere


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
    """只以 PID 1 為證據：子程序的 environ 會被程序標題覆寫（G0 的調整 9）。

    安全審查 L4：先算出洩漏與檢查的結果，才 assert（洩漏的檢查在最前面）。程式碼審查 LOW-4：
    /proc/1/comm 個別確認是服務程序（不和 cmdline 合併比對）。
    """
    canaries = _canaries()
    environ = _exec(service, "tr '\\0' '\\n' < /proc/1/environ")
    cmdline = _exec(service, "tr '\\0' ' ' < /proc/1/cmdline")
    comm = _exec(service, "cat /proc/1/comm")

    leaked = (
        _found(environ.stdout, canaries)
        | _found(cmdline.stdout, canaries)
        | _found(comm.stdout, canaries)
    )
    readable = all(result.returncode == 0 for result in (environ, cmdline, comm))
    names = {line.split("=", 1)[0] for line in environ.stdout.splitlines() if "=" in line}
    expected = {"PGDATA"} if service == "db" else {"DB_PASSWORD_FILE"}
    is_the_service = comm.stdout.strip() == PROGRAMS[service]
    runs_the_service = PROGRAMS[service] in cmdline.stdout
    assert leaked == set(), sorted(leaked)
    assert readable, f"{service} 的 /proc/1 讀取失敗"
    assert bool(environ.stdout), f"{service} 的 /proc/1/environ 是空的"
    assert expected <= names, sorted(expected - names)
    assert is_the_service, f"{service} 的 PID 1（comm）不是 {PROGRAMS[service]}"
    assert runs_the_service, f"{service} 的 PID 1（cmdline）不是 {PROGRAMS[service]}"


def test_the_socket_proxy_environment_holds_no_secret() -> None:
    """socket-proxy 的映像沒有 shell：以 Config.Env 為證據。"""
    environment = _inspect("socket-proxy")["Config"]["Env"] or []

    leaked = _found("\n".join(environment), _canaries())
    assert leaked == set(), sorted(leaked)
    # 正向對照：確實讀到了環境（映像的 PATH 一定在）。
    assert "PATH" in _env_names(environment)


@pytest.mark.parametrize("service", APP_SERVICES)
def test_a_maintenance_command_sees_only_file_settings(service: str) -> None:
    names = docker(
        "exec",
        container(service),
        "python",
        "-c",
        "import os; print('\\n'.join(sorted(os.environ)))",
    ).split()

    secret_like = [name for name in names if name.endswith(("_PASSWORD", "_ENCRYPTION_KEYS"))]
    assert secret_like == [], secret_like
    # 正向對照：讀到的是服務的環境（*_FILE 的設定在）。
    assert "DB_PASSWORD_FILE" in names


@pytest.mark.parametrize("service", ["api", "runner", "worker", "db"])
def test_the_mounted_secrets_are_the_disposable_values_positive_control(service: str) -> None:
    """正向對照：/run/secrets 的檔名恰好是矩陣；內容和拋棄式的值逐一精確相同，偵測器全部抓得到。"""
    canaries = _canaries()
    listing = _exec(service, "ls /run/secrets")
    names = set(listing.stdout.split())
    contents = {name: _exec(service, f"cat /run/secrets/{name}").stdout for name in names}

    listed = listing.returncode == 0
    matches = {name for name, value in contents.items() if value == canaries.get(name)}
    detected = _found("\n".join(contents.values()), canaries)
    assert listed, f"{service} 的 /run/secrets 列不出來"
    assert names == _expected_secrets(service), sorted(names ^ _expected_secrets(service))
    assert matches == names, sorted(names - matches)
    assert detected == names, sorted(names ^ detected)


# --- CSEC-L3：db 的初始化 ------------------------------------------------------------------------


def _logs(service: str) -> tuple[str, str]:
    """docker logs 的 stdout 與 stderr（程式碼審查 MEDIUM-4：PostgreSQL 的 log 在 stderr）。"""
    # 固定的 docker 指令；輸出只在測試程序中計算，不印出。
    result = subprocess.run(  # noqa: S603
        ["docker", "logs", container(service)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    succeeded = result.returncode == 0
    assert succeeded, f"docker logs {service} 的結束碼是 {result.returncode}"
    return result.stdout, result.stderr


def test_the_database_was_initialised_through_the_wrapper() -> None:
    """D21：wrapper 建立標記、00-begin.sh 確認、99-end.sh 刪除；healthy 之後標記不存在。

    三行訊息都寫到 stdout（依序）；洩漏的檢查涵蓋 stdout 與 stderr。
    """
    stdout, stderr = _logs("db")
    steps = [
        "secscan db-entrypoint: first initialisation, marker created",
        "secscan initdb: started (marker present)",
        "secscan initdb: completed (marker removed)",
    ]
    positions = [stdout.find(step) for step in steps]

    leaked = _found(stdout, _canaries()) | _found(stderr, _canaries())
    marker_gone = _exec("db", f"test ! -e {MARKER}").returncode == 0
    reads_stderr = SERVER_READY in stderr
    assert leaked == set(), sorted(leaked)
    assert all(position >= 0 for position in positions), positions
    assert positions == sorted(positions), positions
    assert marker_gone, "healthy 之後初始化未完成標記還在"
    # 正向對照：伺服器寫到 stderr 的 log 讀得到。
    assert reads_stderr, "docker logs 的 stderr 沒有伺服器的 log"


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


def _compose(environment: Mapping[str, str], *args: str) -> str:
    """成功的路徑：結束碼必須是 0、輸出不是空的（G1 審查 HIGH-1）。失敗時只回報結束碼，不印出輸出。

    環境是 recipe 的白名單環境（live_environment），不是每個測試被隔離過的 os.environ。
    """
    # 固定的 docker compose 與 repo 的 compose.yaml。
    result = subprocess.run(  # noqa: S603
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
        env=dict(environment),
    )
    succeeded = result.returncode == 0
    assert succeeded, f"docker compose config {' '.join(args)} 的結束碼是 {result.returncode}"
    has_output = bool(result.stdout.strip())
    assert has_output, f"docker compose config {' '.join(args)} 沒有輸出"
    return result.stdout


def test_the_compose_configuration_holds_no_secret(live_environment: Mapping[str, str]) -> None:
    canaries = _canaries()
    text = _compose(live_environment)
    resolved = json.loads(_compose(live_environment, "--format", "json"))
    directory = os.path.normpath(live_environment["SECSCAN_LIVE_SECRETS_DIR"])

    leaked = _found(text, canaries) | _found(json.dumps(resolved), canaries)
    assert leaked == set()
    files = {name: entry["file"] for name, entry in resolved["secrets"].items()}
    referenced = {
        str(entry["source"] if isinstance(entry, dict) else entry)
        for service in resolved["services"].values()
        for entry in service.get("secrets", [])
    }
    # 正向對照：解析出來的 secret 涵蓋服務引用的每一個（db_password 一定在），而且都在拋棄式目錄
    # 之下。
    assert "db_password" in referenced
    assert referenced <= set(files)
    assert {os.path.dirname(os.path.normpath(path)) for path in files.values()} == {directory}


def test_the_compose_environment_has_no_secret_names(live_environment: Mapping[str, str]) -> None:
    listing = _compose(live_environment, "--environment")
    names = {line.split("=", 1)[0] for line in listing.splitlines() if "=" in line}
    secret_names = {item.env_name for item in SECRET_FILES}

    assert not names & secret_names
    assert "COMPOSE_ENV_FILES" not in names
    # 正向對照：清單確實是 recipe 的白名單環境。
    expected = {"SECSCAN_SECRETS_DIR", "COMPOSE_DISABLE_ENV_FILE", "SECSCAN_LIVE_PROJECT"}
    assert expected <= names, sorted(expected - names)
    project = live_environment["SECSCAN_LIVE_PROJECT"]
    assert project == "secscan-live"


@pytest.mark.parametrize("service", SERVICES)
def test_no_container_records_an_env_file(service: str) -> None:
    """S10 (e) 沒有看到這個 label；有的話必須是空的（執行期的偵測）。"""
    labels = _inspect(service)["Config"]["Labels"] or {}

    assert labels.get("com.docker.compose.project.environment_file", "") == ""


def _alembic(
    environment: Mapping[str, str], *, missing: str | None
) -> subprocess.CompletedProcess[str]:
    """Live 的 alembic（-x dotenv=off、秘密只以 *_FILE 傳入）；missing 給定時少給那一個。"""
    directory = environment["SECSCAN_LIVE_SECRETS_DIR"]
    child = {
        **environment,
        "DB_PASSWORD_FILE": f"{directory}/db_password",
        "DB_OWNER_PASSWORD_FILE": f"{directory}/db_owner_password",
        "SECRET_ENCRYPTION_KEYS_FILE": f"{directory}/secret_encryption_keys",
        "EVIDENCE_ENCRYPTION_KEYS_FILE": f"{directory}/evidence_encryption_keys",
        "CONTENT_ENCRYPTION_KEYS_FILE": f"{directory}/content_encryption_keys",
    }
    if missing is not None:
        del child[missing]
    # 固定的 alembic 指令；只確認結束碼與錯誤訊息中的設定名稱，輸出不印出。
    return subprocess.run(
        ["uv", "run", "--locked", "alembic", "-x", "dotenv=off", "current"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
        env=child,
    )


def test_the_migration_reads_the_disposable_files_positive_control(
    live_environment: Mapping[str, str],
) -> None:
    """正向對照：*_FILE 都給的時候成功（下面的負向測試因此不是因為其他原因失敗）。"""
    result = _alembic(live_environment, missing=None)

    succeeded = result.returncode == 0
    assert succeeded, f"alembic current 的結束碼是 {result.returncode}"
    leaked = _found(result.stdout + result.stderr, _canaries())
    assert leaked == set()


@pytest.mark.parametrize(
    ("missing", "reason"),
    [
        ("DB_PASSWORD_FILE", MISSING_APP_PASSWORD),
        ("DB_OWNER_PASSWORD_FILE", MISSING_OWNER_PASSWORD),
    ],
)
def test_the_migration_does_not_fall_back_to_the_env_file(
    live_environment: Mapping[str, str], missing: str, reason: str
) -> None:
    """修正 17：少給一個 *_FILE 時失敗，不會從開發的 .env 補上（-x dotenv=off）。

    明確驗證失敗的原因（第二輪程式碼審查 LOW-3）：錯誤是「缺少那一個設定」的固定訊息，不是連線
    失敗（MigrationConnectionError 的訊息也含 DB_OWNER_PASSWORD，只比對名稱分辨不出來）。訊息的
    文字由 tests/unit/test_migration_env.py 對照實際的例外，避免這裡的比對空轉。
    """
    result = _alembic(live_environment, missing=missing)

    failed = result.returncode != 0
    assert failed, f"少了 {missing} 卻成功"
    names_the_reason = reason in result.stderr
    assert names_the_reason, f"錯誤訊息不是「{reason}」"
    connection_error = CONNECTION_ERROR in result.stderr
    assert not connection_error, "失敗的原因是連線，不是缺少設定"
    leaked = _found(result.stdout + result.stderr, _canaries())
    assert leaked == set()


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
