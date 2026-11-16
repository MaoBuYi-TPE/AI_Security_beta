"""db 的初始化（CSEC-07；docs/DECISIONS.md §32；計畫 §2.5）：靜態檢查，以允許清單判定。

- initdb 的 SQL（10-roles.sql，G0b 驗證過的版本）：密碼從 `*_FILE` 讀檔；meta-command、語句、
  SET／RESET 都是允許清單；CREATE ROLE 之前關閉所有會記錄語句內容的設定（D19），之後 RESET。
- 初始化未完成標記（D18、D21）：wrapper 在初始化開始之前建立，00-begin.sh 只檢查，只有 99-end.sh
  刪除；healthcheck 同時要求 readiness 與標記不存在。
- 設定來源（D20；F1）：db、db-test 的 command、environment、掛載都是允許清單，不得使用 debug 等級的
  log（第一次初始化時暫時伺服器的環境會被寫進 log，含 superuser 的密碼）。

這些都只檢查 repo 的檔案；實際的初始化在 G0b、G0c 以拋棄式資源驗證，正式 compose 下的啟動留給
G3 的 Live（CSEC-L3、CSEC-L6）與 G5。
"""

import re
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE: dict[str, Any] = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
SERVICES: dict[str, dict[str, Any]] = COMPOSE["services"]
INITDB = ROOT / "deploy" / "postgres" / "initdb"
WRAPPER = ROOT / "deploy" / "postgres" / "db-entrypoint.sh"
ROLES_SQL = INITDB / "10-roles.sql"
BEGIN = INITDB / "00-begin.sh"
END = INITDB / "99-end.sh"
WRAPPER_IN_CONTAINER = "/usr/local/lib/secscan/db-entrypoint.sh"
MARKER = "/var/lib/postgresql/secscan-initdb-incomplete"
HEALTHCHECK = [
    "CMD",
    "sh",
    "-c",
    f"pg_isready -h 127.0.0.1 -p 5432 -U postgres && test ! -e {MARKER}",
]
INITDB_ARGS = "--auth-local=scram-sha-256 --auth-host=scram-sha-256"
# §2.5 第 6 步：CREATE ROLE 之前明確關閉、之後 RESET 的設定（D19；G0b 以映像盤點，清單完整）。
SUPPRESSED = {
    "log_statement": "'none'",
    "log_min_duration_statement": "-1",
    "log_min_duration_sample": "-1",
    "log_transaction_sample_rate": "0",
    "log_min_error_statement": "panic",
    "debug_print_parse": "off",
    "debug_print_rewritten": "off",
    "debug_print_plan": "off",
    "password_encryption": "'scram-sha-256'",
}
# command 中允許的設定（D20 的盤點）：db-test 另外關閉持久化換取速度。
ALLOWED_COMMAND_SETTINGS = {
    "db": {"cluster_name", "log_error_verbosity"},
    "db-test": {
        "cluster_name",
        "log_error_verbosity",
        "fsync",
        "synchronous_commit",
        "full_page_writes",
    },
}
DEBUG_LEVELS = {f"debug{level}" for level in range(1, 6)}
LOG_LEVEL_SETTINGS = {"log_min_messages", "client_min_messages"}
CONFIG_FILE_SETTINGS = ("config_file", "hba_file", "ident_file", "include")
ENVIRONMENT = {
    "db": {
        "POSTGRES_INITDB_ARGS",
        "POSTGRES_PASSWORD_FILE",
        "SECSCAN_OWNER_DB_USER",
        "SECSCAN_OWNER_DB_PASSWORD_FILE",
        "SECSCAN_APP_DB_USER",
        "SECSCAN_APP_DB_PASSWORD_FILE",
        "SECSCAN_APP_DB_NAME",
    },
    "db-test": {"POSTGRES_INITDB_ARGS", "POSTGRES_PASSWORD_FILE"},
}
DB_VOLUMES = [
    "db_data:/var/lib/postgresql",
    "./deploy/postgres/initdb:/docker-entrypoint-initdb.d:ro",
    f"./deploy/postgres/db-entrypoint.sh:{WRAPPER_IN_CONTAINER}:ro",
]
DB_TMPFS = ["/var/run/postgresql:mode=1777", "/tmp:mode=1777"]  # noqa: S108 - 容器內的路徑
DB_TEST_TMPFS = [
    "/var/lib/postgresql:mode=1777",
    "/var/run/postgresql:mode=1777",
    "/tmp:mode=1777",  # noqa: S108 - 容器內的路徑
]


def _code_lines(path: Path) -> list[str]:
    """去掉註解與空行之後的程式行（shell 與 psql 都以 # 或 -- 開頭的整行是註解）。"""
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith(("#", "--")):
            lines.append(line)
    return lines


def _words(lines: list[str]) -> set[str]:
    return {word for line in lines for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", line)}


# --- 初始化未完成標記（D18、D21）---------------------------------------------------------------


def test_the_initdb_directory_has_exactly_the_three_files() -> None:
    assert sorted(path.name for path in INITDB.iterdir()) == [
        "00-begin.sh",
        "10-roles.sql",
        "99-end.sh",
    ]


@pytest.mark.parametrize("script", [BEGIN, END], ids=lambda path: path.name)
def test_init_scripts_are_executable_and_do_not_use_set(script: Path) -> None:
    """不可執行的 .sh 會被 entrypoint source（set 會影響它）：兩個檔案都是 100755。"""
    lines = _code_lines(script)

    assert script.stat().st_mode & stat.S_IXUSR
    assert script.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
    assert "set" not in _words(lines)
    assert f"secscan_initdb_marker={MARKER}" in lines


def test_the_begin_script_only_checks_the_marker_and_fails_closed() -> None:
    lines = _code_lines(BEGIN)

    assert 'if [ -e "$secscan_initdb_marker" ]; then' in lines
    # 標記不存在（wrapper 沒有執行）：建立它並失敗，之後維持 unhealthy。
    else_branch = lines[lines.index("else") + 1 :]
    assert else_branch[0] == "printf '' > \"$secscan_initdb_marker\""
    assert "exit 1" in else_branch
    assert "rm" not in _words(lines)


def test_only_the_end_script_removes_the_marker() -> None:
    removers = {
        path.name for path in (*INITDB.iterdir(), WRAPPER) if "rm" in _words(_code_lines(path))
    }

    assert removers == {"99-end.sh"}
    assert 'rm -f -- "$secscan_initdb_marker" || exit 1' in _code_lines(END)


def test_the_wrapper_creates_the_marker_before_the_official_entrypoint() -> None:
    lines = _code_lines(WRAPPER)
    text = "\n".join(lines)

    assert WRAPPER.parent != INITDB
    assert WRAPPER.read_text(encoding="utf-8").startswith("#!/bin/sh\n")
    assert f"secscan_initdb_marker={MARKER}" in lines
    # PGDATA 是空的：不建立任何東西就停止。
    assert lines[lines.index('if [ -z "$PGDATA" ]; then') + 2] == "exit 1"
    # 判斷條件和官方 entrypoint 決定是否初始化的條件逐字相同。
    assert text.count('if [ ! -s "$PGDATA/PG_VERSION" ]; then') == 1
    create = lines.index("if ! printf '' > \"$secscan_initdb_marker\"; then")
    flush = lines.index('if ! sync "$secscan_initdb_marker" /var/lib/postgresql; then')
    assert lines.index('if [ ! -s "$PGDATA/PG_VERSION" ]; then') < create < flush
    assert lines[-1] == 'exec /usr/local/bin/docker-entrypoint.sh "$@"'
    assert lines.count("exit 1") == 3


def test_the_wrapper_never_removes_the_marker_reads_secrets_or_switches_user() -> None:
    words = _words(_code_lines(WRAPPER))

    assert not words & {"rm", "set", "su", "gosu", "unset"}
    assert not {word for word in words if "PASSWORD" in word.upper() or word.endswith("_FILE")}


def test_the_healthcheck_requires_readiness_and_no_marker() -> None:
    """G0b 驗證過的指令逐字相同；時間參數沿用正式的值。"""
    healthcheck = COMPOSE["x-postgres"]["healthcheck"]

    assert healthcheck == {"test": HEALTHCHECK, "interval": "2s", "timeout": "3s", "retries": 30}
    for name in ("db", "db-test"):
        assert SERVICES[name]["healthcheck"] == healthcheck


def test_only_the_db_runs_the_wrapper() -> None:
    db = SERVICES["db"]

    assert db["entrypoint"] == ["/bin/sh", WRAPPER_IN_CONTAINER]
    assert db["command"][0] == "postgres"
    assert db["user"] == "999:999"
    assert db["read_only"] is True
    # 標記與 PGDATA 在同一個具名 volume（標記在 PGDATA 之外）。
    assert db["volumes"][0] == "db_data:/var/lib/postgresql"
    assert "entrypoint" not in SERVICES["db-test"]
    assert not any("initdb" in str(volume) for volume in SERVICES["db-test"].get("volumes", []))


# --- initdb 的 SQL（允許清單）--------------------------------------------------------------------

_META = [
    re.compile(r"\\set VERBOSITY terse"),
    re.compile(r"\\set SHOW_CONTEXT never"),
    re.compile(r"\\getenv [a-z_]+ [A-Z_]+"),
    re.compile(r"\\if :\{\?[A-Za-z_]+\}"),
    re.compile(r"\\if :[a-z_]+"),
    re.compile(r"\\if :SHELL_ERROR"),
    re.compile(r"\\else"),
    re.compile(r"\\endif"),
    re.compile(r"\\set [a-z_]+ `.+`"),
    re.compile(r"\\unset [a-z_]+"),
]
_DO = re.compile(r"DO \$\$ BEGIN RAISE EXCEPTION 'secscan initdb: [^':`\\]+'; END \$\$;")
_STATEMENTS = [
    re.compile(r"SET (?P<name>[a-z_]+) = (?P<value>.+)"),
    re.compile(r"RESET (?P<name>[a-z_]+)"),
    re.compile(
        r'CREATE ROLE :"[a-z_]+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION '
        r"NOBYPASSRLS PASSWORD :'(owner|app)_password'"
    ),
    re.compile(r'CREATE DATABASE :"app_db" OWNER :"owner_user"'),
    re.compile(r'REVOKE ALL ON DATABASE :"app_db" FROM PUBLIC'),
    re.compile(r'GRANT CONNECT ON DATABASE :"app_db" TO :"app_user"'),
    re.compile(r"REVOKE CONNECT ON DATABASE (postgres|template1) FROM PUBLIC"),
]
PASSWORD_VARIABLES = ("owner_password", "app_password")
FILE_VARIABLES = ("owner_file", "app_file")


def _sql() -> tuple[list[str], list[str]]:
    """meta-command 的行與 SQL 語句（DO 是一行；其他語句以 ; 結尾，可能跨行）。"""
    meta: list[str] = []
    statements: list[str] = []
    pending: list[str] = []
    for line in _code_lines(ROLES_SQL):
        if line.startswith("\\"):
            meta.append(line)
            continue
        pending.append(line)
        if line.endswith(";"):
            statements.append(" ".join(pending).removesuffix(";"))
            pending = []
    assert pending == []
    return meta, statements


def test_meta_commands_are_on_the_allowlist() -> None:
    meta, _ = _sql()

    assert meta
    for line in meta:
        assert any(pattern.fullmatch(line) for pattern in _META), line
    for forbidden in ("\\warn", "\\errverbose", "\\setenv", "\\o", "\\echo", "\\qecho", "\\gexec"):
        assert not any(line.startswith(forbidden) for line in meta), forbidden
    assert "\\set" not in meta


def test_passwords_are_read_from_files_named_by_the_environment() -> None:
    meta, _ = _sql()
    getenv = [line.split() for line in meta if line.startswith("\\getenv")]

    assert {(variable, name) for _, variable, name in getenv} == {
        ("owner_user", "SECSCAN_OWNER_DB_USER"),
        ("app_user", "SECSCAN_APP_DB_USER"),
        ("app_db", "SECSCAN_APP_DB_NAME"),
        ("owner_file", "SECSCAN_OWNER_DB_PASSWORD_FILE"),
        ("app_file", "SECSCAN_APP_DB_PASSWORD_FILE"),
    }
    for _, _, name in getenv:
        if "PASSWORD" in name:
            assert name.endswith("_FILE"), name
    # 每個取得的變數都在使用之前以 \if 確認有設定。
    for _, variable, _ in getenv:
        assert f"\\if :{{?{variable}}}" in meta, variable


def test_backticks_only_reference_the_file_paths() -> None:
    text = ROLES_SQL.read_text(encoding="utf-8")
    commands = re.findall(r"`([^`]*)`", text)

    assert len(commands) == 4
    for command in commands:
        referenced = set(re.findall(r":'([a-z_]+)'", command))
        assert referenced, command
        assert referenced <= set(FILE_VARIABLES), command
        for variable in PASSWORD_VARIABLES:
            assert variable not in command


def test_files_are_checked_on_the_client_before_reading() -> None:
    """一般檔案、不是 symlink、恰好一行、32 到 4095 個可列印的 ASCII；讀檔之後檢查 SHELL_ERROR。"""
    meta, _ = _sql()
    awk = (
        "LC_ALL=C awk 'NR == 1 && length($0) >= 32 && length($0) <= 4095 && $0 ~ /^[!-~]+$/ "
        '{ ok = 1 } END { if (NR == 1 && ok) print "true"; else print "false" }\''
    )
    for name in ("owner", "app"):
        check = next(line for line in meta if line.startswith(f"\\set {name}_file_ok "))
        assert f"if [ -f :'{name}_file' ] && [ ! -L :'{name}_file' ]; then {awk}" in check
        read = meta.index(f"\\set {name}_password `cat :'{name}_file'`")
        assert meta[read + 1] == "\\if :SHELL_ERROR"
        assert meta.index(f"\\if :{name}_file_ok") < read
    # SHELL_ERROR 是 psql 16 起才有的變數：先確認它存在。
    assert meta.index("\\if :{?SHELL_ERROR}") < meta.index(
        "\\set owner_password `cat :'owner_file'`"
    )


def test_failures_use_fixed_messages() -> None:
    _, statements = _sql()
    raises = [statement for statement in statements if statement.startswith("DO ")]

    assert raises
    for statement in raises:
        assert _DO.fullmatch(f"{statement};"), statement


def test_sql_statements_are_on_the_allowlist() -> None:
    _, statements = _sql()
    text = ROLES_SQL.read_text(encoding="utf-8").lower()

    for statement in statements:
        if statement.startswith("DO "):
            continue
        assert any(pattern.fullmatch(statement) for pattern in _STATEMENTS), statement
    for forbidden in ("alter system", "alter role", "alter database", "set_config("):
        assert forbidden not in text, forbidden


def test_statement_logging_is_off_around_create_role() -> None:
    """D19：CREATE ROLE 帶著密碼；之前關閉每一項會記錄語句內容的設定，之後全部 RESET。"""
    _, statements = _sql()
    creates = [i for i, s in enumerate(statements) if s.startswith("CREATE ROLE")]
    first, last = creates[0], creates[-1]
    sets = {
        match["name"]: match["value"]
        for statement in statements[:first]
        if (match := _STATEMENTS[0].fullmatch(statement))
    }
    resets = {
        match["name"]
        for statement in statements[last + 1 :]
        if (match := _STATEMENTS[1].fullmatch(statement))
    }
    names = {
        match["name"]
        for statement in statements
        for pattern in _STATEMENTS[:2]
        if (match := pattern.fullmatch(statement))
    }

    assert len(creates) == 2
    assert sets == SUPPRESSED
    assert resets == set(SUPPRESSED)
    assert names == set(SUPPRESSED)


def test_password_variables_appear_only_where_they_are_read_used_and_unset() -> None:
    meta, statements = _sql()
    for variable in PASSWORD_VARIABLES:
        in_meta = [line for line in meta if variable in line]
        in_sql = [statement for statement in statements if variable in statement]
        assert in_meta == [
            f"\\set {variable} `cat :'{variable.replace('password', 'file')}'`",
            f"\\unset {variable}",
        ]
        assert len(in_sql) == 1
        assert in_sql[0].startswith("CREATE ROLE")


# --- 設定來源（D20；F1）-------------------------------------------------------------------------


def _command_settings(command: list[str]) -> dict[str, str]:
    """postgres 的參數解析成設定；名稱不分大小寫、- 與 _ 視為相同。不認得的形式一律拒絕。"""
    if not command or command[0] != "postgres":
        raise ValueError("command 必須以 postgres 開頭")
    settings: dict[str, str] = {}
    args = iter(command[1:])
    for arg in args:
        if arg == "-c":
            pair = next(args, "")
        elif arg.startswith("-c") or (arg.startswith("--") and "=" in arg):
            pair = arg[2:]
        else:
            raise ValueError(f"不允許的參數形式：{arg}")
        name, separator, value = pair.partition("=")
        if not separator:
            raise ValueError(f"設定缺少值：{pair}")
        settings[name.lower().replace("-", "_")] = value
    return settings


def _forbidden_settings(settings: dict[str, str]) -> set[str]:
    """不論允許清單之後怎麼擴充都拒絕的設定：debug 等級的 log、改變設定檔的來源。"""
    forbidden = {
        name
        for name, value in settings.items()
        if name in LOG_LEVEL_SETTINGS and value.lower() in DEBUG_LEVELS
    }
    forbidden |= {name for name in settings if name.startswith(CONFIG_FILE_SETTINGS)}
    return forbidden


@pytest.mark.parametrize("name", ["db", "db-test"])
def test_the_command_sets_only_allowed_settings(name: str) -> None:
    settings = _command_settings(SERVICES[name]["command"])

    assert set(settings) <= ALLOWED_COMMAND_SETTINGS[name]
    assert _forbidden_settings(settings) == set()


@pytest.mark.parametrize(
    "command",
    [
        ["postgres", "-c", "log_min_messages=debug5"],
        ["postgres", "-c", "LOG_MIN_MESSAGES=DEBUG1"],
        ["postgres", "--log-min-messages=debug3"],
        ["postgres", "-clog_min_messages=debug2"],
        ["postgres", "-c", "client_min_messages=debug4"],
        ["postgres", "-c", "config_file=/etc/x.conf"],
        ["postgres", "-c", "include_dir=/etc"],
    ],
)
def test_debug_logging_and_config_files_are_always_refused(command: list[str]) -> None:
    """允許清單之後擴充時仍然成立的檢查（D20）：debug1 到 debug5、設定檔的來源。"""
    assert _forbidden_settings(_command_settings(command))


@pytest.mark.parametrize(
    "command",
    [["postgres", "-d", "3"], ["postgres", "-d3"], ["postgres", "-F"], ["pg_ctl", "start"]],
)
def test_other_argument_forms_are_refused(command: list[str]) -> None:
    with pytest.raises(ValueError, match=r"command|參數"):
        _command_settings(command)


@pytest.mark.parametrize("name", ["db", "db-test"])
def test_the_environment_is_on_the_allowlist(name: str) -> None:
    environment = SERVICES[name]["environment"]

    assert set(environment) == ENVIRONMENT[name]
    assert environment["POSTGRES_INITDB_ARGS"] == INITDB_ARGS


def test_mounts_are_on_the_allowlist() -> None:
    db, db_test = SERVICES["db"], SERVICES["db-test"]

    assert db["volumes"] == DB_VOLUMES
    assert db["tmpfs"] == DB_TMPFS
    assert "volumes" not in db_test
    assert db_test["tmpfs"] == DB_TEST_TMPFS
    for service in (db, db_test):
        assert "configs" not in service
        assert "env_file" not in service
