"""migrate-db-roles 的設定、SCRAM 核對與 migration 的憑證（T23b-b1；ROLE-05、06 的 unit 部分）。

不連 DB：只測連線之前的檢查（非 loopback、缺少密碼、owner 與應用程式角色相同、錯誤的 DB_USER）。
實際的 PostgreSQL verifier 由整合測試確認（owner 已存在時，密碼相符就沿用、不符就拒絕）。
"""

import argparse
import base64
import hashlib
import hmac
import io
import re
import secrets
from pathlib import Path

import pytest
from alembic import command
from pydantic import SecretStr, ValidationError

from secscan.cli import db_roles
from secscan.cli.db_roles import (
    DEV_CLUSTER_NAME,
    EXIT_FAILURE,
    AdminCredentials,
    target_from,
)
from secscan.cli.scram import UnsupportedPasswordError, scram_matches, scram_verifier
from secscan.core.config import Settings
from secscan.migrations import alembic_config
from secscan.migrations.credentials import (
    MigrationCredentials,
    MissingOwnerPasswordError,
    OwnerIsAppRoleError,
)

OWNER_PASSWORD = "owner-" + secrets.token_hex(16)
ADMIN_PASSWORD = "admin-" + secrets.token_hex(16)


def _verifier(password: str, *, iterations: int = 4096) -> str:
    """和 PostgreSQL 相同的 SCRAM-SHA-256 verifier（RFC 5802／7677）。"""
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    stored = hashlib.sha256(hmac.new(salted, b"Client Key", hashlib.sha256).digest()).digest()
    server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    encode = base64.b64encode
    return (
        f"SCRAM-SHA-256${iterations}:{encode(salt).decode()}"
        f"${encode(stored).decode()}:{encode(server).decode()}"
    )


def test_scram_matches_only_the_right_password() -> None:
    verifier = _verifier(OWNER_PASSWORD)

    assert scram_matches(verifier, OWNER_PASSWORD)
    assert not scram_matches(verifier, OWNER_PASSWORD + "x")


@pytest.mark.parametrize(
    "verifier",
    [
        None,
        "md5" + "0" * 32,
        "SCRAM-SHA-256$4096:not base64!$AAAA:AAAA",
        "SCRAM-SHA-256$0:AAAA$AAAA:AAAA",
        "SCRAM-SHA-256$4096:AAA$AAAA:AAAA",
    ],
)
def test_scram_refuses_anything_it_cannot_verify(verifier: str | None) -> None:
    assert not scram_matches(verifier, OWNER_PASSWORD)


def test_scram_refuses_passwords_that_postgres_would_saslprep() -> None:
    """非 ASCII 的密碼 PostgreSQL 會先做 SASLprep；這裡不實作，一律視為不相符（fail closed）。"""
    password = "密碼" + secrets.token_hex(4)

    assert not scram_matches(_verifier(password), password)


# ---------------------------------------------------------------- 設定


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {"app_env": "test", "_env_file": None, **overrides}
    return Settings(**values)  # type: ignore[arg-type]


def _credentials(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_the_target_comes_from_the_db_owner_and_admin_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _credentials(monkeypatch, DB_OWNER_PASSWORD=OWNER_PASSWORD, DB_ADMIN_PASSWORD=ADMIN_PASSWORD)

    target = target_from(_settings(db_port=55432))

    assert (target.host, target.port, target.database) == ("127.0.0.1", 55432, "secscan")
    assert (target.app_role, target.owner_role, target.admin_user) == (
        "secscan_app",
        "secscan_owner",
        "postgres",
    )
    assert target.owner_password.get_secret_value() == OWNER_PASSWORD
    assert target.expected_cluster == DEV_CLUSTER_NAME
    assert OWNER_PASSWORD not in repr(target)


@pytest.mark.parametrize(
    ("environment", "settings", "error"),
    [
        ({"DB_ADMIN_PASSWORD": ADMIN_PASSWORD}, {}, MissingOwnerPasswordError),
        ({"DB_OWNER_PASSWORD": OWNER_PASSWORD}, {}, ValueError),
        (
            {"DB_OWNER_PASSWORD": OWNER_PASSWORD, "DB_ADMIN_PASSWORD": ADMIN_PASSWORD},
            {"db_host": "10.0.0.5"},
            ValueError,
        ),
        (
            {
                "DB_OWNER_PASSWORD": OWNER_PASSWORD,
                "DB_ADMIN_PASSWORD": ADMIN_PASSWORD,
                "DB_OWNER_USER": "secscan_app",
            },
            {},
            OwnerIsAppRoleError,
        ),
        (
            {"DB_OWNER_PASSWORD": OWNER_PASSWORD, "DB_ADMIN_PASSWORD": ADMIN_PASSWORD},
            {"db_user": "Secscan-App"},
            ValueError,
        ),
    ],
)
def test_unsafe_settings_are_refused_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
    environment: dict[str, str],
    settings: dict[str, object],
    error: type[Exception],
) -> None:
    _credentials(monkeypatch, **environment)

    with pytest.raises(error):
        target_from(_settings(**settings))


def test_the_command_reports_settings_errors_without_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _credentials(monkeypatch, DB_OWNER_PASSWORD=OWNER_PASSWORD, DB_ADMIN_PASSWORD=ADMIN_PASSWORD)
    messages: list[str] = []
    args = argparse.Namespace(command=db_roles.COMMAND, dry_run=True)

    result = db_roles.run(args, _settings(db_host="db.example"), messages.append)

    assert result == EXIT_FAILURE
    assert "loopback" in messages[0]
    assert all(OWNER_PASSWORD not in line and ADMIN_PASSWORD not in line for line in messages)


def test_other_commands_are_not_handled() -> None:
    args = argparse.Namespace(command="worker")

    assert db_roles.run(args, _settings(), lambda _: None) is None


def test_the_admin_credentials_default_to_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_ADMIN_PASSWORD", ADMIN_PASSWORD)

    admin = AdminCredentials()

    assert admin.user == "postgres"
    assert admin.password == SecretStr(ADMIN_PASSWORD)


# ---------------------------------------------------------------- migration 的憑證


def test_the_owner_settings_keep_everything_but_the_role() -> None:
    settings = _settings(db_host="::1", db_port=55434, db_name="secscan", db_lock_timeout_seconds=3)
    credentials = MigrationCredentials(password=SecretStr(OWNER_PASSWORD))

    owner = credentials.owner_settings(settings)

    assert (owner.db_host, owner.db_port, owner.db_name) == ("::1", 55434, "secscan")
    assert owner.db_lock_timeout_seconds == 3
    assert (owner.db_user, owner.db_password) == ("secscan_owner", SecretStr(OWNER_PASSWORD))
    assert settings.db_user == "secscan_app"


@pytest.mark.parametrize("password", [None, SecretStr("   ")])
def test_the_owner_password_is_required(password: SecretStr | None) -> None:
    with pytest.raises(MissingOwnerPasswordError, match="make env"):
        MigrationCredentials(password=password).owner_settings(_settings())


def test_the_owner_must_differ_from_the_app_role() -> None:
    credentials = MigrationCredentials(user="secscan_app", password=SecretStr(OWNER_PASSWORD))

    with pytest.raises(OwnerIsAppRoleError):
        credentials.owner_settings(_settings())


# ---------------------------------------------------------------- v0025 的 offline SQL


def _offline_sql(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *x: str) -> str:
    monkeypatch.chdir(tmp_path)
    config = alembic_config()
    config.cmd_opts = argparse.Namespace(x=list(x))
    buffer = io.StringIO()
    config.output_buffer = buffer
    command.upgrade(config, "0024:0025", sql=True)
    return buffer.getvalue()


def test_offline_sql_grants_the_matrix_and_the_global_function_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _offline_sql(tmp_path, monkeypatch)

    assert "GRANT SELECT, INSERT ON TABLE public.api_spec_operations" in script
    assert 'GRANT INSERT ON TABLE public.run_rule_locations TO "secscan_app"' in script
    assert 'GRANT SELECT ON TABLE public.alembic_version TO "secscan_app"' in script
    assert "REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA public FROM PUBLIC" in script
    assert "ALTER DEFAULT PRIVILEGES FOR ROLE ' || quote_ident(current_user)" in script
    assert "IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS" not in script
    assert re.search(r"GRANT [A-Z, ]*(TRUNCATE|REFERENCES|TRIGGER|MAINTAIN|ALL)", script) is None


def test_offline_sql_takes_the_app_role_from_x_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = _offline_sql(tmp_path, monkeypatch, "app_role=lab_app")

    assert 'TO "lab_app"' in script
    assert "secscan_app" not in script


def test_offline_sql_refuses_an_unsafe_app_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(RuntimeError, match="v0025 需要"):
        _offline_sql(tmp_path, monkeypatch, 'app_role=evil"; DROP TABLE scans; --')


# ---------------------------------------------------------------- T23b-b1 審查之後新增


def test_the_generated_verifier_matches_only_its_password() -> None:
    """CREATE ROLE 以本機產生的 verifier 傳送，明文不到伺服器（安全審查 L1）。"""
    verifier = scram_verifier(OWNER_PASSWORD)

    assert verifier.startswith("SCRAM-SHA-256$4096:")
    assert scram_matches(verifier, OWNER_PASSWORD)
    assert not scram_matches(verifier, OWNER_PASSWORD + "x")
    assert OWNER_PASSWORD not in verifier
    assert scram_verifier(OWNER_PASSWORD) != verifier  # 每次的 salt 不同


def test_the_verifier_refuses_passwords_postgres_would_saslprep() -> None:
    with pytest.raises(UnsupportedPasswordError):
        scram_verifier("密碼")


@pytest.mark.parametrize("name", ["Secscan_Owner", "pg_owner", "owner-1", "owner;drop", ""])
def test_the_owner_role_name_follows_the_v0025_rule(name: str) -> None:
    with pytest.raises(ValidationError):
        MigrationCredentials(user=name, password=SecretStr(OWNER_PASSWORD))


def test_an_app_role_with_the_reserved_prefix_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _credentials(monkeypatch, DB_OWNER_PASSWORD=OWNER_PASSWORD, DB_ADMIN_PASSWORD=ADMIN_PASSWORD)

    with pytest.raises(ValueError, match="pg_"):
        target_from(_settings(db_user="pg_app"))


def test_invalid_settings_are_described_without_their_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _credentials(monkeypatch, DB_OWNER_USER="Bad-Owner", DB_OWNER_PASSWORD=OWNER_PASSWORD)
    messages: list[str] = []
    args = argparse.Namespace(command=db_roles.COMMAND, dry_run=False)

    assert db_roles.run(args, _settings(), messages.append) == EXIT_FAILURE

    assert "user" in messages[0]
    assert "Bad-Owner" not in messages[0]
    assert OWNER_PASSWORD not in messages[0]


def test_the_command_is_registered_with_a_dry_run_flag() -> None:
    from secscan.cli import _parser

    assert _parser().parse_args(["migrate-db-roles", "--dry-run"]).dry_run is True
    assert _parser().parse_args(["migrate-db-roles"]).dry_run is False
