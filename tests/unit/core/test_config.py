import re
from ipaddress import IPv4Network
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from secscan.core.config import DEFAULT_LAB_CIDR, ENV_FILE, AppEnv, Settings

REPO_ROOT = Path(__file__).resolve().parents[3]


def test_defaults_to_prod_when_app_env_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setenv("DB_PASSWORD", "prod-requires-a-password")

    settings = Settings(_env_file=None)

    assert settings.app_env == "prod"
    assert settings.docs_enabled is False


def test_reads_app_env_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "dev")

    assert Settings(_env_file=None).app_env == "dev"


def test_reads_app_env_from_env_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("APP_ENV", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("APP_ENV=dev\n", encoding="utf-8")

    assert Settings(_env_file=env_file).app_env == "dev"


def test_default_settings_read_dotenv_in_cwd_and_ignore_unrelated_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # 測試環境預設不讀 .env（tests/conftest.py）；這裡還原成正式程式的預設值來驗證它。
    monkeypatch.setitem(Settings.model_config, "env_file", ENV_FILE)
    monkeypatch.delenv("APP_ENV", raising=False)
    (tmp_path / ".env").write_text("APP_ENV=dev\nUNRELATED_KEY=1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert Settings().app_env == "dev"


def test_rejects_unknown_app_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "staging")

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_are_immutable() -> None:
    settings = Settings(app_env="test", _env_file=None)

    with pytest.raises(ValidationError):
        settings.app_env = "dev"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("app_env", "expected"),
    [("dev", True), ("test", False), ("prod", False)],
)
def test_docs_enabled_only_in_dev(app_env: AppEnv, expected: bool) -> None:
    settings = Settings(app_env=app_env, db_password=SecretStr("pw"), _env_file=None)

    assert settings.docs_enabled is expected


def test_database_defaults_point_to_local_dev_db() -> None:
    settings = Settings(app_env="dev", _env_file=None)

    assert settings.db_host == "127.0.0.1"
    assert settings.db_port == 55432
    assert settings.db_name == "secscan"
    assert settings.db_user == "secscan_app"
    assert settings.db_password is None
    assert settings.db_connect_timeout_seconds == 5


def test_reads_database_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DB_HOST", "db.control.internal")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_NAME", "secscan_prod")
    monkeypatch.setenv("DB_USER", "secscan_service")
    monkeypatch.setenv("DB_PASSWORD", "pw-from-env")
    monkeypatch.setenv("DB_CONNECT_TIMEOUT_SECONDS", "2")

    settings = Settings(app_env="prod", _env_file=None)

    assert settings.db_host == "db.control.internal"
    assert settings.db_port == 5432
    assert settings.db_name == "secscan_prod"
    assert settings.db_user == "secscan_service"
    assert settings.db_password is not None
    assert settings.db_password.get_secret_value() == "pw-from-env"
    assert settings.db_connect_timeout_seconds == 2


def test_prod_fails_fast_without_db_password() -> None:
    with pytest.raises(ValidationError, match="DB_PASSWORD"):
        Settings(app_env="prod", _env_file=None)


@pytest.mark.parametrize("password", ["", "   "])
def test_prod_rejects_blank_db_password(password: str) -> None:
    with pytest.raises(ValidationError, match="DB_PASSWORD"):
        Settings(app_env="prod", db_password=SecretStr(password), _env_file=None)


@pytest.mark.parametrize("app_env", ["dev", "test"])
def test_non_prod_allows_missing_db_password(app_env: AppEnv) -> None:
    assert Settings(app_env=app_env, _env_file=None).db_password is None


@pytest.mark.parametrize("port", [0, 65536])
def test_rejects_out_of_range_db_port(port: int) -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="test", db_port=port, _env_file=None)


@pytest.mark.parametrize("timeout", [0, 61])
def test_rejects_out_of_range_connect_timeout(timeout: int) -> None:
    with pytest.raises(ValidationError):
        Settings(app_env="test", db_connect_timeout_seconds=timeout, _env_file=None)


@pytest.mark.parametrize("field", ["db_host", "db_name", "db_user"])
def test_rejects_blank_database_identifiers(field: str) -> None:
    with pytest.raises(ValidationError):
        Settings.model_validate({"app_env": "test", field: ""})


def test_settings_repr_masks_db_password() -> None:
    settings = Settings(app_env="test", db_password=SecretStr("super-secret-value"), _env_file=None)

    assert "super-secret-value" not in repr(settings)
    assert "super-secret-value" not in str(settings)


# --- LAB_ONLY 與 LAB_CIDR（docs/DECISIONS.md §10.1）-------------------------------------------


def test_lab_only_by_default_with_the_lab_network() -> None:
    settings = Settings(app_env="test", _env_file=None)

    assert settings.lab_only is True
    assert settings.lab_cidr == IPv4Network("10.89.7.0/24")


def test_default_lab_cidr_is_the_lab_compose_network() -> None:
    """預設值必須是 compose.lab.yaml 的 lab_net；只改其中一邊時，這裡會失敗。"""
    compose = (REPO_ROOT / "compose.lab.yaml").read_text(encoding="utf-8")

    assert re.findall(r"subnet:\s*(\S+)", compose) == [str(DEFAULT_LAB_CIDR)]


@pytest.mark.parametrize("value", ["false", "0", "no"])
def test_lab_only_cannot_be_turned_off(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """P0 只掃 lab：關掉 LAB_ONLY 時啟動就失敗，不會變成可以掃任何 IP。"""
    monkeypatch.setenv("LAB_ONLY", value)

    with pytest.raises(ValidationError, match="LAB_ONLY"):
        Settings(app_env="test", _env_file=None)


@pytest.mark.parametrize("cidr", ["10.89.0.0/16", "172.16.5.0/24", "192.168.56.0/30"])
def test_reads_lab_cidr_from_environment(monkeypatch: pytest.MonkeyPatch, cidr: str) -> None:
    monkeypatch.setenv("LAB_CIDR", cidr)

    assert Settings(app_env="test", _env_file=None).lab_cidr == IPv4Network(cidr)


@pytest.mark.parametrize(
    "cidr",
    [
        "10.89.7.5/24",  # host bits 不為 0
        "10.89.7.0",  # 沒有前綴等於 /32
        "8.8.8.0/24",  # 公開網段
        "100.64.0.0/16",  # CGNAT，不是 RFC 1918
        "127.0.0.0/16",  # loopback
        "169.254.0.0/16",  # link-local（含雲端 metadata 位址）
        "10.0.0.0/8",  # 太寬：等於開放整個私有網段
        "172.16.0.0/12",
        "10.88.0.0/15",
        "10.89.7.0/31",  # 太窄：沒有一般意義的網段與廣播位址
        "10.89.7.4/32",
        "fd00::/64",  # IPv6
        "",
        "lab_net",
    ],
)
def test_rejects_lab_cidr_outside_the_allowed_bounds(
    monkeypatch: pytest.MonkeyPatch, cidr: str
) -> None:
    monkeypatch.setenv("LAB_CIDR", cidr)

    with pytest.raises(ValidationError) as caught:
        Settings(app_env="test", _env_file=None)

    assert [error["loc"] for error in caught.value.errors()] == [("lab_cidr",)]


# --- 目標 secret 的加密金鑰（docs/DECISIONS.md §12.1）---------------------------------------


def test_secret_encryption_keys_are_optional_in_settings() -> None:
    """Settings 只負責讀入：需要金鑰的程序（API、金鑰換版的 CLI）自己檢查。

    create-admin-key 不需要金鑰。
    """
    assert Settings(app_env="test", _env_file=None).secret_encryption_keys is None


def test_secret_encryption_keys_are_read_from_environment_and_masked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECRET_ENCRYPTION_KEYS", "key-material-for-the-test")

    settings = Settings(app_env="test", _env_file=None)

    assert settings.secret_encryption_keys is not None
    assert settings.secret_encryption_keys.get_secret_value() == "key-material-for-the-test"
    assert "key-material-for-the-test" not in repr(settings)
    assert "key-material-for-the-test" not in str(settings)
