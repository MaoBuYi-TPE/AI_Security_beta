"""Alembic 設定與 model 登記的結構檢查（不連 DB）。"""

import importlib
import io
import pkgutil
import tomllib
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory

import secscan
from secscan.core.db import Base
from secscan.migrations import MIGRATIONS_DIR, alembic_config, head_revision
from secscan.migrations.metadata import MODELS, target_metadata

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_cli_and_code_use_the_same_script_location() -> None:
    """`alembic` CLI 讀 pyproject；程式與測試用 alembic_config()。兩者必須指向同一個目錄。"""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    configured = pyproject["tool"]["alembic"]["script_location"]

    resolved = Path(configured.replace("%(here)s", str(REPO_ROOT))).resolve()

    assert resolved == MIGRATIONS_DIR
    assert Path(alembic_config().get_main_option("script_location") or "") == MIGRATIONS_DIR


def test_migrations_have_a_single_head() -> None:
    heads = ScriptDirectory.from_config(alembic_config()).get_heads()

    assert heads == [head_revision()]


def test_head_revision_refuses_branched_history(monkeypatch: pytest.MonkeyPatch) -> None:
    """兩個 migration 都接在同一個前版時會產生兩個 head；此時不能猜哪個才是目前版本。"""
    monkeypatch.setattr(ScriptDirectory, "get_heads", lambda _self: ["0002a", "0002b"])

    with pytest.raises(RuntimeError, match="head"):
        head_revision.__wrapped__()


def test_registry_covers_every_feature_models_module() -> None:
    """新增 <feature>/models.py 卻忘了登記時，autogenerate 與漂移檢查會漏掉它。"""
    for module in pkgutil.walk_packages(secscan.__path__, prefix="secscan."):
        if module.name.endswith(".models") and ".migrations" not in module.name:
            importlib.import_module(module.name)

    registered = {model.__tablename__ for model in MODELS}

    assert set(Base.metadata.tables) == registered
    assert target_metadata is Base.metadata


def test_offline_mode_renders_sql_without_connection_or_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`alembic upgrade head --sql` 只產生 SQL 供審查：不連線，也不需要 DB 密碼。"""
    monkeypatch.delenv("APP_ENV", raising=False)  # prod：若讀了 Settings 就會因缺密碼而失敗
    monkeypatch.chdir(tmp_path)
    config = alembic_config()
    buffer = io.StringIO()
    config.output_buffer = buffer

    command.upgrade(config, "head", sql=True)

    script = buffer.getvalue()
    for expected in (
        "BEGIN;",
        "CREATE TABLE projects",
        "CREATE TABLE api_keys",
        "CREATE TABLE audit_events",
        "CREATE TRIGGER audit_events_append_only",
        "CREATE TRIGGER audit_events_no_truncate",
        "CREATE TABLE targets",
        "CREATE TABLE scope_grants",
        "CREATE TRIGGER scope_grants_guard_rows",
        "CREATE TRIGGER scope_grants_no_truncate",
        "INSERT INTO alembic_version (version_num) VALUES ('0001')",
        # 之後每個 migration 都以 UPDATE 把版本往前推，最後停在 head。
        "UPDATE alembic_version SET version_num=",
        f"version_num='{head_revision()}' WHERE",
        "COMMIT;",
    ):
        assert expected in script
