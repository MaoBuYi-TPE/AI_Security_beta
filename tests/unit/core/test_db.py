"""DB 連線設定與型別的單元測試（不連線；實際連線與約束見 tests/integration）。"""

from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest
from fastapi import FastAPI, Request
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool, QueuePool

from secscan.core.config import Settings
from secscan.core.db import (
    ConstraintViolationError,
    UtcDateTime,
    create_db_engine,
    database_resources,
    database_url,
    flush_or_raise,
)
from secscan.migrations import render_item

PASSWORD = "unit-test-password-0001"
TAIPEI = timezone(timedelta(hours=8))
DIALECT = postgresql.dialect()  # type: ignore[no-untyped-call]


class _FailingSession:
    """flush 時丟出不是來自 psycopg 的 IntegrityError（例如其他 driver 或手動建立的錯誤）。"""

    def flush(self) -> None:
        raise IntegrityError("INSERT ...", {"key_hash": b"canary"}, ValueError("not psycopg"))


def _settings(**overrides: object) -> Settings:
    return Settings.model_validate({"app_env": "test", "db_password": PASSWORD, **overrides})


def test_database_url_uses_psycopg_and_settings() -> None:
    url = database_url(_settings(db_host="db.internal", db_port=5432, db_name="app", db_user="svc"))

    assert url.drivername == "postgresql+psycopg"
    assert (url.host, url.port, url.database, url.username) == ("db.internal", 5432, "app", "svc")
    assert url.password == PASSWORD


def test_database_url_hides_password_when_rendered() -> None:
    url = database_url(_settings())

    assert PASSWORD not in str(url)
    assert PASSWORD not in repr(url)
    assert PASSWORD in url.render_as_string(hide_password=False)


def test_database_url_without_password_has_no_password() -> None:
    url = database_url(Settings(app_env="test", _env_file=None))

    assert url.password is None


def test_engine_sets_timeouts_application_name_and_utc() -> None:
    engine = create_db_engine(
        _settings(
            db_connect_timeout_seconds=3,
            db_statement_timeout_seconds=20,
            db_lock_timeout_seconds=2,
            db_idle_in_transaction_timeout_seconds=40,
        ),
        application_name="secscan-x",
    )

    assert dict(engine.url.query) == {
        "application_name": "secscan-x",
        "connect_timeout": "3",
        "options": (
            "-c timezone=UTC -c statement_timeout=20000 -c lock_timeout=2000 "
            "-c idle_in_transaction_session_timeout=40000"
        ),
    }


def test_engine_is_pooled_by_default_and_can_disable_pooling() -> None:
    assert isinstance(create_db_engine(_settings()).pool, QueuePool)
    assert isinstance(create_db_engine(_settings(), pooled=False).pool, NullPool)


@pytest.mark.parametrize("pooled", [True, False])
def test_engine_hides_sql_parameters_in_errors(pooled: bool) -> None:
    """SQL 參數（key hash、稽核內容、日後的密文）不得出現在例外訊息與日誌中。"""
    assert create_db_engine(_settings(), pooled=pooled).hide_parameters is True


def test_engine_repr_masks_password() -> None:
    assert PASSWORD not in repr(create_db_engine(_settings()))


def test_database_resources_require_app_initialization() -> None:
    """app.state.db 沒有設定時要明確失敗，而不是拿到 None 之後才在別處出錯。"""
    request = Request({"type": "http", "app": FastAPI(), "headers": []})

    with pytest.raises(RuntimeError, match=r"app\.state\.db"):
        database_resources(request)


def test_unknown_integrity_error_still_becomes_constraint_violation() -> None:
    with pytest.raises(ConstraintViolationError) as caught:
        flush_or_raise(cast(Session, _FailingSession()))

    assert (caught.value.constraint, caught.value.sqlstate) == (None, None)
    # 原始例外含 SQL 參數與 DB 的 DETAIL（可能有資料值），不再接在例外鏈上。
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    assert "canary" not in str(caught.value)


def test_utc_datetime_rejects_naive_values() -> None:
    with pytest.raises(ValueError, match="時區"):
        UtcDateTime().process_bind_param(datetime(2027, 6, 30), DIALECT)


def test_utc_datetime_stores_and_returns_utc() -> None:
    taipei_noon = datetime(2027, 6, 30, 12, 0, tzinfo=TAIPEI)
    column_type = UtcDateTime()

    stored = column_type.process_bind_param(taipei_noon, DIALECT)
    loaded = column_type.process_result_value(taipei_noon, DIALECT)

    assert stored == loaded == datetime(2027, 6, 30, 4, 0, tzinfo=UTC)
    assert stored is not None
    assert stored.tzinfo is UTC
    assert column_type.process_bind_param(None, DIALECT) is None
    assert column_type.process_result_value(None, DIALECT) is None


def test_migrations_render_utc_datetime_as_plain_timestamptz() -> None:
    """autogenerate 產生的 migration 不 import 應用程式型別，保持可獨立重播。"""
    assert render_item("type", UtcDateTime(), None) == "sa.DateTime(timezone=True)"
    assert render_item("type", postgresql.JSONB(), None) is False
    assert render_item("column", UtcDateTime(), None) is False
