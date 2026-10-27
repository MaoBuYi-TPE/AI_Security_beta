"""資料庫基礎（docs/ARCHITECTURE.md §6）：命名慣例、Declarative Base、UTC 時間型別、
engine 工廠、readiness 檢查，以及把約束錯誤轉成不依賴 SQLAlchemy 的例外。

PostgreSQL 是唯一事實來源。ORM model 放在各功能模組的 models.py，並登記在
secscan.migrations.metadata；repository 只回傳 frozen domain model。domain 模組不得 import
這裡（import-linter 強制）。
"""

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated
from uuid import UUID, uuid4

import psycopg
from fastapi import Depends, Request
from sqlalchemy import URL, DateTime, Dialect, Engine, MetaData, create_engine, func, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column
from sqlalchemy.pool import NullPool
from sqlalchemy.types import TypeDecorator

from secscan.core.config import Settings

logger = logging.getLogger(__name__)

# 約束與索引名稱固定可預期：migration 可重現，service 也能依約束名稱對應錯誤碼。
NAMING_CONVENTION = {
    "pk": "pk_%(table_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
}

DRIVER = "postgresql+psycopg"
DEFAULT_APPLICATION_NAME = "secscan-api"
MILLISECONDS_PER_SECOND = 1_000


class UtcDateTime(TypeDecorator[datetime]):
    """timestamptz；拒絕沒有時區的 datetime，讀出時一律轉成 UTC。

    沒有時區的時間（例如台北機器上的 datetime.now()）會被 DB 當成 UTC 存，靜默差 8 小時，
    所以在送進 DB 之前就擋下。
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("拒絕沒有時區的 datetime：請傳入帶時區（建議 UTC）的時間")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    # 所有 datetime 欄位都是 UtcDateTime；以唯讀 mapping 宣告，避免被意外修改。
    type_annotation_map = MappingProxyType({datetime: UtcDateTime()})


class UuidPrimaryKeyMixin:
    """UUID 主鍵：ORM 端先產生（同一 transaction 內即可引用），DB 端也有預設值。"""

    # sort_order：讓主鍵排在資料表的第一欄（mixin 欄位預設排在子類別欄位之後）。
    id: Mapped[UUID] = mapped_column(
        primary_key=True, default=uuid4, server_default=func.gen_random_uuid(), sort_order=-1
    )


class CreatedAtMixin:
    """建立時間以 DB 時鐘為準（transaction 開始時間），避免應用程式時鐘偏差。

    同一個 transaction 建立的多筆資料時間相同；需要嚴格先後順序時另用序號欄位。
    """

    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


def database_url(settings: Settings) -> URL:
    """由個別欄位組出連線 URL（密碼會正確跳脫，str/repr 時自動遮罩）。"""
    password = settings.db_password.get_secret_value() if settings.db_password else None
    return URL.create(
        DRIVER,
        username=settings.db_user,
        password=password,
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
    )


def session_options(settings: Settings) -> str:
    """每個連線的 session 設定（libpq 的 options）。

    - timezone=UTC：固定以 UTC 解讀 timestamptz（CLAUDE.md §11）。
    - 逾時（docs/DECISIONS.md §13.8）：statement 與等鎖都有上限，transaction 中閒置太久就終止
      session，不會無限期持有鎖、卡住撤銷或取消。不寫在 postgresql.conf，只影響應用程式的連線。
    """
    timeouts = {
        "statement_timeout": settings.db_statement_timeout_seconds,
        "lock_timeout": settings.db_lock_timeout_seconds,
        "idle_in_transaction_session_timeout": settings.db_idle_in_transaction_timeout_seconds,
    }
    return " ".join(
        ["-c timezone=UTC"]
        + [f"-c {name}={seconds * MILLISECONDS_PER_SECOND}" for name, seconds in timeouts.items()]
    )


def create_db_engine(
    settings: Settings,
    *,
    application_name: str = DEFAULT_APPLICATION_NAME,
    pooled: bool = True,
) -> Engine:
    """建立 engine（不會立即連線）。pooled=False 給一次性的程序，例如 migration。

    hide_parameters：SQL 參數（key hash、稽核內容、日後的密文）不出現在例外訊息與日誌中。
    """
    url = database_url(settings).update_query_dict(
        {
            "application_name": application_name,
            "connect_timeout": str(settings.db_connect_timeout_seconds),
            "options": session_options(settings),
        }
    )
    if pooled:
        return create_engine(url, pool_pre_ping=True, hide_parameters=True)
    return create_engine(url, poolclass=NullPool, hide_parameters=True)


class DatabaseStatus(StrEnum):
    READY = "ready"
    UNAVAILABLE = "unavailable"
    SCHEMA_OUTDATED = "schema_outdated"


def probe_database(engine: Engine, expected_revision: str) -> DatabaseStatus:
    """readiness 用：能否連線，以及 schema 是否正好在預期的 migration 版本。

    DB 錯誤一律回報 UNAVAILABLE 並記下例外類別與 SQLSTATE；不記錯誤訊息，因為驅動的訊息
    含主機、port 與帳號。
    """
    try:
        with engine.connect() as connection:
            table = connection.execute(text("SELECT to_regclass('alembic_version')")).scalar()
            if table is None:
                return DatabaseStatus.SCHEMA_OUTDATED
            revisions = connection.execute(text("SELECT version_num FROM alembic_version"))
            current = list(revisions.scalars())
    except (DBAPIError, PoolTimeoutError) as exc:
        origin = exc.orig if isinstance(exc, DBAPIError) else exc
        logger.warning(
            "database readiness probe failed: error_type=%s sqlstate=%s",
            type(origin).__name__,
            getattr(origin, "sqlstate", None),
        )
        return DatabaseStatus.UNAVAILABLE
    if current == [expected_revision]:
        return DatabaseStatus.READY
    return DatabaseStatus.SCHEMA_OUTDATED


@dataclass(frozen=True, slots=True)
class DatabaseResources:
    """應用程式層級的 DB 資源，由 main.create_app 建立並放在 app.state.db。"""

    engine: Engine
    schema_revision: str


def database_resources(request: Request) -> DatabaseResources:
    """FastAPI 依賴：取出 app 啟動時建立的 DB 資源。"""
    resources = getattr(request.app.state, "db", None)
    if not isinstance(resources, DatabaseResources):
        raise RuntimeError("資料庫資源尚未初始化（create_app 應設定 app.state.db）")
    return resources


def request_session(
    resources: Annotated[DatabaseResources, Depends(database_resources)],
) -> Iterator[Session]:
    """每個請求一個 session 與 transaction：正常結束時 commit，有例外時 rollback。

    一律以 DbSession 使用：scope="function" 讓依賴在回應送出「之前」結束，commit 失敗會變成 500，
    client 不會先拿到成功的回應（預設 scope 在回應送出之後才結束；docs/DECISIONS.md §9.3）。
    """
    with Session(resources.engine, expire_on_commit=False) as session, session.begin():
        yield session


DbSession = Annotated[Session, Depends(request_session, scope="function")]


class ConstraintViolationError(Exception):
    """寫入違反資料庫約束。

    constraint 為約束名稱（依 NAMING_CONVENTION），sqlstate 為 PostgreSQL 錯誤碼，不明時為 None。
    兩者只供 service 對應穩定錯誤碼，不可原樣回給 client。
    """

    def __init__(self, constraint: str | None, sqlstate: str | None) -> None:
        super().__init__(f"違反資料庫約束：{constraint or '未知'}（SQLSTATE {sqlstate or '未知'}）")
        self.constraint = constraint
        self.sqlstate = sqlstate


def flush_or_raise(session: Session) -> None:
    """flush 並把 IntegrityError 轉成 ConstraintViolationError；呼叫端的 transaction 須回滾。

    不把原始例外接在例外鏈上：它含 SQL 與 DB 的 DETAIL（例如重複的 key hash 值），
    一旦進入 traceback 就會寫進日誌。約束名稱與 SQLSTATE 已足夠判斷原因。
    """
    try:
        session.flush()
    except IntegrityError as exc:
        constraint, sqlstate = _constraint_details(exc)
        raise ConstraintViolationError(constraint, sqlstate) from None


def _constraint_details(exc: IntegrityError) -> tuple[str | None, str | None]:
    if isinstance(exc.orig, psycopg.Error):
        return exc.orig.diag.constraint_name, exc.orig.sqlstate
    return None, None
