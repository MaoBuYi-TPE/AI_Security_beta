"""既有資料庫的擁有權移轉（T23b-b1；docs/DECISIONS.md §31.5）：

    uv run secscan-admin migrate-db-roles [--dry-run]       （make db-roles-migrate [DRY_RUN=1]）

T23b-b1 之前，應用程式角色（DB_USER）擁有開發 DB 與其中所有物件。這個指令把它們移轉給 owner 角色
（DB_OWNER_USER），之後由 make migrate（以 owner 執行）套用 v0025 的逐表權限。只用於已經存在的
資料庫；新建的 DB（initdb）、Live 與 db-test 直接建立兩個角色。

- 在主機上執行：superuser 的密碼取自 DB_ADMIN_PASSWORD（DB_ADMIN_USER，預設 postgres），owner 的帳密
  取自 DB_OWNER_*，目標取自 DB_*。主機只接受 loopback；cluster_name 必須是 secscan-dev。
- 先以 pg_shdepend 列舉應用程式角色與 owner 在所有資料庫中的依賴，以允許清單分類
  （secscan.cli.db_roles_scope）；有任何非預期的項目就拒絕，不自動刪除或移轉（fail closed）。
- dry-run：列出狀態、會不會建立 owner、每一個會移轉的物件與種類的小計、不受影響的範圍、拒絕的理由；
  不做任何改變。
- 執行：在目標資料庫的**同一個 transaction** 中完成：工具專用的 advisory lock、重新列舉與分類、
  沒有 owner 時建立、REASSIGN OWNED（同時移轉目標資料庫本身）、事後檢查（應用程式角色不擁有任何
  物件、owner 擁有原本兩者的聯集、其他角色的物件前後相同）、audit db_roles.migrated，然後 commit。
  任何一步失敗都 rollback，沒有中間狀態；之後以 owner 另外登入一次確認。
- 已移轉（S1、S2）時不寫入任何東西；中斷之後再執行一次就完成。
- 終端、log 與錯誤都不含密碼：CREATE ROLE 以 psycopg 直接執行（例外不含語句），這個 transaction
  關閉 log_statement 與 log_min_error_statement。
"""

import argparse
from collections.abc import Iterable
from dataclasses import dataclass

import psycopg
from psycopg import sql
from pydantic import Field, SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL, Connection, Engine, create_engine, func, select, text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from secscan.audit.service import AuditTrail
from secscan.cli import db_roles_catalog as catalog
from secscan.cli.db_roles_scope import Plan, State, classify
from secscan.cli.keys import Subparsers
from secscan.cli.services import Report
from secscan.core.config import ENV_FILE, Settings
from secscan.migrations.credentials import (
    MigrationCredentials,
    MissingOwnerPasswordError,
    OwnerIsAppRoleError,
    valid_role_name,
)

COMMAND = "migrate-db-roles"
DEV_CLUSTER_NAME = "secscan-dev"
APPLICATION_NAME = "secscan-db-roles"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
EXIT_OK = 0
EXIT_FAILURE = 1
# 工具專用的 advisory lock（"secscanR" 的 8 bytes）：同時執行兩次時，後到的最多等 LOCK_TIMEOUT，
# 之後 rollback 並說明（不會兩個同時移轉）。
TOOL_LOCK_KEY = 0x73656373_63616E52
LOCK_TIMEOUT = "5s"
LOCK_NOT_AVAILABLE = "55P03"
REQUIRE_AUTH = "scram-sha-256"
_STATES = {
    State.LEGACY: "S0（應用程式角色擁有資料庫與物件）",
    State.TRANSFERRED: "S1（已移轉，v0025 還沒套用）",
    State.GRANTED: "S2（已移轉，v0025 已套用）",
}


class AdminCredentials(BaseSettings):
    """superuser 的帳密（環境變數 DB_ADMIN_USER、DB_ADMIN_PASSWORD；make env 產生密碼）。"""

    model_config = SettingsConfigDict(
        env_prefix="DB_ADMIN_",
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    user: str = Field(default="postgres", min_length=1)
    password: SecretStr | None = None


@dataclass(frozen=True, slots=True)
class Target:
    host: str
    port: int
    database: str
    app_role: str
    owner_role: str
    owner_password: SecretStr
    admin_user: str
    admin_password: SecretStr
    connect_timeout_seconds: int
    expected_cluster: str = DEV_CLUSTER_NAME


class MigrationRefusedError(Exception):
    """移轉途中拒絕（建立 owner 失敗、事後檢查不符）；transaction 會 rollback。訊息不含密碼。"""


class CommitUncertainError(Exception):
    """commit 本身失敗：伺服器可能已經 commit，也可能沒有。"""


def register(commands: Subparsers) -> None:
    parser = commands.add_parser(
        COMMAND,
        help="既有的資料庫：把擁有權由應用程式角色移轉給 owner（T23b-b1，只需要一次）",
        description=(
            "以 superuser（DB_ADMIN_*）把 DB_USER 擁有的資料庫與物件移轉給 DB_OWNER_USER；"
            "範圍以允許清單檢查，不符就拒絕。之後執行 make migrate。"
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="只列出範圍，不做任何改變")


def run(args: argparse.Namespace, settings: Settings, report: Report) -> int | None:
    if args.command != COMMAND:
        return None
    try:
        target = target_from(settings)
    except (ValidationError, ValueError, MissingOwnerPasswordError, OwnerIsAppRoleError) as exc:
        report(f"設定不正確：{_reason(exc)}（沒有做任何改變）")
        return EXIT_FAILURE
    return migrate_db_roles(target, dry_run=args.dry_run, report=report)


def target_from(settings: Settings) -> Target:
    owner = MigrationCredentials()
    owner_password = owner.required_password(settings)
    admin = AdminCredentials()
    if admin.password is None or not admin.password.get_secret_value().strip():
        raise ValueError("缺少 DB_ADMIN_PASSWORD（make env 產生；superuser 的密碼）")
    if settings.db_host not in LOOPBACK_HOSTS:
        raise ValueError(f"DB_HOST 只接受 loopback 位址 {sorted(LOOPBACK_HOSTS)}")
    if not valid_role_name(settings.db_user):
        raise ValueError("DB_USER 只接受小寫英數與底線，不可以 pg_ 開頭（v0025 的規則）")
    return Target(
        host=settings.db_host,
        port=settings.db_port,
        database=settings.db_name,
        app_role=settings.db_user,
        owner_role=owner.user,
        owner_password=owner_password,
        admin_user=admin.user,
        admin_password=admin.password,
        connect_timeout_seconds=settings.db_connect_timeout_seconds,
    )


def migrate_db_roles(target: Target, *, dry_run: bool, report: Report) -> int:
    engine = _engine(target, target.admin_user, target.admin_password)
    try:
        try:
            connection = engine.connect()
        except OperationalError:
            report(
                "無法以 superuser（DB_ADMIN_USER）連到目標資料庫：確認 db 已啟動、"
                "DB_ADMIN_PASSWORD 與 DB_* 正確（沒有做任何改變）"
            )
            return EXIT_FAILURE
        with connection:
            result = _guarded(connection, target, dry_run=dry_run, report=report)
    finally:
        engine.dispose()
    if result is not None:
        return result
    return confirm_owner_login(target, report)


def _guarded(
    connection: Connection, target: Target, *, dry_run: bool, report: Report
) -> int | None:
    """把拒絕與 DB 錯誤轉成說明；commit 本身失敗時結果不確定，另外說明。"""
    try:
        return _transfer(connection, target, dry_run=dry_run, report=report)
    except MigrationRefusedError as exc:
        report(f"{exc}：transaction 已 rollback，沒有做任何改變")
    except CommitUncertainError:
        report(
            "commit 時發生錯誤：移轉的結果不確定。請以 make db-roles-migrate DRY_RUN=1 確認"
            "目前的狀態（S0 代表沒有移轉，S1 代表已經移轉）"
        )
    except DBAPIError as exc:
        origin = exc.orig
        sqlstate = getattr(origin, "sqlstate", None)
        if sqlstate == LOCK_NOT_AVAILABLE:
            report(
                f"等鎖超過 {LOCK_TIMEOUT}（另一個 migrate-db-roles 正在執行，或還有連線持有資料表的"
                "鎖）：transaction 已 rollback，沒有做任何改變；確認之後再執行一次"
            )
        else:
            report(
                f"資料庫錯誤（{type(origin).__name__}，SQLSTATE {sqlstate or '未知'}）："
                "transaction 已 rollback，沒有做任何改變"
            )
    return EXIT_FAILURE


def _transfer(
    connection: Connection, target: Target, *, dry_run: bool, report: Report
) -> int | None:
    """回傳 exit code；None 代表要再確認 owner 能登入。"""
    roles = {"app": target.app_role, "owner": target.owner_role}
    password = target.owner_password.get_secret_value()
    with connection.begin() as transaction:
        cluster = connection.execute(text("SHOW cluster_name")).scalar_one()
        if cluster != target.expected_cluster:
            transaction.rollback()
            report(
                f"拒絕：cluster_name 是 {cluster!r}，只接受 {target.expected_cluster!r}"
                "（沒有做任何改變）"
            )
            return EXIT_FAILURE
        _prepare(connection)
        plan = classify(catalog.snapshot(connection, owner_password=password, **roles))
        _describe(plan, target, report, dry_run=dry_run)
        outcome = _outcome(plan, dry_run=dry_run, report=report)
        if outcome is not _EXECUTE:
            transaction.rollback()
            return outcome
        _execute(connection, target, plan)
        try:
            transaction.commit()
        except DBAPIError:
            raise CommitUncertainError from None
    report(f"已移轉 {len(plan.transfers)} 個物件給 {target.owner_role}。")
    return None


_EXECUTE = -1


def _outcome(plan: Plan, *, dry_run: bool, report: Report) -> int | None:
    """不需要寫入時的結果（exit code，或 None 代表確認 owner 能登入）；要移轉時回傳 _EXECUTE。"""
    if plan.refused:
        return EXIT_FAILURE
    if plan.state is not State.LEGACY:
        report("已完成移轉：沒有做任何改變。")
        return None
    if dry_run:
        report("dry-run：沒有做任何改變；確認上面的範圍之後執行 make db-roles-migrate。")
        return EXIT_OK
    return _EXECUTE


def _execute(connection: Connection, target: Target, plan: Plan) -> None:
    """建立 owner、REASSIGN OWNED、事後檢查與 audit（呼叫端在同一個 transaction 中 commit）。"""
    roles = {"app": target.app_role, "owner": target.owner_role}
    before = catalog.ownership(connection, **roles)
    # 分類與這次讀取之間若有新的物件（READ COMMITTED），兩者就不同：不移轉沒有分類過的物件。
    if frozenset(item.key for item in plan.transfers) != before.app:
        raise MigrationRefusedError("分類之後應用程式角色擁有的物件改變了")
    third_party = catalog.third_party_objects(connection, **roles)
    if plan.create_owner:
        _create_owner(connection, target)
    _reassign(connection, target)
    problems = catalog.ownership_problems(before, catalog.ownership(connection, **roles))
    if catalog.third_party_objects(connection, **roles) != third_party:
        problems = (*problems, "移轉前後目標資料庫中其他角色的物件不同")
    # 同一個 transaction 中重新分類：必須是 S1（已移轉、v0025 還沒套用），而且沒有任何拒絕的項目。
    after = classify(
        catalog.snapshot(
            connection, owner_password=target.owner_password.get_secret_value(), **roles
        )
    )
    if after.refused or after.state is not State.TRANSFERRED:
        problems = (*problems, "移轉之後重新分類的結果不是 S1", *after.refusals)
    if problems:
        raise MigrationRefusedError("事後檢查不符（" + "；".join(problems) + "）")
    record_audit(connection, plan)


def _prepare(connection: Connection) -> None:
    """這個 transaction 的設定：等鎖的上限、不記錄語句（CREATE ROLE 含密碼），以及工具的鎖。"""
    connection.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
    connection.execute(text("SET LOCAL log_statement = 'none'"))
    connection.execute(text("SET LOCAL log_min_error_statement = panic"))
    connection.execute(text("SET LOCAL log_min_duration_statement = -1"))
    connection.execute(select(func.pg_advisory_xact_lock(TOOL_LOCK_KEY)))


def _create_owner(connection: Connection, target: Target) -> None:
    """psycopg 直接執行：SQLAlchemy 的例外訊息會帶語句（含密碼），psycopg 的不會。"""
    raw = psycopg_connection(connection)
    statement = sql.SQL(
        "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS "
        "PASSWORD {}"
    ).format(
        sql.Identifier(target.owner_role), sql.Literal(target.owner_password.get_secret_value())
    )
    try:
        raw.execute(statement)
    except psycopg.Error as exc:
        raise MigrationRefusedError(
            f"無法建立 owner 角色（SQLSTATE {exc.sqlstate or '未知'}）"
        ) from None


def psycopg_connection(connection: Connection) -> psycopg.Connection[tuple[object, ...]]:
    raw = connection.connection.driver_connection
    if not isinstance(raw, psycopg.Connection):
        raise TypeError("migrate-db-roles 需要 psycopg 連線")
    return raw


def _reassign(connection: Connection, target: Target) -> None:
    preparer = connection.dialect.identifier_preparer
    connection.execute(
        text(
            f"REASSIGN OWNED BY {preparer.quote_identifier(target.app_role)} "
            f"TO {preparer.quote_identifier(target.owner_role)}"
        )
    )


def record_audit(connection: Connection, plan: Plan) -> None:
    """和移轉同一個 transaction 的 audit（actor 是 null；只記狀態與數量）。

    還沒有任何 migration 的資料庫沒有 audit_events，略過。
    """
    if connection.execute(text("SELECT to_regclass('public.audit_events')")).scalar() is None:
        return
    with Session(bind=connection, join_transaction_mode="conditional_savepoint") as session:
        _record(session, plan)


def _record(session: Session, plan: Plan) -> None:
    AuditTrail(session).record(
        action="db_roles.migrated",
        object_type="database",
        object_id=None,
        actor_key_id=None,
        project_id=None,
        request_id=None,
        changes={
            "state": plan.state.value if plan.state is not None else None,
            "created_owner": plan.create_owner,
            "transferred": dict(plan.transfer_counts()),
        },
    )


def confirm_owner_login(target: Target, report: Report) -> int:
    engine = _engine(target, target.owner_role, target.owner_password)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except OperationalError:
        report(
            f"{target.owner_role} 無法以 .env 的 DB_OWNER_PASSWORD 登入目標資料庫："
            "確認密碼與 pg_hba"
            "（擁有權已移轉）"
        )
        return EXIT_FAILURE
    finally:
        engine.dispose()
    report(
        f"{target.owner_role} 可以登入。下一步：make migrate（以 owner 套用 v0025 的逐表權限）。"
    )
    return EXIT_OK


def _describe(plan: Plan, target: Target, report: Report, *, dry_run: bool) -> None:
    mode = "dry-run，不做任何改變" if dry_run else "執行"
    report(
        f"migrate-db-roles（{mode}）：資料庫 {target.database}（{target.host}:{target.port}，"
        f"cluster {target.expected_cluster}）；{target.app_role} → {target.owner_role}"
    )
    report(f"狀態：{_STATES[plan.state] if plan.state is not None else '無法判斷'}")
    if plan.refused:
        _list(report, "拒絕（沒有做任何改變）：", plan.refusals)
        return
    if plan.state is not State.LEGACY:
        return
    owner = (
        "會建立（LOGIN，沒有任何高風險屬性；密碼取自 .env 的 DB_OWNER_PASSWORD）"
        if plan.create_owner
        else "已存在（屬性、成員關係與密碼已確認）"
    )
    report(f"owner 角色：{owner}")
    _list(
        report,
        f"會移轉的物件（共 {len(plan.transfers)} 個）：",
        (item.identity for item in plan.transfers),
    )
    counts = "、".join(f"{kind} {count}" for kind, count in plan.transfer_counts().items())
    report(f"小計：{counts}")
    report(
        "不受影響：其他資料庫、其他角色擁有的物件（移轉前後比對，不同就 rollback）；"
        "default privileges 與角色設定（已確認沒有）"
    )


def _list(report: Report, title: str, items: Iterable[str]) -> None:
    report(title)
    for item in items:
        report(f"  - {item}")


def _engine(target: Target, user: str, password: SecretStr) -> Engine:
    url = URL.create(
        "postgresql+psycopg",
        username=user,
        password=password.get_secret_value(),
        host=target.host,
        port=target.port,
        database=target.database,
        query={
            "application_name": APPLICATION_NAME,
            "connect_timeout": str(target.connect_timeout_seconds),
            # 只接受 SCRAM：port 被別的服務占用時，對方不能要求明文密碼（libpq 16 起）。
            "require_auth": REQUIRE_AUTH,
        },
    )
    return create_engine(url, poolclass=NullPool, hide_parameters=True)


def _reason(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "；".join(
            f"{'.'.join(str(part) for part in error['loc'])}：{error['msg']}"
            for error in exc.errors()
        )
    return str(exc)
