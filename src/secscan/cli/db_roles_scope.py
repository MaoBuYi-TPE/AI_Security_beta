"""migrate-db-roles 的範圍分類（T23b-b1；docs/DECISIONS.md §31.5）：純函式，不連 DB。

REASSIGN OWNED 會移轉目前資料庫中的物件與所有共用物件（資料庫、tablespace），但不處理其他資料庫、
授予舊角色的權限與 default privileges（PostgreSQL 18 文件）。所以先列舉應用程式角色與 owner 在
**所有資料庫**中的依賴（pg_shdepend），只有全部落在 SecScan 預期的範圍時才移轉；其他一律拒絕，
不自動刪除或移轉（fail closed）。
"""

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

APP = "app"
OWNER = "owner"
OWNERSHIP = "o"
ACL = "a"


class State(StrEnum):
    LEGACY = "S0"  # 應用程式角色擁有資料庫與物件
    TRANSFERRED = "S1"  # 已移轉，v0025 還沒套用
    GRANTED = "S2"  # 已移轉，v0025 已套用


class Kind(StrEnum):
    """依賴的物件種類（collector 由 catalog 判斷）。"""

    TARGET_DATABASE = "target database"
    DATABASE = "database"
    TABLESPACE = "tablespace"
    TABLE = "table"
    SEQUENCE = "sequence"
    TRIGGER_FUNCTION = "trigger function"
    PUBLIC_SCHEMA = "schema public"
    OWNER_FUNCTION_DEFAULTS = "owner function defaults"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class Dependency:
    """pg_shdepend 的一列。other_database 是 None 代表目標資料庫中的物件或共用物件。

    key 是 (dbid, classid, objid, objsubid)：移轉之前和實際的擁有權比對，不移轉沒有分類過的物件。
    """

    role: str
    deptype: str
    kind: Kind
    identity: str
    other_database: str | None = None
    key: tuple[int, int, int, int] = (0, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class RoleFacts:
    """login：LOGIN 而且密碼沒有過期；password_matches：owner 已存在時，.env 的密碼和它相符。"""

    exists: bool
    login: bool = False
    risky: bool = False
    memberships: int = 0
    password_matches: bool = True


@dataclass(frozen=True, slots=True)
class Snapshot:
    """分類需要的全部事實（collector 在同一個 transaction 中讀取）。"""

    app: RoleFacts
    owner: RoleFacts
    dependencies: tuple[Dependency, ...]
    third_party_objects: tuple[str, ...]
    settings: tuple[str, ...]
    connections: int


@dataclass(frozen=True, slots=True)
class Plan:
    state: State | None
    create_owner: bool
    transfers: tuple[Dependency, ...]
    refusals: tuple[str, ...]

    @property
    def refused(self) -> bool:
        return bool(self.refusals)

    def transfer_counts(self) -> dict[str, int]:
        return dict(sorted(Counter(item.kind.value for item in self.transfers).items()))


# 應用程式角色在 S0 可以擁有的（REASSIGN OWNED 要移轉的）種類。
_APP_OWNABLE = frozenset({Kind.TARGET_DATABASE, Kind.TABLE, Kind.SEQUENCE, Kind.TRIGGER_FUNCTION})
# owner 可以擁有的種類：同上，加上 v0025 的全域 default ACL（函式，只有 owner 自己）。
_OWNER_OWNABLE = _APP_OWNABLE | {Kind.OWNER_FUNCTION_DEFAULTS}
# S2 時應用程式角色的授權：目標資料庫的 CONNECT、public 的 USAGE 與其中資料表的 DML。
_APP_GRANTABLE = frozenset({Kind.TARGET_DATABASE, Kind.PUBLIC_SCHEMA, Kind.TABLE})


def classify(snapshot: Snapshot) -> Plan:
    refusals = list(_role_refusals(snapshot))
    state = _state(snapshot.dependencies)
    if state is None:
        refusals.append("目標資料庫的擁有者既不是應用程式角色、也不是 owner")
    refusals.extend(_dependency_refusals(snapshot.dependencies, state))
    refusals.extend(
        f"目標資料庫中有其他角色的物件：{item}" for item in snapshot.third_party_objects
    )
    refusals.extend(f"有角色或資料庫層級的設定：{item}" for item in snapshot.settings)
    if snapshot.connections:
        refusals.append(
            f"還有 {snapshot.connections} 個應用程式角色或 owner 的連線：請先執行 make down"
        )
    transfers = tuple(
        item
        for item in snapshot.dependencies
        if item.role == APP and item.deptype == OWNERSHIP and item.other_database is None
    )
    return Plan(
        state=state,
        create_owner=not snapshot.owner.exists,
        transfers=transfers if state is State.LEGACY else (),
        refusals=tuple(refusals),
    )


def _role_refusals(snapshot: Snapshot) -> Iterable[str]:
    if not snapshot.app.exists:
        yield "找不到應用程式角色"
    elif snapshot.app.risky:
        yield "應用程式角色有 SUPERUSER、CREATEDB、CREATEROLE、REPLICATION 或 BYPASSRLS 屬性"
    if snapshot.app.memberships:
        yield "應用程式角色有成員關係"
    owner = snapshot.owner
    if not owner.exists:
        return
    if owner.risky or not owner.login:
        yield "owner 角色已存在，但屬性不符（必須是 LOGIN、沒有任何高風險屬性）"
    if owner.memberships:
        yield "owner 角色已存在，但有成員關係"
    if not owner.password_matches:
        yield (
            "owner 角色已存在，但 .env 的 DB_OWNER_PASSWORD 和它的密碼不符（或不是 SCRAM-SHA-256）"
        )


def _state(dependencies: tuple[Dependency, ...]) -> State | None:
    database_owner = {
        item.role
        for item in dependencies
        if item.kind is Kind.TARGET_DATABASE and item.deptype == OWNERSHIP
    }
    if database_owner == {APP}:
        return State.LEGACY
    if database_owner != {OWNER}:
        return None
    app_grants = any(item.role == APP and item.deptype == ACL for item in dependencies)
    return State.GRANTED if app_grants else State.TRANSFERRED


def _dependency_refusals(
    dependencies: tuple[Dependency, ...], state: State | None
) -> Iterable[str]:
    for item in dependencies:
        reason = _refusal(item, state)
        if reason is not None:
            yield f"{reason}：{_describe(item)}"


def _refusal(item: Dependency, state: State | None) -> str | None:
    if item.other_database is not None:
        return "其他資料庫中有依賴（REASSIGN OWNED 不處理其他資料庫）"
    if item.deptype == OWNERSHIP:
        allowed = _APP_OWNABLE if item.role == APP else _OWNER_OWNABLE
        return None if item.kind in allowed else "不在預期範圍內的擁有權"
    if item.deptype == ACL and item.role == APP:
        if state in (State.TRANSFERRED, State.GRANTED) and item.kind in _APP_GRANTABLE:
            return None
        return "不在預期範圍內的授權"
    return "不在預期範圍內的依賴"


def _describe(item: Dependency) -> str:
    role = "應用程式角色" if item.role == APP else "owner"
    where = f"資料庫 {item.other_database} 的 " if item.other_database is not None else ""
    return f"{role}（{item.deptype}）{where}{item.identity}"
