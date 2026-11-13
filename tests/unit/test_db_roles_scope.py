"""migrate-db-roles 的範圍分類（ROLE-06 的 unit 部分；docs/DECISIONS.md §31.5）。

db-test 建立不了 tablespace、subscription 等物件，這裡以合成的 pg_shdepend 資料測分類器：
只有 SecScan 預期的範圍才移轉，其他一律拒絕（fail closed）。
"""

import pytest

from secscan.cli.db_roles_catalog import Ownership, ownership_problems
from secscan.cli.db_roles_scope import (
    ACL,
    APP,
    OWNER,
    OWNERSHIP,
    Dependency,
    Kind,
    RoleFacts,
    Snapshot,
    State,
    classify,
)

APP_ROLE = RoleFacts(exists=True, login=True)
NO_OWNER = RoleFacts(exists=False)
OWNER_ROLE = RoleFacts(exists=True, login=True)


def _owned(role: str, kind: Kind, identity: str = "x") -> Dependency:
    return Dependency(role=role, deptype=OWNERSHIP, kind=kind, identity=identity)


LEGACY = (
    _owned(APP, Kind.TARGET_DATABASE, "database secscan"),
    _owned(APP, Kind.TABLE, "table projects"),
    _owned(APP, Kind.TABLE, "table scans"),
    _owned(APP, Kind.SEQUENCE, "sequence scans_queue_position_seq"),
    _owned(APP, Kind.TRIGGER_FUNCTION, "function audit_events_reject_mutation()"),
)
TRANSFERRED = (
    _owned(OWNER, Kind.TARGET_DATABASE, "database secscan"),
    _owned(OWNER, Kind.TABLE, "table projects"),
)
GRANTED = (
    *TRANSFERRED,
    _owned(OWNER, Kind.OWNER_FUNCTION_DEFAULTS, "default privileges on new functions"),
    Dependency(role=APP, deptype=ACL, kind=Kind.TARGET_DATABASE, identity="database secscan"),
    Dependency(role=APP, deptype=ACL, kind=Kind.PUBLIC_SCHEMA, identity="schema public"),
    Dependency(role=APP, deptype=ACL, kind=Kind.TABLE, identity="table projects"),
)


def _snapshot(
    dependencies: tuple[Dependency, ...] = LEGACY,
    *,
    app: RoleFacts = APP_ROLE,
    owner: RoleFacts = NO_OWNER,
    third_party: tuple[str, ...] = (),
    settings: tuple[str, ...] = (),
    connections: int = 0,
) -> Snapshot:
    return Snapshot(
        app=app,
        owner=owner,
        dependencies=dependencies,
        third_party_objects=third_party,
        settings=settings,
        connections=connections,
    )


def test_the_legacy_state_transfers_every_app_object_and_creates_the_owner() -> None:
    plan = classify(_snapshot())

    assert plan.state is State.LEGACY
    assert not plan.refused
    assert plan.create_owner
    assert plan.transfers == LEGACY
    assert plan.transfer_counts() == {
        "sequence": 1,
        "table": 2,
        "target database": 1,
        "trigger function": 1,
    }


def test_an_existing_owner_that_owns_nothing_is_reused() -> None:
    plan = classify(_snapshot(owner=OWNER_ROLE))

    assert (plan.state, plan.refused, plan.create_owner) == (State.LEGACY, False, False)


@pytest.mark.parametrize(
    ("dependencies", "state"), [(TRANSFERRED, State.TRANSFERRED), (GRANTED, State.GRANTED)]
)
def test_transferred_states_have_nothing_to_transfer(
    dependencies: tuple[Dependency, ...], state: State
) -> None:
    plan = classify(_snapshot(dependencies, owner=OWNER_ROLE))

    assert (plan.state, plan.refused, plan.transfers) == (state, False, ())


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        (_owned(APP, Kind.DATABASE, "database other"), "擁有權"),
        (_owned(APP, Kind.TABLESPACE, "tablespace fast"), "擁有權"),
        (_owned(APP, Kind.OTHER, "schema evil"), "擁有權"),
        (_owned(APP, Kind.OTHER, "large object 16500"), "擁有權"),
        (_owned(APP, Kind.OTHER, "function public.helper()"), "擁有權"),
        (_owned(APP, Kind.OTHER, "view public.leak"), "擁有權"),
        (_owned(APP, Kind.OTHER, "subscription feed"), "擁有權"),
        (_owned(APP, Kind.OTHER, "default privileges belonging to role app"), "擁有權"),
        (
            Dependency(
                role=APP,
                deptype=OWNERSHIP,
                kind=Kind.OTHER,
                identity="pg_class",
                other_database="elsewhere",
            ),
            "其他資料庫",
        ),
        (Dependency(role=APP, deptype=ACL, kind=Kind.TABLE, identity="table projects"), "授權"),
        (Dependency(role=APP, deptype=ACL, kind=Kind.OTHER, identity="parameter work_mem"), "授權"),
        (Dependency(role=APP, deptype="r", kind=Kind.OTHER, identity="policy p on t"), "依賴"),
        (Dependency(role=APP, deptype="i", kind=Kind.OTHER, identity="init privs"), "依賴"),
        (Dependency(role=APP, deptype="t", kind=Kind.TABLESPACE, identity="t"), "依賴"),
        (Dependency(role=OWNER, deptype=ACL, kind=Kind.TABLE, identity="table x"), "依賴"),
        (_owned(OWNER, Kind.OTHER, "schema owner_stuff"), "擁有權"),
    ],
)
def test_anything_outside_the_expected_scope_is_refused(extra: Dependency, reason: str) -> None:
    plan = classify(_snapshot((*LEGACY, extra), owner=OWNER_ROLE))

    assert plan.refused
    assert any(reason in item and extra.identity in item for item in plan.refusals)


def test_grants_to_the_app_role_on_other_databases_are_refused_even_after_the_transfer() -> None:
    other = Dependency(
        role=APP, deptype=ACL, kind=Kind.OTHER, identity="pg_class", other_database="elsewhere"
    )

    plan = classify(_snapshot((*GRANTED, other), owner=OWNER_ROLE))

    assert plan.refused


@pytest.mark.parametrize(
    "snapshot",
    [
        _snapshot(app=RoleFacts(exists=False)),
        _snapshot(app=RoleFacts(exists=True, login=True, risky=True)),
        _snapshot(app=RoleFacts(exists=True, login=True, memberships=1)),
        _snapshot(owner=RoleFacts(exists=True, login=False)),
        _snapshot(owner=RoleFacts(exists=True, login=True, risky=True)),
        _snapshot(owner=RoleFacts(exists=True, login=True, memberships=2)),
        _snapshot(owner=RoleFacts(exists=True, login=True, password_matches=False)),
        _snapshot(third_party=("table public.extra (owner mallory)",)),
        _snapshot(settings=("角色 secscan_app 的 session_replication_role",)),
        _snapshot(connections=1),
        _snapshot(LEGACY[1:]),
        _snapshot(
            (*LEGACY, _owned(OWNER, Kind.TARGET_DATABASE, "database secscan")), owner=OWNER_ROLE
        ),
    ],
)
def test_role_facts_settings_and_connections_are_checked(snapshot: Snapshot) -> None:
    assert classify(snapshot).refused


# ---------------------------------------------------------------- 事後檢查（純函式）

APP_OBJECTS = frozenset({(0, 1262, 16400, 0), (16400, 1259, 16500, 0)})
OTHERS = ((16401, 1259, 16600, 0, "mallory"),)


def _ownership(
    app: frozenset[tuple[int, int, int, int]],
    owner: frozenset[tuple[int, int, int, int]],
    others: tuple[tuple[int, int, int, int, str], ...] = OTHERS,
) -> Ownership:
    return Ownership(app=app, owner=owner, others=others)


def test_a_clean_transfer_has_no_problems() -> None:
    before = _ownership(APP_OBJECTS, frozenset())

    assert ownership_problems(before, _ownership(frozenset(), APP_OBJECTS)) == ()


@pytest.mark.parametrize(
    ("after", "reason"),
    [
        (_ownership(frozenset({(0, 1262, 16400, 0)}), APP_OBJECTS), "仍擁有"),
        (_ownership(frozenset(), frozenset({(0, 1262, 16400, 0)})), "聯集"),
        (
            _ownership(frozenset(), APP_OBJECTS | {(16400, 1255, 16700, 0)}),
            "聯集",
        ),
        (_ownership(frozenset(), APP_OBJECTS, others=()), "其他角色"),
        (
            _ownership(frozenset(), APP_OBJECTS, others=((16401, 1259, 16600, 0, "eve"),)),
            "其他角色",
        ),
    ],
)
def test_the_post_check_catches_every_difference(after: Ownership, reason: str) -> None:
    before = _ownership(APP_OBJECTS, frozenset())

    problems = ownership_problems(before, after)

    assert any(reason in problem for problem in problems)
