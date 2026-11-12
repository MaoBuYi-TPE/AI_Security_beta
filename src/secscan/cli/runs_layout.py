"""runs volume 的 layout 指令（docs/DECISIONS.md §30.13）。

    secscan-admin init-runs-layout [--runs-dir /runs]
    secscan-admin migrate-runs-layout --expect-volume <volume 名稱> [--dry-run]

- init-runs-layout：compose 的一次性服務 runs-init 執行（沒有金鑰、沒有網路、只掛載 runs volume）。
  不讀取 DB 與金鑰的設定（在 Settings 之前分派）。根目錄是空的就建立 active/、held/ 與 .layout；
  有 .layout 也重新檢查全部條件（runner/layout.py）；不通過就 exit 1，runner 與 worker 因此不會
  啟動。
- migrate-runs-layout：由 make runs-layout-migrate 在 runner 容器內執行（compose run --no-deps）。
  主機端已解析實際的 volume、確認 compose 的標籤、沒有任何容器使用它；這裡再確認：
  - 容器內的 RUNNER_RUNS_VOLUME 等於 --expect-volume，而且 runs 目錄是掛載點；
  - DB 在 head（with_database）、拿得到 evidence advisory lock；
  - 沒有 lease 有效的 run（含解析），也沒有容器還沒確認刪除的 run。
  任何一項不成立就 exit 1、不做任何改變。之後依 runner/layout_migration.py 搬移；--dry-run 只列出
  計畫，不寫任何東西（含 audit）。搬移之前寫 audit `runs_layout.migrate`，完成之後寫
  `runs_layout.migrated`。可以重跑；有衝突時不完成 layout、exit 1。
說明都寫到 stderr；目錄名稱以外不含路徑或內容。
"""

import argparse
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from secscan.cli.evidence import with_evidence_lock
from secscan.cli.services import EXIT_FAILURE, EXIT_OK, Report, audit_local, with_database
from secscan.core.config import Settings
from secscan.core.json_types import JsonValue
from secscan.runner.config import RunnerSettings
from secscan.runner.layout import LayoutError, init_layout
from secscan.runner.layout_migration import LayoutMigrator, MigrationPlan, MigrationResult
from secscan.runner.sealed_files import EvidenceError
from secscan.scans.evidence_hold_isolation import HoldIsolationStore
from secscan.scans.evidence_records import EvidenceStore
from secscan.scans.models import ScannerRunModel

INIT_COMMAND = "init-runs-layout"
MIGRATE_COMMAND = "migrate-runs-layout"
APPLICATION_NAME = "secscan-runs-layout"
DEFAULT_RUNS_DIR = Path("/runs")
OBJECT_TYPE = "runs_volume"
MAX_LISTED = 10
# 還沒解除的隔離紀錄一次全部讀進來（實際只有少數幾筆）；達到這個數量就拒絕，不截斷。
MAX_HOLDS = 100_000
# Docker 的 volume 名稱。
_VOLUME_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}")

type Subparsers = argparse._SubParsersAction[Any]
type MountCheck = Callable[[Path], bool]


def register(commands: Subparsers) -> None:
    init = commands.add_parser(
        INIT_COMMAND,
        help="建立或檢查 runs volume 的 layout（compose 的 runs-init 執行；不需要 DB 與金鑰）",
        description=(
            "根目錄是空的就建立 active/、held/ 與 .layout；否則重新檢查全部條件，不通過就 exit 1"
            "（請執行 make runs-layout-migrate）。"
        ),
    )
    init.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR, help=argparse.SUPPRESS)
    migrate = commands.add_parser(
        MIGRATE_COMMAND,
        help="把既有的 runs volume 搬到新的 layout（make runs-layout-migrate 在容器內執行）",
        description=(
            "隔離的目錄搬到 held/、其他 run 目錄搬到 active/，寫入 .layout。可以重跑；"
            "--dry-run 只列出計畫。"
        ),
    )
    migrate.add_argument(
        "--expect-volume", required=True, help="主機端解析的 runs volume 名稱（必須和容器內相同）"
    )
    migrate.add_argument("--dry-run", action="store_true", help="只列出計畫，不做任何改變")


def init_command(args: argparse.Namespace, report: Report) -> int:
    try:
        result = init_layout(args.runs_dir)
    except LayoutError as exc:
        report(f"{exc}。runner 與 worker 不會啟動。")
        return EXIT_FAILURE
    done = "已建立 runs volume 的 layout" if result.created else "runs volume 的 layout 正確"
    others = f"（根目錄另有 {result.others} 個其他條目，不影響啟動）" if result.others else ""
    report(f"{done}{others}。")
    return EXIT_OK


def run(
    args: argparse.Namespace,
    settings: Settings,
    report: Report,
    *,
    mounted: MountCheck = os.path.ismount,
) -> int | None:
    """這個模組的指令（init-runs-layout 在 Settings 之前分派）；其他指令回傳 None。"""
    if args.command != MIGRATE_COMMAND:
        return None
    expected = args.expect_volume
    if not _VOLUME_NAME.fullmatch(expected):
        report("--expect-volume 不是合法的 volume 名稱：沒有做任何改變。")
        return EXIT_FAILURE
    try:
        runner_settings = RunnerSettings()
    except ValidationError:
        report("設定不正確（RUNNER_* 環境變數）：沒有做任何改變。")
        return EXIT_FAILURE
    if runner_settings.runs_volume != expected:
        report(
            "容器內的 RUNNER_RUNS_VOLUME 和主機解析的 volume 不同：拒絕搬移"
            "（請確認 .env 與 compose 的設定），沒有做任何改變。"
        )
        return EXIT_FAILURE
    runs_dir = runner_settings.runs_dir
    if not mounted(runs_dir):
        report("runs 目錄不是掛載點（沒有掛上 runs volume）：拒絕搬移，沒有做任何改變。")
        return EXIT_FAILURE
    return with_database(
        settings,
        report,
        lambda engine: migrate_volume(engine, runs_dir, dry_run=args.dry_run, report=report),
        application_name=APPLICATION_NAME,
    )


def migrate_volume(engine: Engine, runs_dir: Path, *, dry_run: bool, report: Report) -> int:
    """DB 的前提與搬移（在 evidence advisory lock 內）。"""
    sessions = sessionmaker(engine, expire_on_commit=False)
    store = EvidenceStore(sessions, engine=engine)
    outcome = with_evidence_lock(
        store, lambda: _locked(engine, sessions, runs_dir, dry_run=dry_run, report=report)
    )
    if outcome is None:
        report("拿不到原始證據的 advisory lock（runner 還在執行？）：沒有做任何改變。")
        return EXIT_FAILURE
    return outcome


def _locked(
    engine: Engine,
    sessions: sessionmaker[Session],
    runs_dir: Path,
    *,
    dry_run: bool,
    report: Report,
) -> int:
    leased, unconfirmed = _busy_runs(sessions)
    if leased:
        report(
            f"有 {leased} 個 run 還有有效的 lease：先 make down，等 lease 過期之後再執行。"
            "沒有做任何改變。"
        )
        return EXIT_FAILURE
    if unconfirmed:
        report(
            f"有 {unconfirmed} 個 run 的容器還沒確認刪除（runner 異常結束時會留下），要先由 runner "
            "對帳；新版的 runner 在舊的 layout 上不會啟動。請依 README 的「runner 異常結束之後的"
            "人工修復」處理（DECISIONS §30.13 的剩餘風險 12）。沒有做任何改變。"
        )
        return EXIT_FAILURE
    isolation = HoldIsolationStore(sessions)
    holds = isolation.unresolved(limit=MAX_HOLDS)
    if len(holds) >= MAX_HOLDS:
        report("還沒解除的隔離紀錄太多：拒絕搬移，沒有做任何改變。")
        return EXIT_FAILURE
    migrator = LayoutMigrator(runs_dir, {held.name: held for held in holds}, isolation)
    try:
        plan = migrator.plan()
    except (LayoutError, EvidenceError) as exc:
        report(f"{exc}：沒有做任何改變。")
        return EXIT_FAILURE
    _describe(plan, report)
    if plan.blocking:
        report(
            "根目錄有 UUID 名稱、但不是目錄的條目（例如 symlink）：layout 不允許它們，"
            "請人工確認並移走之後再執行。沒有做任何改變。"
        )
        return EXIT_FAILURE
    if dry_run:
        report("dry-run：沒有做任何改變。")
        return EXIT_OK
    audit_local(engine, "runs_layout.migrate", _counts(plan), object_type=OBJECT_TYPE)
    try:
        result = migrator.migrate(plan)
    except (LayoutError, EvidenceError) as exc:
        report(f"搬移沒有完成（{exc}）：再執行一次會從目前的狀態繼續。")
        return EXIT_FAILURE
    return _finish(engine, result, report)


def _busy_runs(sessions: sessionmaker[Session]) -> tuple[int, int]:
    """(lease 有效的 run, 容器還沒確認刪除的 run) 的數量。"""
    run = ScannerRunModel
    leased = (run.lease_owner.is_not(None)) & (run.lease_expires_at > func.clock_timestamp())
    unconfirmed = (run.container_name.is_not(None)) & (run.container_removed_at.is_(None))
    with sessions() as session:
        counts = session.execute(
            select(func.count().filter(leased), func.count().filter(unconfirmed)).select_from(run)
        ).one()
        return int(counts[0]), int(counts[1])


def _describe(plan: MigrationPlan, report: Report) -> None:
    report(
        f"計畫：搬到 active/ {len(plan.to_active)} 個、搬到 held/（還沒解除的隔離）"
        f"{len(plan.to_held)} 個；其他條目 {len(plan.others)} 個不動；"
        f"{'已有' if plan.has_marker else '還沒有'} .layout。"
    )
    for name in plan.to_held[:MAX_LISTED]:
        report(f"  搬到 held/：{name}")
    for name in plan.others[:MAX_LISTED]:
        report(f"  不動的其他條目：{name}")
    for name in plan.blocking[:MAX_LISTED]:
        report(f"  UUID 名稱、但不是目錄（阻擋）：{name}")


def _finish(engine: Engine, result: MigrationResult, report: Report) -> int:
    changes: dict[str, JsonValue] = {
        "moved_active": result.moved_active,
        "moved_held": result.moved_held,
        "isolated": result.isolated,
        "unverified": len(result.unverified),
        "conflicts": len(result.conflicts),
    }
    if not result.complete:
        audit_local(engine, "runs_layout.migrate_failed", changes, object_type=OBJECT_TYPE)
        listed = "、".join(result.conflicts[:MAX_LISTED])
        report(
            f"有 {len(result.conflicts)} 個目錄無法搬移（{listed}）：目的地已有同名的條目，或身分"
            "和隔離紀錄不符。它們保留原狀，layout 沒有完成；請人工確認之後再執行一次。"
        )
        return EXIT_FAILURE
    audit_local(engine, "runs_layout.migrated", changes, object_type=OBJECT_TYPE)
    if result.unverified:
        listed = "、".join(result.unverified[:MAX_LISTED])
        report(
            f"有 {len(result.unverified)} 個隔離的目錄身分和紀錄不符（{listed}）："
            "沒有記下隔離完成、維持隔離中；keeper 的對帳會記錄衝突，retention-status 看得到，"
            "請人工確認。"
        )
    report(
        f"完成：搬到 active/ {result.moved_active} 個、搬到 held/ {result.moved_held} 個，"
        f"其中 {result.isolated} 個隔離紀錄已記下隔離完成。現在可以執行 make up。"
    )
    return EXIT_OK


def _counts(plan: MigrationPlan) -> dict[str, JsonValue]:
    return {
        "to_active": len(plan.to_active),
        "to_held": len(plan.to_held),
        "others": len(plan.others),
        "has_marker": plan.has_marker,
        "blocking": len(plan.blocking),
    }
