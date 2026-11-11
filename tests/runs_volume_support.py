"""測試用的 runs volume（docs/DECISIONS.md §30.13）：建立新的 layout，回傳 active/。

既有的測試把 run 的目錄放在回傳的目錄中；vault 與 HoldMoves 以 volume 的根目錄（.parent）建立。
"""

import math
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine
from sqlalchemy.orm import sessionmaker

from secscan.runner.evidence import EvidenceVault
from secscan.runner.hold_moves import HoldMoves
from secscan.runner.isolation import HoldIsolation
from secscan.runner.layout import active_dir, init_layout
from secscan.scans.evidence_hold_isolation import HoldIsolationStore


def runs_volume(tmp_path: Path) -> Path:
    """tmp_path/runs 是 volume 的根目錄（layout 已建立）；回傳 active/。"""
    root = tmp_path / "runs"
    root.mkdir()
    init_layout(root)
    return active_dir(root)


def inode(runs: Path, name: object) -> int:
    """active/ 中目錄的 inode（隔離紀錄的 source_ino）。"""
    return (runs / str(name)).lstat().st_ino


def hold_isolation(
    engine: Engine,
    runs: Path,
    vault: EvidenceVault,
    *,
    clock: Callable[[], datetime] | None = None,
    monotonic: Callable[[], float] | None = None,
) -> HoldIsolation:
    """runs 是 active/；keeper 使用的隔離（真的 DB 與檔案）。"""
    options: dict[str, Any] = {}
    if clock is not None:
        options["clock"] = clock
    if monotonic is not None:
        options["monotonic"] = monotonic
    return HoldIsolation(
        HoldIsolationStore(sessionmaker(engine, expire_on_commit=False)),
        HoldMoves(runs.parent),
        vault,
        **options,
    )


def isolate(engine: Engine, runs: Path, vault: EvidenceVault) -> None:
    """keeper 的一次對帳：隔離中的目錄搬到 held/ 並記下隔離完成。"""
    hold_isolation(engine, runs, vault).reconcile(math.inf)
