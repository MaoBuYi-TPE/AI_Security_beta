"""常駐程序的子命令：容器版的 runner 與 worker（docs/DECISIONS.md §14.6、§14.8）。

    uv run secscan-admin runner [--once] [--outcome succeed|fail] [--hold-seconds 0-300]
    uv run secscan-admin worker [--once]

- 都先確認 DB 就緒；收到 SIGTERM 或 SIGINT 時停止：runner 會停止並刪除執行中的容器，把 run 標成
  interrupted（RUNNER_STOPPED）。runner 啟動時先對帳上一個 runner 留下的 run 與容器，之後每 10 秒
  一次（docs/DECISIONS.md §17.2）。
- runner 經 RUNNER_DOCKER_URL（預設 socket-proxy）操作容器；SECRET_ENCRYPTION_KEYS 沒有設定時，
  需要 target 認證的 scan 會失敗（SECRET_UNAVAILABLE），其他照常。
- 金鑰（docs/DECISIONS.md §30.2）：runner 沒有合法的 EVIDENCE_ENCRYPTION_KEYS、worker 沒有合法的
  CONTENT_ENCRYPTION_KEYS 就不啟動；runner 持有的兩組不得共用金鑰。
- --once：最多處理一個 run 就結束。沒有可用的引擎、lease 失效或 Docker 中途不可用時 exit 1。
- 原始證據的 keeper（docs/DECISIONS.md §30.3）：常駐時是背景執行緒；--once 不啟動執行緒，改在處理
  之前與結束之前各同步跑一輪。keeper 有任何失敗時不認領新的 run，--once 以 exit 1 結束。
- runs volume 的 layout（§30.13）：runner 啟動時先檢查（不通過就不啟動）；run 的目錄在 active/，
  隔離的目錄由 keeper 搬到 held/。
"""

import os
import signal
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from pathlib import Path
from types import FrameType
from uuid import UUID, uuid4

from pydantic import SecretStr
from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from secscan.audit.service import AuditTrail
from secscan.core.config import Settings
from secscan.core.db import DatabaseStatus, create_db_engine, probe_database
from secscan.core.json_types import JsonValue
from secscan.findings.service import FindingLinker
from secscan.migrations import head_revision
from secscan.runner.config import RunnerSettings
from secscan.runner.docker_runtime import DockerRuntime
from secscan.runner.evidence import EvidenceVault
from secscan.runner.hold_moves import HoldMoves
from secscan.runner.isolation import HoldIsolation
from secscan.runner.keeper import EvidenceKeeper, KeeperSettings
from secscan.runner.layout import LAYOUT_FILE, Area, LayoutError, active_dir, check_layout
from secscan.runner.loop import RunnerLoop
from secscan.runner.reconciler import ContainerReconciler
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FakeScript
from secscan.scanners.domain.instances import InstanceRole
from secscan.scanners.service import Fleet
from secscan.scans.evidence_hold_isolation import HoldIsolationStore
from secscan.scans.evidence_records import EvidenceStore
from secscan.scans.queue import RunReport, ScanQueue
from secscan.security.blob_cipher import BlobCipher
from secscan.security.key_rings import (
    EVIDENCE_SETTING,
    SECRET_SETTING,
    check_held,
    content_cipher,
    evidence_cipher,
)
from secscan.security.secret_cipher import InvalidEncryptionKeysError, SecretCipher
from secscan.targets.domain import LabNetwork
from secscan.worker.artifacts import ArtifactReader
from secscan.worker.config import WorkerSettings
from secscan.worker.loop import WorkerLoop
from secscan.worker.reports import ReportWorker
from secscan.worker.retention import ContentRetention
from secscan.worker.service import Worker
from secscan.worker.telemetry import TelemetryReader

EXIT_OK = 0
EXIT_FAILURE = 1
RUNNER_APPLICATION_NAME = "secscan-runner"
WORKER_APPLICATION_NAME = "secscan-worker"
PACKAGE = "secscan"
WORKER_POLL_SECONDS = 2.0
# runner 停止時等 keeper 結束這一輪的上限（compose 的 stop_grace_period 是 30 秒）。
KEEPER_STOP_SECONDS = 15.0

type Report = Callable[[str], None]

NOT_READY = {
    DatabaseStatus.UNAVAILABLE: "無法連線資料庫：請先執行 make db-up，並確認 .env 的 DB_* 設定。",
    DatabaseStatus.SCHEMA_OUTDATED: "資料庫 schema 不是目前版本：請先執行 make migrate。",
}


@contextmanager
def stop_signals() -> Iterator[threading.Event]:
    """SIGTERM、SIGINT 設定停止的旗標（結束時還原原本的 handler）。"""
    stop = threading.Event()

    def request_stop(_signal: int, _frame: FrameType | None) -> None:
        stop.set()

    previous = {
        number: signal.signal(number, request_stop) for number in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        yield stop
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def run_runner(
    settings: Settings,
    runner_settings: RunnerSettings,
    script: FakeScript,
    *,
    once: bool,
    report: Report,
) -> int:
    cipher = _optional_cipher(settings, report)
    evidence = _evidence_cipher(settings, cipher, report)
    if evidence is None:
        return EXIT_FAILURE
    try:
        check_layout(runner_settings.runs_dir)
    except LayoutError as exc:
        report(f"{exc}。runner 不啟動。")
        return EXIT_FAILURE
    try:
        runtime = DockerRuntime.connect(runner_settings.docker_url)
    except ValueError as exc:
        report(f"RUNNER_DOCKER_URL 不正確：{exc}。")
        return EXIT_FAILURE
    engine = create_db_engine(settings, application_name=RUNNER_APPLICATION_NAME, pooled=False)
    try:
        if not _ready(engine, report):
            return EXIT_FAILURE
        sessions = sessionmaker(engine, expire_on_commit=False)
        keeper = _keeper(sessions, engine, settings, runner_settings, evidence)
        with stop_signals() as stop:
            loop = _runner_loop(
                sessions,
                settings,
                runner_settings,
                runtime,
                script,
                cipher,
                stop.is_set,
                lambda: keeper.healthy,
            )
            reports = _serve(loop, keeper, once=once, report=report)
    except SQLAlchemyError as exc:
        report(f"資料庫發生錯誤（{type(exc).__name__}），已停止。")
        return EXIT_FAILURE
    finally:
        engine.dispose()
    return _runner_exit(loop, reports, keeper, once=once, report=report)


def _keeper(
    sessions: sessionmaker[Session],
    engine: Engine,
    settings: Settings,
    runner_settings: RunnerSettings,
    cipher: BlobCipher,
) -> EvidenceKeeper:
    vault = EvidenceVault(runner_settings.runs_dir, cipher)
    return EvidenceKeeper(
        EvidenceStore(sessions, engine=engine),
        vault,
        KeeperSettings(
            retention_days=settings.evidence_retention_days,
            plaintext_max_minutes=settings.evidence_plaintext_max_minutes,
        ),
        isolation=HoldIsolation(
            HoldIsolationStore(sessions), HoldMoves(runner_settings.runs_dir), vault
        ),
    )


def _serve(
    loop: RunnerLoop, keeper: EvidenceKeeper, *, once: bool, report: Report
) -> list[RunReport]:
    """常駐：keeper 在背景執行緒；--once：處理之前與結束之前各同步跑一輪。"""

    def on_report(item: RunReport) -> None:
        report(describe(item))

    if once:
        keeper.run_pass()
        try:
            return loop.run(once=True, on_report=on_report)
        finally:
            keeper.run_pass()
    keeper.start()
    try:
        return loop.run(once=False, on_report=on_report)
    finally:
        keeper.stop(timeout=KEEPER_STOP_SECONDS)


def _runner_loop(
    sessions: sessionmaker[Session],
    settings: Settings,
    runner_settings: RunnerSettings,
    runtime: DockerRuntime,
    script: FakeScript,
    cipher: SecretCipher | None,
    stop_requested: Callable[[], bool],
    evidence_ready: Callable[[], bool],
) -> RunnerLoop:
    owner = _owner(InstanceRole.RUNNER)
    workspace = Workspace(active_dir(runner_settings.runs_dir), runner_settings.secrets_dir)
    policy = runner_settings.container_policy()
    guard = runner_settings.guard_channel()
    queue = _queue(sessions, settings)
    loop = RunnerLoop(
        _fleet(sessions, owner, InstanceRole.RUNNER),
        runtime=runtime,
        workspace=workspace,
        guard=guard,
        reconciler=ContainerReconciler(queue, runtime, workspace, guard),
        policy=policy,
        stop_requested=stop_requested,
        evidence_ready=evidence_ready,
        poll_seconds=runner_settings.poll_seconds,
    )
    loop.attach(
        ContainerRunner(
            queue,
            runtime,
            workspace,
            owner=owner,
            policy=policy,
            script=script,
            cipher=cipher,
            guard=guard,
            endpoint=runner_settings.guard_endpoint(),
            stop_requested=stop_requested,
            on_heartbeat=loop.beat,
        )
    )
    return loop


def run_worker(settings: Settings, *, once: bool, report: Report) -> int:
    content = _content_cipher(settings, report)
    if content is None or not _only_active(WorkerSettings().runs_dir, report):
        return EXIT_FAILURE
    engine = create_db_engine(settings, application_name=WORKER_APPLICATION_NAME, pooled=False)
    try:
        if not _ready(engine, report):
            return EXIT_FAILURE
        sessions = sessionmaker(engine, expire_on_commit=False)
        owner = _owner(InstanceRole.WORKER)
        with stop_signals() as stop:
            reports = WorkerLoop(
                _worker(sessions, _queue(sessions, settings), owner),
                _fleet(sessions, owner, InstanceRole.WORKER),
                stop_requested=stop.is_set,
                poll_seconds=WORKER_POLL_SECONDS,
                reports=ReportWorker(
                    sessions,
                    owner=owner,
                    cipher=content,
                    retention=timedelta(days=settings.report_retention_days),
                ),
                retention=ContentRetention(sessions),
            ).run(once=once, on_report=lambda item: report(describe(item)))
    except SQLAlchemyError as exc:
        report(f"資料庫發生錯誤（{type(exc).__name__}），已停止。")
        return EXIT_FAILURE
    finally:
        engine.dispose()
    if once and not reports:
        report("沒有等待解析的 run。")
    return EXIT_OK


def _only_active(runs_dir: Path, report: Report) -> bool:
    """worker 的 runs 目錄必須是 active/ 本身（subpath 掛載）：看得到 held/ 或 .layout 代表掛到了
    volume 的根目錄（例如 subpath 沒有生效），拒絕啟動（安全審查 LOW-1；§30.13）。"""
    for name in (Area.HELD.value, LAYOUT_FILE):
        try:
            os.lstat(runs_dir / name)
        except FileNotFoundError:
            continue
        except OSError:
            pass  # 無法確認（例如沒有權限）：視為看得到，fail closed。
        report("worker 的 runs 目錄看得到 held/ 或 .layout（掛到 volume 的根目錄）：不啟動。")
        return False
    return True


def _worker(sessions: sessionmaker[Session], queue: ScanQueue, owner: str) -> Worker:
    worker_settings = WorkerSettings()
    return Worker(
        queue,
        owner=owner,
        artifacts=ArtifactReader(worker_settings.runs_dir),
        telemetry=TelemetryReader(worker_settings.telemetry_dir),
        # taxonomy 在這裡載入（sha256 不符時 worker 啟動就失敗，§25.3）。
        findings=FindingLinker(sessions),
    )


def describe(item: RunReport) -> str:
    return (
        f"run {item.run_id}（scan {item.scan_id}）：{item.run_status.value}；"
        f"scan {item.scan_status.value}。"
    )


def _runner_exit(
    loop: RunnerLoop,
    reports: list[RunReport],
    keeper: EvidenceKeeper,
    *,
    once: bool,
    report: Report,
) -> int:
    if loop.failures:
        report(f"有 {loop.failures} 個 run 無法確認容器已停止，留給對帳（原因見上方的 log）。")
        return EXIT_FAILURE
    if not keeper.healthy:
        report(
            "原始證據無法加密或清除（原因見上方的 log）：明文保留原狀，修好之前不認領新的 run；"
            "secscan-admin retention-status 列出積壓。"
        )
        return EXIT_FAILURE
    if not loop.available_engines:
        report("沒有可用的引擎：Docker、scan_net、volume 或映像不符合要求（原因見上方的 log）。")
        return EXIT_FAILURE
    if once and not reports:
        report("沒有排隊中的 run。")
    return EXIT_OK


def with_database(
    settings: Settings, report: Report, action: Callable[[Engine], int], *, application_name: str
) -> int:
    """本機管理指令：連線、確認 schema 是目前版本，再執行 action；DB 錯誤只報類別。"""
    engine = create_db_engine(settings, application_name=application_name, pooled=False)
    try:
        if not _ready(engine, report):
            return EXIT_FAILURE
        return action(engine)
    except SQLAlchemyError as exc:
        report(f"資料庫發生錯誤（{type(exc).__name__}），已停止。")
        return EXIT_FAILURE
    finally:
        engine.dispose()


def audit_local(
    engine: Engine,
    action: str,
    changes: dict[str, JsonValue],
    *,
    object_type: str,
    object_id: UUID | None = None,
    project_id: UUID | None = None,
) -> None:
    """本機管理指令的 audit（actor 是 null）：只記數量或雜湊，不記內容。"""
    with Session(engine, expire_on_commit=False) as session, session.begin():
        AuditTrail(session).record(
            action=action,
            object_type=object_type,
            object_id=object_id,
            actor_key_id=None,
            project_id=project_id,
            request_id=None,
            changes=changes,
        )


def _ready(engine: Engine, report: Report) -> bool:
    status = probe_database(engine, head_revision())
    if status is not DatabaseStatus.READY:
        report(NOT_READY[status])
        return False
    return True


def _optional_cipher(settings: Settings, report: Report) -> SecretCipher | None:
    try:
        return SecretCipher.from_setting(_setting(settings.secret_encryption_keys))
    except InvalidEncryptionKeysError as exc:
        report(f"{exc}；需要 target 認證的 scan 會失敗（SECRET_UNAVAILABLE）。")
        return None


def _evidence_cipher(
    settings: Settings, secret: SecretCipher | None, report: Report
) -> BlobCipher | None:
    """原始證據的金鑰：缺少、不合規則，或和目標 secret 的金鑰共用時，runner 不啟動。"""
    keys = _setting(settings.evidence_encryption_keys)
    rings = {EVIDENCE_SETTING: keys}
    if secret is not None:
        rings[SECRET_SETTING] = _setting(settings.secret_encryption_keys)
    try:
        cipher = evidence_cipher(keys)
        check_held(rings)
    except InvalidEncryptionKeysError as exc:
        report(f"{exc}；runner 不啟動（沒有它就無法加密 runs volume 中的原始證據）。")
        return None
    return cipher


def _content_cipher(settings: Settings, report: Report) -> BlobCipher | None:
    """報告內容的金鑰：缺少或不合規則時，worker 不啟動。"""
    try:
        return content_cipher(_setting(settings.content_encryption_keys))
    except InvalidEncryptionKeysError as exc:
        report(f"{exc}；worker 不啟動（沒有它就無法加密報告內容）。")
        return None


def _setting(value: SecretStr | None) -> str | None:
    return value.get_secret_value() if value is not None else None


def _queue(sessions: sessionmaker[Session], settings: Settings) -> ScanQueue:
    return ScanQueue(sessions, lab=LabNetwork(settings.lab_cidr), clock=lambda: datetime.now(UTC))


def _fleet(sessions: sessionmaker[Session], owner: str, role: InstanceRole) -> Fleet:
    return Fleet(sessions, owner=owner, role=role, software_version=version(PACKAGE))


def _owner(role: InstanceRole) -> str:
    return f"{role.value}:{os.getpid()}:{uuid4().hex}"
