"""常駐程序的子命令：容器版的 runner 與 worker（docs/DECISIONS.md §14.6、§14.8）。

    uv run secscan-admin runner [--once] [--outcome succeed|fail] [--hold-seconds 0-300]
    uv run secscan-admin worker [--once]

- 都先確認 DB 就緒；收到 SIGTERM 或 SIGINT 時停止：runner 會停止並刪除執行中的容器，把 run 標成
  interrupted（RUNNER_STOPPED）。runner 啟動時先對帳上一個 runner 留下的 run 與容器，之後每 10 秒
  一次（docs/DECISIONS.md §17.2）。
- runner 經 RUNNER_DOCKER_URL（預設 socket-proxy）操作容器；SECRET_ENCRYPTION_KEYS 沒有設定時，
  需要 target 認證的 scan 會失敗（SECRET_UNAVAILABLE），其他照常。
- --once：最多處理一個 run 就結束。沒有可用的引擎、lease 失效或 Docker 中途不可用時 exit 1。
"""

import os
import signal
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.metadata import version
from types import FrameType
from uuid import uuid4

from sqlalchemy import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from secscan.core.config import Settings
from secscan.core.db import DatabaseStatus, create_db_engine, probe_database
from secscan.migrations import head_revision
from secscan.runner.config import RunnerSettings
from secscan.runner.docker_runtime import DockerRuntime
from secscan.runner.loop import RunnerLoop
from secscan.runner.reconciler import ContainerReconciler
from secscan.runner.service import ContainerRunner
from secscan.runner.workspace import Workspace
from secscan.scanners.domain.fake import FakeScript
from secscan.scanners.domain.instances import InstanceRole
from secscan.scanners.service import Fleet
from secscan.scans.queue import RunReport, ScanQueue
from secscan.security.secret_cipher import InvalidEncryptionKeysError, SecretCipher
from secscan.targets.domain import LabNetwork
from secscan.worker.artifacts import ArtifactReader
from secscan.worker.config import WorkerSettings
from secscan.worker.loop import WorkerLoop
from secscan.worker.service import Worker
from secscan.worker.telemetry import TelemetryReader

EXIT_OK = 0
EXIT_FAILURE = 1
RUNNER_APPLICATION_NAME = "secscan-runner"
WORKER_APPLICATION_NAME = "secscan-worker"
PACKAGE = "secscan"
WORKER_POLL_SECONDS = 2.0

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
    try:
        runtime = DockerRuntime.connect(runner_settings.docker_url)
    except ValueError as exc:
        report(f"RUNNER_DOCKER_URL 不正確：{exc}。")
        return EXIT_FAILURE
    cipher = _optional_cipher(settings, report)
    engine = create_db_engine(settings, application_name=RUNNER_APPLICATION_NAME, pooled=False)
    try:
        if not _ready(engine, report):
            return EXIT_FAILURE
        sessions = sessionmaker(engine, expire_on_commit=False)
        with stop_signals() as stop:
            loop = _runner_loop(
                sessions, settings, runner_settings, runtime, script, cipher, stop.is_set
            )
            reports = loop.run(once=once, on_report=lambda item: report(describe(item)))
    except SQLAlchemyError as exc:
        report(f"資料庫發生錯誤（{type(exc).__name__}），已停止。")
        return EXIT_FAILURE
    finally:
        engine.dispose()
    return _runner_exit(loop, reports, once=once, report=report)


def _runner_loop(
    sessions: sessionmaker[Session],
    settings: Settings,
    runner_settings: RunnerSettings,
    runtime: DockerRuntime,
    script: FakeScript,
    cipher: SecretCipher | None,
    stop_requested: Callable[[], bool],
) -> RunnerLoop:
    owner = _owner(InstanceRole.RUNNER)
    workspace = Workspace(runner_settings.runs_dir, runner_settings.secrets_dir)
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
    engine = create_db_engine(settings, application_name=WORKER_APPLICATION_NAME, pooled=False)
    try:
        if not _ready(engine, report):
            return EXIT_FAILURE
        sessions = sessionmaker(engine, expire_on_commit=False)
        owner = _owner(InstanceRole.WORKER)
        with stop_signals() as stop:
            reports = WorkerLoop(
                _worker(_queue(sessions, settings), owner),
                _fleet(sessions, owner, InstanceRole.WORKER),
                stop_requested=stop.is_set,
                poll_seconds=WORKER_POLL_SECONDS,
            ).run(once=once, on_report=lambda item: report(describe(item)))
    except SQLAlchemyError as exc:
        report(f"資料庫發生錯誤（{type(exc).__name__}），已停止。")
        return EXIT_FAILURE
    finally:
        engine.dispose()
    if once and not reports:
        report("沒有等待解析的 run。")
    return EXIT_OK


def _worker(queue: ScanQueue, owner: str) -> Worker:
    worker_settings = WorkerSettings()
    return Worker(
        queue,
        owner=owner,
        artifacts=ArtifactReader(worker_settings.runs_dir),
        telemetry=TelemetryReader(worker_settings.telemetry_dir),
    )


def describe(item: RunReport) -> str:
    return (
        f"run {item.run_id}（scan {item.scan_id}）：{item.run_status.value}；"
        f"scan {item.scan_status.value}。"
    )


def _runner_exit(loop: RunnerLoop, reports: list[RunReport], *, once: bool, report: Report) -> int:
    if loop.failures:
        report(f"有 {loop.failures} 個 run 無法確認容器已停止，留給對帳（原因見上方的 log）。")
        return EXIT_FAILURE
    if not loop.available_engines:
        report("沒有可用的引擎：Docker、scan_net、volume 或映像不符合要求（原因見上方的 log）。")
        return EXIT_FAILURE
    if once and not reports:
        report("沒有排隊中的 run。")
    return EXIT_OK


def _ready(engine: Engine, report: Report) -> bool:
    status = probe_database(engine, head_revision())
    if status is not DatabaseStatus.READY:
        report(NOT_READY[status])
        return False
    return True


def _optional_cipher(settings: Settings, report: Report) -> SecretCipher | None:
    keys = settings.secret_encryption_keys
    try:
        return SecretCipher.from_setting(keys.get_secret_value() if keys is not None else None)
    except InvalidEncryptionKeysError as exc:
        report(f"{exc}；需要 target 認證的 scan 會失敗（SECRET_UNAVAILABLE）。")
        return None


def _queue(sessions: sessionmaker[Session], settings: Settings) -> ScanQueue:
    return ScanQueue(sessions, lab=LabNetwork(settings.lab_cidr), clock=lambda: datetime.now(UTC))


def _fleet(sessions: sessionmaker[Session], owner: str, role: InstanceRole) -> Fleet:
    return Fleet(sessions, owner=owner, role=role, software_version=version(PACKAGE))


def _owner(role: InstanceRole) -> str:
    return f"{role.value}:{os.getpid()}:{uuid4().hex}"
