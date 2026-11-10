"""原始證據的 keeper（docs/DECISIONS.md §30.3）：runner 程序內的背景執行緒。

每 10 秒一輪，每輪有時間與數量的上限：
1. 逾期：等待解析超過 EVIDENCE_PLAINTEXT_MAX_MINUTES 的 run → failed（PARSE_DEADLINE_EXCEEDED）；
2. 加密：已終止、容器確認刪除的 run 的目錄；從來沒有目錄的記為 none；
3. 清除：加密超過 EVIDENCE_RETENTION_DAYS 的目錄；
4. 孤兒：沒有 scanner_runs 紀錄的 UUID 目錄（舊的 probe…）：一小時沒有變動才加密，加密檔標頭中的
   時間超過保留期限才刪除；絕不在未加密時刪除。
第 2 到 4 步持有 advisory lock，和 rotate-evidence-keys 互斥；拿不到鎖（換版中）時這一輪略過。
這幾步之前先確認 runs volume 存在而且可寫（沒有掛上時，找不到目錄不能記成 none；§30.11）。

keeper 有自己的 DB session，和主迴圈只共用健康狀態：主迴圈監看容器時加密照常進行，心跳、對帳與取消
都不受影響。任何一個 run 失敗都保留明文、不記下 sealed、繼續處理其他 run；這一輪就不健康，主迴圈
停止認領新的 run（CapabilityIssue.EVIDENCE_SEALING_FAILED），直到有一輪沒有任何失敗才恢復。
執行緒意外結束、停擺（太久沒有完成一輪）或換版中也算不健康；正常停止時保留最後一輪的結果。
任何例外都不會讓執行緒結束：非預期的例外只記類別，這一輪不健康（審查 HIGH-1）。
失敗的 run 與孤兒目錄退避（20 秒起倍增，最多 10 分鐘；runner/backoff.py）：不會每一輪都重試、
佔滿批次而讓其他 run 等不到加密；還在退避的仍算不健康（安全審查 M1）。log 只有 run_id 與錯誤的種類。

隔離（§30.12）：同一個目錄（run 的加密、孤兒的檢查與加密）連續 3 次超過資源上限（深度、條目數或
路徑總長度），就寫入 evidence_holds 與 audit，之後跳過它、不算退避中（明文保留，等待
retry-evidence）；寫入失敗時維持不健康、下次再寫。清除時超過上限不計數（已加密的目錄被改過或
環境有問題：維持全域 fail closed）。
"""

import logging
import threading
import time
from collections.abc import Callable, Collection, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from secscan.runner.backoff import Backoff, BackoffKey
from secscan.runner.evidence import DirectoryState, EvidenceError, EvidenceLimitError
from secscan.runner.fs import TreeError
from secscan.scans.domain.evidence import EvidenceHoldCode, SealedEvidence
from secscan.scans.evidence_records import EvidenceRun

logger = logging.getLogger(__name__)

# 幾輪的時間沒有完成一輪就視為停擺。
STALE_PASSES = 3
_KNOWN_BATCH = 500
_FAILURES = (EvidenceError, TreeError, SQLAlchemyError, OSError)
_HELD = "目錄 %s 連續 %s 次超過上限（%s）：已隔離、明文保留、不再自動重試（retry-evidence）"
_HOLD_FAILED = (
    "目錄 %s 連續 %s 次超過上限（%s），但無法記下隔離（%s）：維持不健康，下一次失敗時再寫入"
)


class Store(Protocol):
    """DB 的部分（scans.evidence_records.EvidenceStore）。"""

    def overdue(
        self, *, now: datetime, max_minutes: int, limit: int
    ) -> tuple[EvidenceRun, ...]: ...

    def expire(self, run: EvidenceRun, *, now: datetime, max_minutes: int) -> bool: ...

    def sealable(self, *, limit: int, exclude: Collection[UUID]) -> tuple[EvidenceRun, ...]: ...

    def record(self, run: EvidenceRun, sealed: SealedEvidence | None) -> bool: ...

    def purgeable(
        self, *, now: datetime, retention_days: int, limit: int, exclude: Collection[UUID]
    ) -> tuple[EvidenceRun, ...]: ...

    def record_purged(self, run: EvidenceRun) -> bool: ...

    def known(self, run_ids: Collection[UUID]) -> frozenset[UUID]: ...

    def hold(
        self, directory: UUID, run: EvidenceRun | None, code: EvidenceHoldCode, attempts: int
    ) -> None: ...

    def held(self, directories: Collection[UUID]) -> frozenset[UUID]: ...

    def exclusive(self) -> AbstractContextManager[bool]: ...


class Vault(Protocol):
    """檔案的部分（runner.evidence.EvidenceVault）。"""

    def check(self) -> None: ...

    def entries(self) -> tuple[str, ...]: ...

    def inspect(self, name: str) -> DirectoryState | None: ...

    def sealed_at(self, name: str) -> int | None: ...

    def seal(self, name: str) -> SealedEvidence | None: ...

    def purge(self, name: str) -> None: ...


@dataclass(frozen=True, slots=True)
class KeeperSettings:
    retention_days: int
    plaintext_max_minutes: int
    interval_seconds: float = 10.0
    max_pass_seconds: float = 30.0
    batch: int = 20
    orphan_quiet_seconds: float = 3_600.0


@dataclass(slots=True)
class PassReport:
    expired: int = 0
    sealed: int = 0
    none: int = 0
    purged: int = 0
    orphans_sealed: int = 0
    orphans_purged: int = 0
    held: int = 0
    failures: int = 0
    deferred: int = 0
    skipped: bool = False

    @property
    def clean(self) -> bool:
        return self.failures == 0 and self.deferred == 0 and not self.skipped


class EvidenceKeeper:
    def __init__(
        self,
        store: Store,
        vault: Vault,
        settings: KeeperSettings,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._vault = vault
        self._settings = settings
        self._clock = clock
        self._monotonic = monotonic
        self._state = threading.Lock()
        self._healthy = False
        self._finished_at: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._backoff = Backoff(settings.interval_seconds, monotonic)

    @property
    def healthy(self) -> bool:
        """最近一輪沒有任何失敗，而且沒有停擺（執行緒模式：執行緒還在）。

        要求停止之後是最後一輪的結果：正常停止不是失敗（審查 MEDIUM-1）。
        """
        with self._state:
            if not self._healthy or self._finished_at is None:
                return False
            finished_at = self._finished_at
        if self._stop.is_set():
            return True
        if self._thread is not None and not self._thread.is_alive():
            return False
        settings = self._settings
        limit = STALE_PASSES * (settings.interval_seconds + settings.max_pass_seconds)
        return self._monotonic() - finished_at <= limit

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("keeper 已經啟動")
        self._thread = threading.Thread(target=self._loop, name="evidence-keeper", daemon=True)
        self._thread.start()

    def stop(self, timeout: float) -> None:
        """要求停止，等這一輪結束（最多 timeout 秒）。"""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def run_pass(self) -> PassReport:
        report = PassReport()
        deadline = self._monotonic() + self._settings.max_pass_seconds
        try:
            self._expire(report, deadline)
            with self._store.exclusive() as acquired:
                if not acquired:
                    report.skipped = True
                    logger.warning("原始證據的金鑰換版中：這一輪不加密、不清除")
                else:
                    self._vault.check()
                    self._forget_held()
                    self._seal(report, deadline)
                    self._purge(report, deadline)
                    self._orphans(report, deadline)
        except _FAILURES as exc:
            report.failures += 1
            logger.error("keeper 這一輪中止（%s）", _kind(exc))
        except Exception as exc:  # noqa: BLE001 - 執行緒不能因為非預期的例外結束（只記類別）
            report.failures += 1
            logger.error("keeper 這一輪發生非預期的錯誤（%s）", type(exc).__name__)
        report.deferred = len(self._backoff)
        self._finish(report)
        return report

    # --- 各步驟 ----------------------------------------------------------------------------

    def _expire(self, report: PassReport, deadline: float) -> None:
        settings = self._settings
        now = self._clock()
        candidates = self._store.overdue(
            now=now, max_minutes=settings.plaintext_max_minutes, limit=settings.batch
        )
        for run in candidates:
            if self._monotonic() > deadline:
                return
            try:
                expired = self._store.expire(
                    run, now=now, max_minutes=settings.plaintext_max_minutes
                )
            except SQLAlchemyError as exc:
                self._failed(report, run.run_id, exc)
                continue
            if expired:
                report.expired += 1
                logger.warning("run %s 等待解析逾期：已轉成 failed，接著加密", run.run_id)

    def _seal(self, report: PassReport, deadline: float) -> None:
        candidates = self._store.sealable(
            limit=self._settings.batch, exclude=self._backoff.waiting_runs()
        )
        for run in candidates:
            if self._monotonic() > deadline:
                return
            try:
                sealed = self._vault.seal(str(run.run_id))
                self._store.record(run, sealed)
            except _FAILURES as exc:
                self._failed(report, run.run_id, exc, run=run)
                continue
            self._backoff.clear(run.run_id)
            if sealed is None:
                report.none += 1
            else:
                report.sealed += 1

    def _purge(self, report: PassReport, deadline: float) -> None:
        settings = self._settings
        candidates = self._store.purgeable(
            now=self._clock(),
            retention_days=settings.retention_days,
            limit=settings.batch,
            exclude=self._backoff.waiting_runs(),
        )
        for run in candidates:
            if self._monotonic() > deadline:
                return
            try:
                with _purging():
                    self._vault.purge(str(run.run_id))
                self._store.record_purged(run)
            except _FAILURES as exc:
                self._failed(report, run.run_id, exc)
                continue
            self._backoff.clear(run.run_id)
            report.purged += 1

    def _orphans(self, report: PassReport, deadline: float) -> None:
        names = self._vault.entries()
        skipped = self._runs_or_held(names)
        self._backoff.forget_missing_orphans(set(names))
        waiting = self._backoff.waiting()
        handled = 0
        for name in names:
            if UUID(name) in skipped or name in waiting:
                continue
            if self._monotonic() > deadline or handled >= self._settings.batch:
                return
            try:
                handled += self._orphan(report, name)
            except _FAILURES as exc:
                self._failed(report, name, exc)
                continue
            self._backoff.clear(name)

    def _runs_or_held(self, names: tuple[str, ...]) -> frozenset[UUID]:
        """有 scanner_runs 紀錄的目錄（不是孤兒），以及隔離中的孤兒目錄（分批查詢）。"""
        skipped: set[UUID] = set()
        for start in range(0, len(names), _KNOWN_BATCH):
            batch = [UUID(name) for name in names[start : start + _KNOWN_BATCH]]
            known = self._store.known(batch)
            skipped |= known | self._store.held([item for item in batch if item not in known])
        return frozenset(skipped)

    def _orphan(self, report: PassReport, name: str) -> int:
        """處理了（加密或刪除）回 1，還沒到時間回 0。"""
        state = self._vault.inspect(name)
        if state is None:
            return 0
        now = self._clock().timestamp()
        if state.plaintext:
            if now - state.newest_mtime < self._settings.orphan_quiet_seconds:
                return 0
            self._vault.seal(name)
            report.orphans_sealed += 1
            logger.info("孤兒目錄 %s 已加密", name)
            return 1
        sealed_at = self._vault.sealed_at(name)
        retention = timedelta(days=self._settings.retention_days).total_seconds()
        if sealed_at is None:
            if now - state.newest_mtime < self._settings.orphan_quiet_seconds:
                return 0
        elif now - sealed_at < retention:
            return 0
        with _purging():
            self._vault.purge(name)
        report.orphans_purged += 1
        logger.info("孤兒目錄 %s 已清除", name)
        return 1

    # --- 狀態 ------------------------------------------------------------------------------

    def _failed(
        self,
        report: PassReport,
        key: BackoffKey,
        exc: BaseException,
        *,
        run: EvidenceRun | None = None,
    ) -> None:
        """run 以 run_id、孤兒以名稱為鍵；連續的上限失敗到了門檻就隔離，寫入成功才不再退避。"""
        report.failures += 1
        attempt = self._backoff.failed(key, exc)
        code = attempt.hold_code()
        if code is None:
            delay = attempt.retry_at - self._monotonic()
            logger.error(
                "目錄 %s 的原始證據無法處理（%s）：保留原狀，%.0f 秒後重試", key, _kind(exc), delay
            )
            return
        directory = key if isinstance(key, UUID) else UUID(key)
        try:
            self._store.hold(directory, run, code, attempt.streak)
        except SQLAlchemyError as error:
            logger.error(_HOLD_FAILED, directory, attempt.streak, code, type(error).__name__)
            return
        self._backoff.clear(key)
        report.held += 1
        logger.error(_HELD, directory, attempt.streak, code)

    def _forget_held(self) -> None:
        """隔離已 commit、keeper 卻收到錯誤時，退避項目永遠不會清除：每一輪依 DB 清掉（§30.12）。"""
        keys = {
            key if isinstance(key, UUID) else UUID(key): key for key in self._backoff.directories()
        }
        if keys:
            for directory in self._store.held(list(keys)):
                self._backoff.clear(keys[directory])

    def _finish(self, report: PassReport) -> None:
        with self._state:
            self._healthy = report.clean
            self._finished_at = self._monotonic()
        counts = (
            report.expired,
            report.sealed,
            report.none,
            report.purged,
            report.orphans_sealed,
            report.orphans_purged,
        )
        if any(counts):
            logger.info(
                "keeper：逾期 %s、加密 %s、沒有目錄 %s、清除 %s、孤兒加密 %s、孤兒清除 %s", *counts
            )

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.run_pass()
            self._stop.wait(self._settings.interval_seconds)


@contextmanager
def _purging() -> Iterator[None]:
    """清除時超過上限不計入隔離：已加密的目錄被改過或環境有問題，維持全域 fail closed。"""
    try:
        yield
    except EvidenceLimitError as exc:
        raise EvidenceError(str(exc)) from None


def _kind(exc: BaseException) -> str:
    """錯誤的種類（EvidenceError 的訊息不含路徑或內容；其他只回報類別）。"""
    if isinstance(exc, EvidenceError):
        return str(exc)
    return type(exc).__name__
