"""worker 讀 guard 的 telemetry（docs/DECISIONS.md §16.6）：guard_telemetry volume 唯讀掛載。

每個轉送的請求一行（guard 寫的 jsonl），嚴格解析；回應的那幾行略過。讀不到、格式不符（含最後一行
沒有換行）、不是一般檔案或超過上限都回傳 None，原因記在 log（不含路徑）：這個 run 的 coverage 就不
算有量測依據。沒有檔案也是 None，由呼叫端依 guard 記下的轉送數判斷是不是根本沒有流量。
"""

import logging
import os
import stat
from pathlib import Path
from uuid import UUID

from secscan.grants.domain.scope import MAX_REQUESTS
from secscan.guard.domain.telemetry import (
    MAX_TELEMETRY_LINE_BYTES,
    ForwardedRequest,
    TelemetryError,
    decode_line,
    telemetry_file_name,
)

# 每個轉送的請求最多兩行（請求與回應）。
DEFAULT_MAX_BYTES = MAX_REQUESTS * 2 * MAX_TELEMETRY_LINE_BYTES
_OPEN = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
_CHUNK = 64 * 1024

logger = logging.getLogger(__name__)


class TelemetryReader:
    def __init__(self, directory: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self._directory = directory
        self._max_bytes = max_bytes

    def forwarded(self, run_id: UUID) -> tuple[ForwardedRequest, ...] | None:
        try:
            raw = self._read(run_id)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            logger.warning("run %s 的 telemetry 讀不到（%s）", run_id, type(exc).__name__)
            return None
        if raw and not raw.endswith(b"\n"):
            logger.warning("run %s 的 telemetry 最後一行不完整", run_id)
            return None
        try:
            records = [decode_line(line) for line in raw.splitlines(keepends=True)]
        except TelemetryError as exc:
            logger.warning("run %s 的 telemetry 格式不符（%s）", run_id, exc)
            return None
        return tuple(record for record in records if isinstance(record, ForwardedRequest))

    def _read(self, run_id: UUID) -> bytes:
        descriptor = os.open(self._directory / telemetry_file_name(run_id), _OPEN)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("不是一般檔案")
            chunks: list[bytes] = []
            total = 0
            while chunk := os.read(descriptor, _CHUNK):
                total += len(chunk)
                if total > self._max_bytes:
                    raise ValueError("超過上限")
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        return b"".join(chunks)
