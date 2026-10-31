"""guard 的紀錄（docs/DECISIONS.md §15.1）：一行一個 JSON，不經 root logger（propagate=False）。

只記：canonical 的 run_id、決定、原因、method、host、port、path（不含 query、截斷）、上游 IP、
status、例外的類別。不記 header 的值、query、token 與例外的訊息（可能含請求的內容）。
不可見或非 ASCII 的值以 "?" 取代，log 不會被注入換行或控制字元。
"""

import json
import logging
import sys
from collections.abc import Mapping
from typing import TextIO
from uuid import UUID

from secscan.grants.domain.scope import PATH_MAX_LENGTH, HttpMethod
from secscan.guard.domain.policy import GuardPolicyVersion
from secscan.guard.domain.requests import RequestView, split_target

_FIELDS_ATTRIBUTE = "guard_fields"
_KNOWN_METHODS = frozenset({*(method.value for method in HttpMethod), "CONNECT", "TRACE"})
_HOST_LIMIT = 100
_PATH_LIMIT = PATH_MAX_LENGTH


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = getattr(record, _FIELDS_ATTRIBUTE, {})
        document = {
            "ts": round(record.created, 3),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
            **fields,
        }
        return json.dumps(document, ensure_ascii=True, sort_keys=False)


def guard_logger(name: str = "secscan.guard", stream: TextIO | None = None) -> logging.Logger:
    """一個只輸出 JSON 的 logger；重複呼叫同一個名稱不會加上第二個 handler。"""
    logger = logging.getLogger(name)
    logger.propagate = False
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
    return logger


class GuardLog:
    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def decision(
        self,
        *,
        allowed: bool,
        reason: str | None,
        run_id: UUID | None,
        view: RequestView | None,
        upstream: str | None = None,
        detail: str | None = None,
        policy_version: GuardPolicyVersion | None = None,
    ) -> None:
        fields: dict[str, object] = {
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "detail": detail,
            "policy_version": None if policy_version is None else policy_version.value,
            "run_id": None if run_id is None else str(run_id),
            "upstream": upstream,
        }
        if view is not None:
            fields.update(_request_fields(view))
        self._emit(logging.INFO, "request", fields)

    def exchange(
        self, event: str, *, run_id: UUID | None, status: int | None, upstream: str | None
    ) -> None:
        fields = {
            "run_id": None if run_id is None else str(run_id),
            "status": status,
            "upstream": upstream,
        }
        self._emit(logging.INFO, event, fields)

    def refused(self, event: str, **fields: object) -> None:
        self._emit(logging.WARNING, event, fields)

    def hook_failed(self, hook: str, error: BaseException) -> None:
        """只記例外的類別：訊息可能含請求的內容。"""
        self._emit(logging.WARNING, "hook_failed", {"hook": hook, "error": type(error).__name__})

    def info(self, event: str, **fields: object) -> None:
        self._emit(logging.INFO, event, fields)

    def _emit(self, level: int, event: str, fields: Mapping[str, object]) -> None:
        self._logger.log(level, event, extra={_FIELDS_ATTRIBUTE: fields})


def _request_fields(view: RequestView) -> dict[str, object]:
    path, _ = split_target(view.target)
    return {
        "method": view.method if view.method in _KNOWN_METHODS else "?",
        "host": safe_text(view.host, _HOST_LIMIT),
        "port": view.port,
        "path": safe_text(path, _PATH_LIMIT),
    }


def safe_text(text: str, limit: int) -> str:
    """可見的 ASCII 才原樣（截斷）記下，否則記 "?"。"""
    if text and all("!" <= character <= "~" for character in text):
        return text[:limit]
    return "?"
