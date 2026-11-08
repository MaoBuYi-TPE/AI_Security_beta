"""T21 報告的契約：ReportDocumentV1 的 JSON Schema 與 golden 快照一致，禁止的欄位不在 schema 中。

schema 改變必須經過審查（更新 golden 是刻意的變更，不為了通過測試擅自更新）。
"""

import json
from pathlib import Path
from typing import Any

from secscan.reports.document_schema import ReportDocumentV1

GOLDEN = Path(__file__).parent / "golden" / "report_document_v1.schema.json"
FORBIDDEN = (
    "storage_key",
    "path_on_disk",
    "ciphertext",
    "key_hash",
    "idempotency_key",
    "request_sha256",
    "lease_owner",
    "lease_expires_at",
    "actor_key_id",
    "requested_by_key_id",
    "created_by_key_id",
    "secret",
    "request_excerpt",
    "response_excerpt",
)


def _keys(node: Any) -> set[str]:
    if isinstance(node, dict):
        found = set(node.get("properties", {}))
        for value in node.values():
            found |= _keys(value)
        return found
    if isinstance(node, list):
        return set().union(*(_keys(item) for item in node)) if node else set()
    return set()


def test_schema_matches_the_reviewed_golden_snapshot() -> None:
    assert ReportDocumentV1.model_json_schema() == json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_schema_forbids_extra_fields_and_sensitive_names() -> None:
    schema = ReportDocumentV1.model_json_schema()
    keys = _keys(schema)
    for name in FORBIDDEN:
        assert name not in keys, name
    definitions = schema["$defs"].values()
    assert all(item.get("additionalProperties") is False for item in definitions)
    assert schema["additionalProperties"] is False
