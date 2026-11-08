"""T21 live：平台報告的下載與核對（sha256、header、schema、Markdown 安全、標示與用語）。"""

import hashlib
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

from markdown_it import MarkdownIt
from markdown_it.token import Token

from secscan.reports.document_schema import ReportDocumentV1
from secscan.reports.domain.wording import (
    BASIS_LABELS,
    NOTICES,
    TRIAGE_LABELS,
    claims_violations,
)

DOWNLOAD_TIMEOUT_SECONDS = 30
_URL = re.compile(r"[a-z][a-z0-9+.-]*://|www\.|@[a-z0-9-]+\.", re.IGNORECASE)
_CODE = re.compile(r"<code>.*?</code>", re.DOTALL)
_MEDIA = {"json": "application/json", "markdown": "text/markdown; charset=utf-8"}
_EXTENSIONS = {"json": "json", "markdown": "md"}


def download(base: str, key: str, report_id: str) -> tuple[int, Mapping[str, str], bytes]:
    request = urllib.request.Request(  # noqa: S310 - 固定的本機 API
        f"{base}/reports/{report_id}/download",
        headers={"Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:  # noqa: S310
            return response.status, dict(response.headers.items()), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers.items()), error.read()


def check_headers(meta: Mapping[str, Any], headers: Mapping[str, str], content: bytes) -> None:
    lowered = {name.lower(): value for name, value in headers.items()}
    assert hashlib.sha256(content).hexdigest() == meta["sha256"]
    assert len(content) == meta["size_bytes"]
    report_format = str(meta["format"])
    assert lowered["content-type"] == _MEDIA[report_format]
    assert lowered["x-content-type-options"] == "nosniff"
    assert lowered["content-security-policy"] == "default-src 'none'; sandbox"
    assert lowered["cache-control"] == "no-store"
    filename = (
        f"secscan-report-{str(meta['scan_id']).replace('-', '')[:8]}-"
        f"{str(meta['id']).replace('-', '')[:8]}.{_EXTENSIONS[report_format]}"
    )
    assert lowered["content-disposition"] == f'attachment; filename="{filename}"'


def _flatten(tokens: list[Token]) -> list[Token]:
    flat: list[Token] = []
    for token in tokens:
        flat.append(token)
        if token.children:
            flat.extend(_flatten(token.children))
    return flat


def check_markdown(text: str) -> str:
    """Markdown 的 token 不變式；回傳 code 以外的文字（給用語檢查）。"""
    markdown = MarkdownIt("commonmark").enable("table")
    tokens = _flatten(markdown.parse(text))
    forbidden = {"html_block", "html_inline", "link_open", "image"}
    assert not [token.type for token in tokens if token.type in forbidden]
    plain = [token.content for token in tokens if token.type == "text"]
    for content in plain:
        assert not _URL.search(content), content
    outside = _CODE.sub("", markdown.render(text).lower())
    for needle in ("<a", "<img", "<script", "href=", "src="):
        assert needle not in outside
    return "\n".join(plain)


def check_document(content: bytes, *, complete: bool) -> ReportDocumentV1:
    document = ReportDocumentV1.model_validate_json(content)
    assert document.notices[: len(NOTICES)] == list(NOTICES)
    assert document.scan.results_complete is complete
    if not complete:
        assert any(notice.startswith("掃描未完整完成") for notice in document.notices)
    assert document.authorization.approved_at is not None
    for finding in document.findings:
        assert finding.triage_label == TRIAGE_LABELS[finding.triage_state]
        if finding.lifecycle_state == "resolved":
            assert finding.resolution is not None
            assert finding.resolution.basis_label == BASIS_LABELS[finding.resolution.basis]
    for text in (*document.notices, *(f.triage_label for f in document.findings)):
        assert claims_violations(text) == []
    return document
