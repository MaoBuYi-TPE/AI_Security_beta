"""T22 S2：量測隔離 fixture 的 Nuclei matcher-status 輸出，不列印請求與回應。"""

import json
import uuid
from collections import Counter

import pytest

from tests.live.lab_support import start_fixture, stop_target
from tests.live.support import Api, admin_key
from tests.live.test_fixture_nuclei_live import _finished, _scan, _web_lab
from tests.live.zap_support import run_file, wait_for_zap

pytestmark = [pytest.mark.live, pytest.mark.enable_socket]


def test_matcher_status_event_shapes_in_isolated_fixture() -> None:
    admin = Api(admin_key())
    wait_for_zap(admin)
    target = start_fixture(vulnerable=True)
    try:
        item = _web_lab(admin, target)
        scan_id = _scan(item, "web_active_lab")
        engine = _finished(item, scan_id)
        events = item.operator.data("GET", f"/scans/{scan_id}/events")
        run_ids = {event["scanner_run_id"] for event in events if event["scanner_run_id"]}
        assert len(run_ids) == 1, (engine["status"], engine["error_code"])
        run_id = uuid.UUID(run_ids.pop())
        report = run_file(str(run_id), "out/results.jsonl")
        assert report is not None, (engine["status"], engine["error_code"])
        events = [json.loads(line) for line in report.splitlines() if line.strip()]
        statuses = Counter(str(event.get("matcher-status", "missing")) for event in events)
        shapes = Counter(
            (
                str(event.get("matcher-status", "missing")),
                bool(event.get("template-id")),
                bool(event.get("matched-at")),
                bool(event.get("error")),
            )
            for event in events
        )
        pairs = {(event.get("template-id"), event.get("matched-at")) for event in events}
        print(  # noqa: T201
            f"[S2] status={engine['status']} error={engine['error_code']} "
            f"bytes={len(report)} events={len(events)} statuses={dict(statuses)} "
            f"shapes={dict(shapes)} unique_template_location_pairs={len(pairs)}"
        )
        assert events, "沒有可檢查的 matcher-status 事件"
    finally:
        stop_target(target)
