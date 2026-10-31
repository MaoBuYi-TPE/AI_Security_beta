"""The final receiver control must not absorb a late out-of-scope delivery."""

from typing import Any
from unittest.mock import Mock

import pytest

from tests.live.guard_paths_regression import BoundaryRecording
from tests.live.guard_paths_support import EvidenceStore
from tests.live.guard_support import Receiver


def test_after_control_rejects_a_late_canary_delivery_before_resetting_the_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary_records = [{"path": "/t33-recorder-before"}, {"path": "/unexpected-late-request"}]
    control_records = [{"path": "/t33-recorder-before"}]
    receivers: list[Receiver] = []
    for name, records in (
        ("target", []),
        ("canary", canary_records),
        ("control-canary", control_records),
    ):
        receiver = Mock(spec=Receiver)
        receiver.name = name
        receiver.records.return_value = records
        receivers.append(receiver)
    recording = BoundaryRecording("encoded-params-1", Mock(spec=EvidenceStore), receivers)
    recording.baselines = {"canary": 1, "control-canary": 1}

    def deliver_control(label: str, *args: Any, **kwargs: Any) -> None:
        records = control_records if label.endswith("control-canary") else canary_records
        records.append({"path": "/t33-recorder-after"})

    send = Mock(side_effect=deliver_control)
    monkeypatch.setattr(recording, "send", send)

    with pytest.raises(AssertionError):
        recording.controls("after")

    send.assert_not_called()
    assert recording.baselines == {"canary": 1, "control-canary": 1}
    assert len(canary_records) == 2
