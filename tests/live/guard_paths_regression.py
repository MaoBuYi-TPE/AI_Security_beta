"""Record the existing Guard boundary matrix under each T33 policy version.

Receiver controls use their own isolated network. Canary counts for the Guard interval must
remain zero; the control requests before and after prove both recorders are actually working.
"""

import base64
import time
from contextlib import ExitStack
from typing import Any

from tests.live.guard_paths_support import EvidenceStore
from tests.live.guard_support import (
    CANARY_IP,
    TARGET_IP,
    LivePolicy,
    Receiver,
    probe,
    raw_request,
    reconnect,
    remove_policy,
    start_receiver,
    stop_receiver,
    write_policy,
)
from tests.live.support import GUARD_LAB_IP, LAB_NET, PROJECT, TELEMETRY_VOLUME, inspect
from tests.live.test_guard_live import TARGET, _cases
from tests.live.zap_support import requests_since, volume_file

Case = tuple[str, bytes, int | None, str | None]
ENCODED = "encoded-params-1"
ENCODED_CROSS_CHECKS = {
    "no-credentials",
    "wrong-token",
    "canary-name",
    "canary-ip",
    "target-ip-form",
    "other-port",
    "other-alias",
    "uppercase",
    "trailing-dot",
    "host-mismatch",
    "padded-port",
    "hex-ip",
    "origin-form-other-host",
    "no-host-http10",
    "delete",
    "lowercase-get",
    "trace",
    "post-with-body",
    "method-override",
    "original-url",
    "query-method",
    "websocket",
    "https",
}
INFRASTRUCTURE = (
    "db:5432",
    "socket-proxy:2375",
    "api:8000",
    "control-canary:8080",
    "169.254.169.254:80",
    "host.docker.internal:80",
    "localhost.localdomain:80",
    f"{GUARD_LAB_IP}:8080",
)


class BoundaryRecording:
    def __init__(self, version: str, store: EvidenceStore, receivers: list[Receiver]) -> None:
        self.version, self.store, self.receivers = version, store, receivers
        self.expected: list[str] = []
        self.expected_hosts: list[list[str]] = []
        self.baselines: dict[str, int] = {}
        self.started = time.time()

    def send(self, label: str, cases: list[Case], **options: str) -> dict[str, dict[str, Any]]:
        # Store bytes before sending so a crash still leaves the intended requests available.
        self.store.write(
            label + "-raw-probes.json",
            [
                {
                    "name": name,
                    "raw": base64.b64encode(raw).decode(),
                    "expected_status": status,
                    "expected_reason": reason,
                }
                for name, raw, status, reason in cases
            ],
        )
        results = probe([(name, raw) for name, raw, _, _ in cases], **options)
        self.store.write(label + "-results.json", results)
        self.snapshot(label)
        for name, _, status, reason in cases:
            assert results[name]["status"] == status, (label, name)
            if reason is not None:
                assert results[name]["reason"] == reason, (label, name)
        return results

    def snapshot(self, label: str) -> None:
        self.store.write(
            label + "-records.json",
            {receiver.name: receiver.records() for receiver in self.receivers},
        )
        self.store.write(label + "-guard-decisions.json", requests_since(self.started))

    def exact_receipts(self) -> None:
        target, canary, control = self.receivers
        received = target.records()
        assert [r["path"] for r in received] == self.expected
        assert all(r["method"] == "GET" and r["peer"] == GUARD_LAB_IP for r in received)
        assert all(not r["proxy_authorization"] for r in received)
        assert [r["host"] for r in received] == self.expected_hosts
        for receiver in (canary, control):
            assert len(receiver.records()) == self.baselines[receiver.name]

    def controls(self, label: str) -> None:
        _, canary, control = self.receivers
        for receiver, host, network in (
            (canary, "lab-canary", LAB_NET),
            (control, "control-canary", f"{PROJECT}_control_net"),
        ):
            path = f"/t33-recorder-{label}"
            before = len(receiver.records())
            if receiver.name in self.baselines:
                assert before == self.baselines[receiver.name]
            self.send(
                f"{label}-{host}",
                [(label, raw_request(path, host=f"{host}:8080"), 200, None)],
                target=f"{host}:8080",
                network=network,
            )
            assert [r["path"] for r in receiver.records()[before:]] == [path]
            self.baselines[receiver.name] = before + 1

    def batch(
        self, label: str, policy: LivePolicy, cases: list[Case], delivered: list[str]
    ) -> dict[str, dict[str, Any]]:
        first, last = "/api/items/7?page=1", "/api/items"
        wrapped = [
            (
                "allowed-first",
                raw_request(
                    TARGET + first,
                    authorization=policy.authorization(),
                    headers=[("Proxy-Connection", "keep-alive")],
                ),
                200,
                None,
            ),
            *cases,
            (
                "allowed-last",
                raw_request(TARGET + last, authorization=policy.authorization()),
                200,
                None,
            ),
        ]
        self.expected.extend([first, *delivered, last])
        self.expected_hosts.extend([["lab-target:8080"] for _ in range(len(delivered) + 2)])
        results = self.send(label, wrapped)
        self.exact_receipts()
        return results


def _encoded_cases(policy: LivePolicy, version: str) -> list[Case]:
    cases = []
    for name, raw, status, reason in _cases(policy):
        if name not in ENCODED_CROSS_CHECKS:
            continue
        assert b"/api/items/7" in raw
        if version != ENCODED and reason == "METHOD_NOT_AUTHORIZED":
            reason = "PATH_AMBIGUOUS"
        cases.append(
            ("encoded-" + name, raw.replace(b"/api/items/7", b"/api/items/name%27"), status, reason)
        )
    accepted = version == ENCODED
    for name in ("encoded-first", "encoded-last"):
        cases.append(
            (
                name,
                raw_request(TARGET + "/api/items/name%27", authorization=policy.authorization()),
                200 if accepted else 403,
                None if accepted else "PATH_AMBIGUOUS",
            )
        )
    return cases


def _rebind(recording: BoundaryRecording, policy: LivePolicy) -> None:
    target, canary, _ = recording.receivers
    paths = ["/api/items/7", "/api/items/name%27"]

    def cases(stage: str) -> list[Case]:
        output: list[Case] = []
        for i, path in enumerate(paths):
            reason = None if stage in {"before", "restored"} else "ADDRESS_NOT_ALLOWED"
            if i == 1 and recording.version != ENCODED:
                reason = "PATH_AMBIGUOUS"
            output.append(
                (
                    f"{stage}-{i}",
                    raw_request(
                        "http://lab-rebind:8080" + path,
                        host="lab-rebind:8080",
                        authorization=policy.authorization(),
                    ),
                    200 if reason is None else 403,
                    reason,
                )
            )
        return output

    accepted = paths if recording.version == ENCODED else paths[:1]
    recording.expected.extend(accepted)
    recording.expected_hosts.extend([["lab-rebind:8080"] for _ in accepted])
    recording.send("dns-before", cases("before"))
    recording.exact_receipts()
    try:
        reconnect(canary, ip=CANARY_IP, aliases=("lab-canary", "lab-rebind"))
        recording.send("dns-shared", cases("shared"))
        recording.exact_receipts()
        reconnect(target, ip=TARGET_IP, aliases=("lab-target", "lab-target-alt"))
        recording.send("dns-moved", cases("moved"))
        recording.exact_receipts()
    finally:
        # Restore both even if one reconnection fails; ExitStack will remove both containers.
        try:
            reconnect(target, ip=TARGET_IP, aliases=("lab-target", "lab-rebind", "lab-target-alt"))
        finally:
            reconnect(canary, ip=CANARY_IP, aliases=("lab-canary",))
    recording.expected.extend(accepted)
    recording.expected_hosts.extend([["lab-rebind:8080"] for _ in accepted])
    recording.send("dns-restored", cases("restored"))
    recording.exact_receipts()


def boundary_probes(version: str) -> None:
    store = EvidenceStore.open(version, "guard-boundary-regression")
    with ExitStack() as cleanup:
        cleanup.callback(store.seal)
        receivers: list[Receiver] = []
        for name, ip, aliases, network in (
            ("t33-target", TARGET_IP, ("lab-target", "lab-rebind", "lab-target-alt"), LAB_NET),
            ("t33-canary", CANARY_IP, ("lab-canary",), LAB_NET),
            ("t33-control-canary", None, ("control-canary",), f"{PROJECT}_control_net"),
        ):
            receiver = Receiver(name)
            cleanup.callback(stop_receiver, receiver)
            start_receiver(name, ip=ip, aliases=aliases, network=network)
            receivers.append(receiver)
            assert receiver.records() == []
        recording = BoundaryRecording(version, store, receivers)
        # Snapshot is registered after receiver cleanup, hence runs before receivers disappear.
        cleanup.callback(recording.snapshot, "final")
        store.write(
            "environment.json",
            {
                "policy_version": version,
                "receivers": {
                    receiver.name: {
                        "image_id": inspect(receiver.container)["Image"],
                        "networks": inspect(receiver.container)["NetworkSettings"]["Networks"],
                    }
                    for receiver in receivers
                },
            },
        )
        policy = write_policy(policy_version=version)
        cleanup.callback(remove_policy, policy)
        rebind = write_policy(origin="http://lab-rebind:8080", policy_version=version)
        cleanup.callback(remove_policy, rebind)
        recording.controls("before")
        original = _cases(policy)
        assert len(original) == 34
        recording.batch("original-34", policy, original, [])
        recording.batch(
            "encoded-boundaries",
            policy,
            _encoded_cases(policy, version),
            ["/api/items/name%27"] * 2 if version == ENCODED else [],
        )
        infra: list[Case] = [
            (
                f"infra-{i}-{kind}",
                raw_request(
                    f"http://{authority}{path}",
                    host=authority,
                    authorization=policy.authorization(),
                ),
                403,
                "ORIGIN_MISMATCH",
            )
            for i, authority in enumerate(INFRASTRUCTURE)
            for kind, path in (("plain", "/"), ("encoded", "/api/items/name%27"))
        ]
        recording.batch("infrastructure", policy, infra, [])
        redirected = recording.batch(
            "redirect-responses",
            policy,
            [
                (name, raw_request(TARGET + path, authorization=policy.authorization()), 302, None)
                for name, path in (
                    ("canary", "/api/items/redirect"),
                    ("excluded", "/api/items/redirect-excluded"),
                )
            ],
            ["/api/items/redirect", "/api/items/redirect-excluded"],
        )
        assert redirected["canary"]["location"] == "http://lab-canary:8080/api/items/7"
        assert redirected["excluded"]["location"] == "/api/admin"
        recording.batch(
            "redirect-followed",
            policy,
            [
                (
                    "canary",
                    raw_request(
                        str(redirected["canary"]["location"]),
                        host="lab-canary:8080",
                        authorization=policy.authorization(),
                    ),
                    403,
                    "ORIGIN_MISMATCH",
                ),
                (
                    "excluded",
                    raw_request(
                        TARGET + str(redirected["excluded"]["location"]),
                        authorization=policy.authorization(),
                    ),
                    403,
                    "PATH_EXCLUDED",
                ),
                (
                    "encoded-canary",
                    raw_request(
                        str(redirected["canary"]["location"]).replace("/7", "/name%27"),
                        host="lab-canary:8080",
                        authorization=policy.authorization(),
                    ),
                    403,
                    "ORIGIN_MISMATCH",
                ),
            ],
            [],
        )
        _rebind(recording, rebind)
        recording.exact_receipts()
        # Confirm every authenticated request was evaluated under the explicit phase policy.
        decisions = [
            d
            for d in requests_since(recording.started)
            if d.get("run_id") in {policy.run_id, rebind.run_id}
        ]
        assert decisions
        assert all(d["policy_version"] == version for d in decisions)
        for label, item in (("matrix", policy), ("rebind", rebind)):
            for suffix in (".jsonl", ".summary.json"):
                artifact = volume_file(TELEMETRY_VOLUME, item.run_id + suffix)
                assert artifact is not None
                store.write(label + "-telemetry" + suffix, artifact)
        store.write(
            "analysis.json",
            {
                "policy_version": version,
                "original_cases": len(original),
                "target_paths": recording.expected,
                "guard_interval_canary_received": 0,
                "guard_interval_control_canary_received": 0,
            },
        )
        recording.controls("after")
        recording.exact_receipts()
