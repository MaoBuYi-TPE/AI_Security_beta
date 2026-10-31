"""T33 evidence helpers, restricted to the disposable secscan-live Lab."""

import hashlib
import json
import os
import subprocess
import sys
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.fernet import Fernet

from tests.guard_path_evidence import EvidenceError, public_echo_rows, received_requests
from tests.live.guard_support import HERE
from tests.live.lab_support import Target, lab_image
from tests.live.support import GUARD_LAB_IP, LAB_NET, container, docker, inspect, wait_for

CAPTURE_IMAGE = (
    "mitmproxy/mitmproxy:12.2.3@sha256:"
    "00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"
)
ROOT = HERE.parents[1]


@dataclass(frozen=True)
class EvidenceStore:
    directory: Path
    key: bytes = field(repr=False)

    @classmethod
    def open(cls, version: str, label: str) -> "EvidenceStore":
        root = Path(os.environ["SECSCAN_GUARD_PATH_RECORD_DIR"]).resolve()
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        key_path = root / ".evidence.key"
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            key = key_path.read_bytes()
        else:
            key = Fernet.generate_key()
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(key)
        if key_path.stat().st_mode & 0o077:
            raise EvidenceError("evidence key must have mode 0600")
        directory = root / version / label
        if directory.is_symlink():
            raise EvidenceError("evidence directory must not be a symbolic link")
        if directory.exists() and any(directory.iterdir()):
            # Preserve failed attempts and prevent optional artifacts from a previous run
            # being mistaken for this run's output. Rename is atomic on this filesystem.
            archive = root / "archive" / version / label
            archive.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.rename(archive / uuid.uuid4().hex)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory.parent, 0o700)
        os.chmod(directory, 0o700)
        return cls(directory, key)

    def write(self, name: str, value: object) -> None:
        raw = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
        path = self.directory / (name + ".fernet")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(Fernet(self.key).encrypt(raw))

    def seal(self) -> None:
        """Hashes authenticate the exact encrypted local artifacts; never publish the key."""
        entries = {
            path.name: {
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
            }
            for path in sorted(self.directory.glob("*.fernet"))
            if path.name != "evidence-manifest.json.fernet"
        }
        self.write("evidence-manifest.json", entries)


class Capture:
    def __init__(self, target: Target, store: EvidenceStore) -> None:
        self.target, self.store = target, store
        self.name = f"secscan-live-t33-capture-{uuid.uuid4().hex[:8]}"
        self.path = store.directory / "packets.jsonl.fernet"
        self.process: subprocess.Popen[bytes] | None = None
        self.output: BinaryIO | None = None

    def start(self) -> "Capture":
        try:
            return self._start()
        except BaseException:
            self.cleanup()
            raise

    def _start(self) -> "Capture":
        info = inspect(self.target.container)
        assert set(info["NetworkSettings"]["Networks"]) == {LAB_NET}
        assert not info["HostConfig"].get("PortBindings")
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self.output = os.fdopen(descriptor, "wb")
        self.process = subprocess.Popen(  # noqa: S603 - fixed helper and isolated target namespace
            [  # noqa: S607
                "docker",
                "run",
                "--rm",
                "-i",
                "--name",
                self.name,
                "--network",
                f"container:{self.target.container}",
                "--read-only",
                "--log-driver",
                "none",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "NET_RAW",
                "--security-opt",
                "no-new-privileges:true",
                "--user",
                "0:0",
                "--memory",
                "128m",
                "--pids-limit",
                "16",
                "--entrypoint",
                "python3",
                "-v",
                f"{HERE / 'path_capture.py'}:/capture.py:ro",
                CAPTURE_IMAGE,
                "-I",
                "-B",
                "-u",
                "/capture.py",
            ],
            stdin=subprocess.PIPE,
            stdout=self.output,
            stderr=subprocess.PIPE,
        )
        assert self.process.stdin is not None
        self.process.stdin.write(
            json.dumps(
                {
                    "key": self.store.key.decode(),
                    "source": GUARD_LAB_IP,
                    "target": self.target.ip,
                    "port": self.target.port,
                }
            ).encode()
            + b"\n"
        )
        self.process.stdin.close()
        wait_for(lambda: self.path.stat().st_size > 0, timeout=20)
        assert self.events()[0] == {"kind": "ready"}
        return self

    def events(self) -> list[dict[str, Any]]:
        cipher = Fernet(self.store.key)
        return [json.loads(cipher.decrypt(line)) for line in self.path.read_bytes().splitlines()]

    def finish(self) -> list[dict[str, Any]]:
        assert self.process is not None
        assert self.output is not None
        docker("stop", "--time", "3", self.name)
        self.process.wait(timeout=10)
        self.output.close()
        events = self.events()
        if any(e["kind"] == "error" for e in events) or events[-1]["kind"] != "complete":
            raise EvidenceError("capture failed or did not finish")
        complete = events[-1]
        if complete["dropped"] or complete["limit_reached"]:
            raise EvidenceError("capture dropped packets or exceeded a limit")
        return received_requests(e for e in events if e["kind"] == "packet")

    def cleanup(self) -> None:
        docker("rm", "-f", self.name, check=False)
        if self.process is not None:
            self.process.wait(timeout=10)
            if self.process.stderr is not None:
                self.process.stderr.close()
        if self.output is not None:
            self.output.close()


@contextmanager
def route_echo(kind: str) -> Iterator[Target]:
    assert kind in {"flask", "express"}
    name, host = f"secscan-live-t33-echo-{kind}", f"lab-t33-{kind}"
    ip = "10.89.10.230" if kind == "flask" else "10.89.10.231"
    filename = "route_echo.py" if kind == "flask" else "route_echo.cjs"
    interpreter = "python" if kind == "flask" else "/nodejs/bin/node"
    image = lab_image("vampi-vuln" if kind == "flask" else "juice-shop")
    target = Target(name, host, ip, 8080)
    docker(
        "run",
        "-d",
        "--name",
        name,
        "--network",
        LAB_NET,
        "--ip",
        ip,
        "--network-alias",
        host,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "128m",
        "--pids-limit",
        "32",
        "--entrypoint",
        interpreter,
        "-v",
        f"{HERE / filename}:/echo/{filename}:ro",
        image,
        f"/echo/{filename}",
    )
    try:
        wait_for(lambda: '"versions"' in docker("logs", name), timeout=20)
        yield target
    finally:
        docker("rm", "-f", name, check=False)


def echo_records(target: Target) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in docker("logs", target.container).splitlines()
        if line.startswith("{")
    ]


_QUERY = """
import json, sys
from sqlalchemy import text
from secscan.core.config import Settings
from secscan.core.db import create_db_engine
engine = create_db_engine(Settings())
with engine.connect() as connection:
    if len(sys.argv) > 1:
        rows = connection.execute(text(
            "SELECT id::text, engine, status, guard_policy_version FROM scanner_runs "
            "WHERE scan_id = CAST(:scan AS uuid) ORDER BY sequence"), {"scan": sys.argv[1]})
        print(json.dumps([dict(row) for row in rows.mappings()]))
    else:
        count = connection.execute(text("SELECT count(*) FROM scanner_runs WHERE "
            "lease_owner IS NOT NULL OR status NOT IN "
            "('succeeded','failed','timed_out','cancelled','interrupted')"))
        print(json.dumps({"pending": count.scalar_one()}))
engine.dispose()
"""


def scan_runs(scan_id: str) -> list[dict[str, Any]]:
    return list(
        json.loads(
            docker(
                "exec", container("runner"), "python", "-I", "-c", _QUERY, str(uuid.UUID(scan_id))
            )
        )
    )


def drained() -> None:
    state = json.loads(docker("exec", container("runner"), "python", "-I", "-c", _QUERY))
    assert state["pending"] == 0, "refusing policy switch while runs/leases remain"
    names = docker("ps", "-a", "--filter", "label=secscan.scan_id", "--format", "{{.Names}}")
    assert not names.strip(), "refusing policy switch with scanner containers"


def environment(target: Target) -> dict[str, Any]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if "vampi" in inspect(target.container)["Config"]["Image"]:
        expected_versions = {"Flask": "2.2.2", "Werkzeug": "2.2.3"}
        versions = docker(
            "exec",
            target.container,
            "python",
            "-c",
            "import importlib.metadata as m,json; "
            "print(json.dumps({n:m.version(n) for n in ('Flask','Werkzeug')}))",
        )
    else:
        expected_versions = {"express": "4.22.3", "path-to-regexp": "0.1.13"}
        versions = docker(
            "exec",
            target.container,
            "/nodejs/bin/node",
            "-e",
            "console.log(JSON.stringify({express:"
            "require('/juice-shop/node_modules/express/package.json').version,"
            "'path-to-regexp':require('/juice-shop/node_modules/path-to-regexp/package.json').version}))",
        )
    actual_versions = json.loads(versions)
    assert actual_versions == expected_versions, "locked Lab framework versions changed"
    return {
        "commit": commit,
        "capture_image": CAPTURE_IMAGE,
        "target": {
            "image": inspect(target.container)["Config"]["Image"],
            "image_id": inspect(target.container)["Image"],
            "ip": target.ip,
        },
        "application_image_id": inspect(container("runner"))["Image"],
        "guard_image_id": inspect(container("guard"))["Image"],
        "frameworks": actual_versions,
        "capture_source_sha256": hashlib.sha256(
            (HERE / "path_capture.py").read_bytes()
        ).hexdigest(),
    }


def export_safe_echo_evidence() -> Path:
    root = Path(os.environ["SECSCAN_GUARD_PATH_RECORD_DIR"]).resolve()
    cipher = Fernet((root / ".evidence.key").read_bytes())
    groups = []
    for version in ("strict-1", "encoded-params-1"):
        for framework in ("flask", "express"):
            directory = root / version / f"golden-lab-t33-{framework}"

            def read(name: str, folder: Path = directory) -> Any:
                return json.loads(cipher.decrypt((folder / (name + ".fernet")).read_bytes()))

            environment_data = read("environment.json")
            raw = cipher.decrypt((directory / "telemetry.jsonl.fernet").read_bytes())
            rows = public_echo_rows(
                version,
                read("guard-decisions.jsonl"),
                [json.loads(line) for line in raw.splitlines()],
                read("target-requests.log"),
                read("probe-results.json"),
            )
            groups.append(
                {
                    "framework": framework,
                    "policy_version": version,
                    "rows": rows,
                    "commit": environment_data["commit"],
                    "framework_versions": environment_data["frameworks"],
                    "target_image": environment_data["target"]["image"],
                    "guard_image_id": environment_data["guard_image_id"],
                    "encrypted_manifest_sha256": hashlib.sha256(
                        (directory / "evidence-manifest.json.fernet").read_bytes()
                    ).hexdigest(),
                }
            )
    scans = []
    for version, label in (
        ("strict-1", "vampi-vuln"),
        ("strict-1", "juice-shop-paths"),
        ("encoded-params-1", "vampi-vuln"),
        ("encoded-params-1", "vampi-secure"),
        ("encoded-params-1", "juice-shop-paths"),
    ):
        directory = root / version / label
        analysis = json.loads(cipher.decrypt((directory / "analysis.json.fernet").read_bytes()))
        if analysis["missing"] or analysis["extra"]:
            raise EvidenceError("cannot export unverified scanner delivery")
        scans.append(
            {
                "policy_version": version,
                "label": label,
                **{
                    name: analysis[name]
                    for name in ("forwarded", "received", "forwarded_encoded", "sqli")
                },
            }
        )
    output = root / "derived" / "path-evidence.json"
    output.parent.mkdir(mode=0o700, exist_ok=True)
    output.write_text(
        json.dumps(
            {
                "schema": 1,
                "recorded_utc": datetime.now(UTC).isoformat(),
                "source": "fixed synthetic probes on locked Flask and Express images",
                "groups": groups,
                "scans": scans,
            },
            indent=2,
        )
        + "\n"
    )
    output.chmod(0o600)
    return output


if __name__ == "__main__":
    if sys.argv[1:] == ["drain"]:
        drained()
    elif sys.argv[1:] == ["export-safe"]:
        export_safe_echo_evidence()
    else:
        raise SystemExit("expected drain or export-safe")
