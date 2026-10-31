"""runner 測試用的 guard 通道：真的 policy 與 status 目錄（tmp），status 由測試寫入。

guard 本身不執行；測試以 status 檔模擬 guard 可用、過期、重啟或不再檢查，以 summary 檔模擬 guard
記下的用量，並讀回 runner 寫的 policy。
"""

import time
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import UUID, uuid4

from secscan.guard.domain.policy import (
    POLICY_SCHEMA,
    GuardPolicyVersion,
    Policy,
    decode_policy,
    policy_file_name,
)
from secscan.guard.domain.status import STATUS_FILE_NAME, GuardStatus, encode_status
from secscan.guard.domain.telemetry import RunSummary, encode_summary, summary_file_name
from secscan.guard.files import remove_file, write_atomic
from secscan.runner.egress import GuardEndpoint
from secscan.runner.guard import GuardChannel

GUARD_LISTEN = "10.89.8.254:8080"
ENDPOINT = GuardEndpoint.parse(GUARD_LISTEN)


@dataclass
class GuardDouble:
    policies: Path
    status_dir: Path
    telemetry: Path
    boot_id: UUID

    @classmethod
    def create(cls, root: Path) -> "GuardDouble":
        policies, status_dir = root / "guard-policies", root / "guard-status"
        telemetry = root / "guard-telemetry"
        for directory in (policies, status_dir, telemetry):
            directory.mkdir()
        double = cls(policies, status_dir, telemetry, uuid4())
        double.healthy()
        return double

    def channel(self) -> GuardChannel:
        return GuardChannel(
            self.policies, self.status_dir, telemetry_dir=self.telemetry, listen=GUARD_LISTEN
        )

    def write_summary(
        self,
        run_id: UUID,
        scan_id: UUID,
        *,
        forwarded: int,
        denied: dict[str, int] | None = None,
        exhausted: bool = False,
        boot_id: UUID | None = None,
        policy_version: GuardPolicyVersion = GuardPolicyVersion.STRICT,
    ) -> None:
        summary = RunSummary(
            policy_version=policy_version,
            run_id=run_id,
            scan_id=scan_id,
            boot_id=boot_id or self.boot_id,
            forwarded=forwarded,
            denied=denied or {},
            exhausted=exhausted,
        )
        write_atomic(self.telemetry, summary_file_name(run_id), encode_summary(summary))

    def status(self, **overrides: object) -> GuardStatus:
        now = int(time.time())
        status = GuardStatus(
            boot_id=self.boot_id,
            started_at=now,
            updated_at=now,
            listen=GUARD_LISTEN,
            policy_schema=POLICY_SCHEMA,
            enforcing=True,
        )
        return replace(status, **overrides)  # type: ignore[arg-type]

    def healthy(self) -> None:
        self.write_status(self.status())

    def write_status(self, status: GuardStatus) -> None:
        write_atomic(self.status_dir, STATUS_FILE_NAME, encode_status(status))

    def stop(self) -> None:
        """guard 停止：status 標成不再檢查。"""
        self.write_status(self.status(enforcing=False))

    def vanish(self) -> None:
        remove_file(self.status_dir, STATUS_FILE_NAME)

    def restart(self) -> None:
        self.boot_id = uuid4()
        self.healthy()

    def policy(self, run_id: UUID) -> Policy | None:
        path = self.policies / policy_file_name(run_id)
        if not path.exists():
            return None
        return decode_policy(path.read_bytes(), run_id=run_id)

    def policy_files(self) -> list[str]:
        return sorted(path.name for path in self.policies.iterdir())
