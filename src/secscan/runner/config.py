"""runner 的設定（環境變數 RUNNER_*；docs/DECISIONS.md §14.8）。建立後不可修改。

預設值對應 compose 的 app stack：經 socket-proxy 連 Docker，volume 掛在 /runs 與 /run-secrets。
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from secscan.core.config import ENV_FILE
from secscan.runner.domain.policy import ContainerPolicy
from secscan.scanners.domain.fake import MAX_HOLD_SECONDS, FakeOutcome, FakeScript

MAX_POLL_SECONDS = 60


class RunnerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="RUNNER_",
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # Docker 的位址：只接受 tcp://主機:port（socket-proxy）或 unix:///絕對路徑。
    docker_url: str = Field(default="tcp://socket-proxy:2375", min_length=1)
    scan_network: str = Field(default="secscan_scan_net", min_length=1)
    runs_volume: str = Field(default="secscan_runs", min_length=1)
    secrets_volume: str = Field(default="secscan_run_secrets", min_length=1)
    # runner 容器內，兩個 volume 掛載的位置。
    runs_dir: Path = Path("/runs")
    secrets_dir: Path = Path("/run-secrets")
    poll_seconds: float = Field(default=2.0, gt=0, le=MAX_POLL_SECONDS)
    # fake 引擎的腳本（展示與 live 測試用）；secscan-admin runner 的參數可以覆寫。
    fake_outcome: FakeOutcome = FakeOutcome.SUCCEED
    fake_hold_seconds: float = Field(default=0, ge=0, le=MAX_HOLD_SECONDS)

    def container_policy(self) -> ContainerPolicy:
        return ContainerPolicy(
            scan_network=self.scan_network,
            runs_volume=self.runs_volume,
            secrets_volume=self.secrets_volume,
        )

    def fake_script(self) -> FakeScript:
        return FakeScript(outcome=self.fake_outcome, hold_seconds=self.fake_hold_seconds)
