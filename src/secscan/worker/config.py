"""worker 的設定（環境變數 WORKER_*）。建立後不可修改。

worker 以唯讀掛載 runs volume（/runs，runner 收集好的輸出，docs/DECISIONS.md §16.5）與 guard 的
telemetry volume（/guard/telemetry，§16.6）；不掛 secrets、policy 與 status，也不接 Docker。
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from secscan.core.config import ENV_FILE


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="WORKER_",
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    runs_dir: Path = Path("/runs")
    telemetry_dir: Path = Path("/guard/telemetry")
