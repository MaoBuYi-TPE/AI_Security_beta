"""執行中的 scan 的 live 測試共用：借用掃描容器的 proxy 帳密、等容器、記下容器的事件與 policy 的
狀態、讓 lease 過期（docs/DECISIONS.md §15.7、§17）。

fake 引擎本身不送流量：掃描期間的收包證據以掃描容器拿到的 proxy-url 從探針送出請求。

「先封鎖 guard、再停止容器」的時間線：policy 變成 blocked 的時間由唯讀掛載 policy volume 的觀察者
記下（每 1 ms 讀一次），容器的 kill／die 由 docker events 記下，兩者都是 VM 的時鐘。guard 的
RUN_BLOCKED log 不適合比較先後：速率限制讓探針的請求在 guard 中等待，醒來時才判斷與記錄。
"""

import base64
import json
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from tests.live.guard_support import raw_request
from tests.live.support import (
    GUARD_IMAGE,
    POLICIES_VOLUME,
    Scannable,
    container,
    docker,
    scan_containers,
    wait_for,
)

HERE = Path(__file__).resolve().parent

# 以 db 容器自己的環境變數連線：密碼不經過測試，也不會印出。run_id 以 psql 的變數帶入。
_EXPIRE_LEASE = (
    "UPDATE scanner_runs SET lease_expires_at = now() - interval '1 second' WHERE id = :'run_id';\n"
)
_PSQL = (
    'PGPASSWORD="$SECSCAN_APP_DB_PASSWORD" psql -h 127.0.0.1 -U "$SECSCAN_APP_DB_USER" '
    '-d "$SECSCAN_APP_DB_NAME" -q -v ON_ERROR_STOP=1 -v run_id="$0"'
)


@dataclass(frozen=True)
class Borrowed:
    """執行中的掃描容器的 proxy 帳密（測試借來從探針送請求）。"""

    run_id: str
    token: str
    container: str

    def request(self, origin: str, path: str) -> bytes:
        credentials = base64.b64encode(f"{self.run_id}:{self.token}".encode()).decode()
        host = urlsplit(origin).netloc
        return raw_request(f"{origin}{path}", host=host, authorization=f"Basic {credentials}")


def running(scan_id: str) -> str:
    """fake 的容器：綁定 auth profile 的 scan 先跑 preflight（§16.5），它很快就結束。"""

    def find() -> str | None:
        names = scan_containers(scan_id, "fake")
        return names[0] if names else None

    return wait_for(find, timeout=60)


def borrow(name: str) -> Borrowed:
    url = docker("exec", name, "cat", "/scan/secret/proxy-url").strip()
    parts = urlsplit(url)
    assert parts.username is not None
    assert parts.password is not None
    return Borrowed(run_id=parts.username, token=parts.password, container=name)


def fake_engine(item: Scannable, scan_id: str) -> dict[str, object]:
    """fake 的 run（第一個是 preflight，§16.5）。"""
    engines = item.operator.data("GET", f"/scans/{scan_id}")["engines"]
    [engine] = [engine for engine in engines if engine["engine"] == "fake"]
    return dict(engine)


@dataclass
class ContainerEvents:
    """runner 建立的容器的事件串流（在建立 scan 之前開始）。

    `docker events --since` 只重播 daemon 記憶體中最近的事件，測試期間其他容器的事件會把它擠掉，
    所以改成即時串流。
    """

    _process: subprocess.Popen[str]
    _lines: list[str] = field(default_factory=list)

    @classmethod
    def start(cls) -> "ContainerEvents":
        process = subprocess.Popen(
            [  # noqa: S607
                "docker",
                "events",
                "--filter",
                "type=container",
                "--filter",
                "label=secscan.managed=true",
                "--format",
                "{{.TimeNano}} {{.Action}} {{.Actor.Attributes.name}}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        time.sleep(1)  # 等串流開始
        return cls(process)

    def stop(self) -> None:
        if self._process.poll() is None:
            time.sleep(1)  # 讓最後的事件送達
            self._process.terminate()
            output, _ = self._process.communicate(timeout=30)
            self._lines = output.splitlines()

    def of(self, name: str) -> list[tuple[float, str]]:
        """這個容器的事件（時間、動作），依時間排序。先呼叫 stop。"""
        events = []
        for line in self._lines:
            moment, action, actor = line.split(" ", 2)
            if actor == name:
                events.append((int(moment) / 1e9, action))
        return sorted(events)


class PolicyWatch:
    """背景的 policy 觀察者：記下某個 run 的 policy 每次改變狀態的時間。"""

    def __init__(self, process: subprocess.Popen[str]) -> None:
        self._process = process

    @classmethod
    def start(cls, run_id: str, *, seconds: float) -> "PolicyWatch":
        process = subprocess.Popen(  # noqa: S603 - 固定的 docker 指令與測試自己組的參數
            [  # noqa: S607
                "docker",
                "run",
                "--rm",
                "-i",
                "--name",
                f"secscan-live-policy-watch-{uuid.uuid4().hex[:8]}",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--entrypoint",
                "python3",
                "-v",
                f"{HERE / 'policy_watch.py'}:/probe/policy_watch.py:ro",
                "-v",
                f"{POLICIES_VOLUME}:/policies:ro",
                GUARD_IMAGE,
                "-I",
                "-B",
                "/probe/policy_watch.py",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        assert process.stdin is not None
        process.stdin.write(json.dumps({"run_id": str(uuid.UUID(run_id)), "seconds": seconds}))
        process.stdin.close()
        watch = cls(process)
        time.sleep(1.5)  # 等容器開始讀
        return watch

    def changes(self, *, timeout: float = 120) -> list[tuple[float, str]]:
        """等觀察者結束，回傳每次改變的（時間、狀態）。"""
        assert self._process.stdout is not None
        output = self._process.stdout.read()
        self._process.wait(timeout=timeout)
        records = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
        return [(float(record["t"]), str(record["state"])) for record in records]


def first(changes: list[tuple[float, str]], state: str) -> float:
    moments = [moment for moment, value in changes if value == state]
    assert moments, f"policy 沒有變成 {state}：{[value for _, value in changes]}"
    return min(moments)


def stopped_at(events: list[tuple[float, str]]) -> float:
    """容器第一次收到 kill 或結束的時間。"""
    stops = [moment for moment, action in events if action in {"kill", "die"}]
    assert stops
    return min(stops)


def expire_lease(run_id: str) -> None:
    """runner 被 SIGKILL 之後讓 lease 立刻過期（不等 30 秒，容器還在執行）。"""
    docker(
        "exec",
        "-i",
        container("db"),
        "sh",
        "-c",
        _PSQL,
        str(uuid.UUID(run_id)),
        stdin=_EXPIRE_LEASE,
    )


def policy_files() -> list[str]:
    """runner 看到的 guard policy 目錄。"""
    return docker("exec", container("runner"), "ls", "-A", "/guard/policies").split()
