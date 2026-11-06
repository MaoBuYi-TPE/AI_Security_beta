"""fixture 換版時保留 target 的網路身分、不留下匿名 volume；不連 Docker。"""

from pathlib import Path
from typing import Any

import yaml

from tests.live import lab_support

COMPOSE = Path(__file__).resolve().parents[2] / "compose.yaml"


def _run_calls(monkeypatch: Any) -> list[tuple[str, ...]]:
    calls: list[tuple[str, ...]] = []

    def docker(*args: str, **kwargs: Any) -> str:
        calls.append(args)
        return '{"ready": true}'

    monkeypatch.setattr(lab_support, "docker", docker)
    monkeypatch.setattr(lab_support, "wait_for", lambda check, **kwargs: check())
    return calls


def _guard_image_volume() -> str:
    """compose 的 guard 以 tmpfs 蓋住映像宣告的 VOLUME；fixture 跑在同一個映像上。"""
    tmpfs = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]["guard"]["tmpfs"]
    [path] = [entry.split(":", 1)[0] for entry in tmpfs if ".mitmproxy" in entry]
    return str(path)


def test_fixture_mounts_tmpfs_over_the_guard_image_volume(monkeypatch: Any) -> None:
    calls = _run_calls(monkeypatch)

    lab_support.start_fixture(vulnerable=True)
    lab_support.start_fixture(vulnerable=False)

    runs = [call for call in calls if call and call[0] == "run"]
    assert len(runs) == 2
    volume = _guard_image_volume()
    for call in runs:
        mounts = [call[i + 1] for i, arg in enumerate(call) if arg == "--tmpfs"]
        assert any(mount.split(":", 1)[0] == volume for mount in mounts), call


def test_fixture_versions_can_reuse_one_host_alias(monkeypatch: Any) -> None:
    calls = _run_calls(monkeypatch)
    vulnerable = lab_support.start_fixture(vulnerable=True, host="lab-fixture-stable")
    secure = lab_support.start_fixture(vulnerable=False, host="lab-fixture-stable")

    assert vulnerable.host == secure.host == "lab-fixture-stable"
    assert vulnerable.ip == secure.ip
    assert vulnerable.port == secure.port
    runs = [call for call in calls if call and call[0] == "run"]
    assert len(runs) == 2
    assert all(call[call.index("--network-alias") + 1] == vulnerable.host for call in runs)
