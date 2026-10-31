"""ExecutionPlan 的資料型別（docs/DECISIONS.md §14.3）：映像一律帶 tag 與 digest，上限是正整數。

plan_hash 是實際執行的內容的 sha256（§20.2）：run 與 scan 的 id 之外的每個欄位都算。
"""

from uuid import UUID

import pytest

from secscan.scanners.domain.plan import (
    ExecutionPlan,
    ImageReference,
    InputFile,
    ResourceLimits,
    plan_hash,
)
from secscan.scans.domain.catalog import Engine

DIGEST = "sha256:" + "ab" * 32


@pytest.mark.parametrize(
    "text",
    [
        f"busybox:1.38.0@{DIGEST}",
        f"projectdiscovery/nuclei:v3.11.1@{DIGEST}",
        f"ghcr.io/zaproxy/zaproxy:2.17.0@{DIGEST}",
        f"registry.example:5000/team/tool-x_y:1.0-rc.1@{DIGEST}",
    ],
)
def test_image_reference_round_trips(text: str) -> None:
    assert str(ImageReference.parse(text)) == text


@pytest.mark.parametrize(
    "text",
    [
        "busybox",
        "busybox:1.38.0",
        f"busybox@{DIGEST}",
        "busybox:latest@sha256:" + "ab" * 31,
        "busybox:1.38.0@sha256:" + "AB" * 32,
        f"BusyBox:1.38.0@{DIGEST}",
        f"busybox:1.38.0@{DIGEST}\n",
        f" busybox:1.38.0@{DIGEST}",
        f"busybox:-x@{DIGEST}",
        f"../busybox:1@{DIGEST}",
        f"busybox:1@sha512:{'ab' * 64}",
    ],
)
def test_image_reference_must_be_pinned(text: str) -> None:
    with pytest.raises(ValueError, match="digest"):
        ImageReference.parse(text)


def test_image_reference_parts() -> None:
    image = ImageReference.parse(f"busybox:1.38.0@{DIGEST}")

    assert (image.repository, image.tag, image.digest) == ("busybox", "1.38.0", DIGEST)


@pytest.mark.parametrize("field", ["memory_bytes", "nano_cpus", "pids", "wall_clock_seconds"])
@pytest.mark.parametrize("value", [0, -1, True])
def test_resource_limits_must_be_positive_integers(field: str, value: int) -> None:
    values = {"memory_bytes": 1, "nano_cpus": 1, "pids": 1, "wall_clock_seconds": 1, field: value}

    with pytest.raises(ValueError, match=field):
        ResourceLimits(**values)


@pytest.mark.parametrize("name", ["run.json", "plan.yaml", "a", "x-1_2.txt"])
def test_input_names(name: str) -> None:
    assert InputFile(name, b"{}").name == name


@pytest.mark.parametrize(
    "name", ["", ".hidden", "../x", "a/b", "A.json", "x" * 65, "run.json\n", "ü.json"]
)
def test_input_names_are_plain(name: str) -> None:
    with pytest.raises(ValueError, match="輸入檔"):
        InputFile(name, b"{}")


def _plan(**changes: object) -> ExecutionPlan:
    values: dict[str, object] = {
        "run_id": UUID(int=1),
        "scan_id": UUID(int=2),
        "engine": Engine.ZAP,
        "image": ImageReference.parse(f"zaproxy/zap-stable:20261016@{DIGEST}"),
        "entrypoint": ("/bin/sh", "-c"),
        "arguments": ("run",),
        "environment": (("SITE", "http://lab:3000"),),
        "inputs": (InputFile("plan.yaml", b'{"maxDuration": 840}'),),
        "target_auth": False,
        "limits": ResourceLimits(memory_bytes=1, nano_cpus=1, pids=1, wall_clock_seconds=900),
    }
    return ExecutionPlan(**{**values, **changes})  # type: ignore[arg-type]


def test_the_plan_hash_is_stable_across_runs() -> None:
    """run 與 scan 的 id 不算：同樣的 plan 在不同的 run 得到同一個 hash（可以比較）。"""
    first = plan_hash(_plan())

    assert first == plan_hash(_plan(run_id=UUID(int=8), scan_id=UUID(int=9)))
    assert len(first) == 64
    assert int(first, 16) >= 0


@pytest.mark.parametrize(
    "change",
    [
        {"image": ImageReference.parse(f"zaproxy/zap-stable:20261017@{DIGEST}")},
        {"entrypoint": ("/bin/sh",)},
        {"arguments": ("run", "again")},
        {"environment": (("SITE", "http://lab:3001"),)},
        {"inputs": (InputFile("plan.yaml", b'{"maxDuration": 900}'),)},
        {"inputs": (InputFile("plan.yml", b'{"maxDuration": 840}'),)},
        {"target_auth": True},
        {"engine": Engine.PREFLIGHT},
        {"limits": ResourceLimits(memory_bytes=2, nano_cpus=1, pids=1, wall_clock_seconds=900)},
        {"limits": ResourceLimits(memory_bytes=1, nano_cpus=1, pids=1, wall_clock_seconds=901)},
    ],
)
def test_everything_that_is_executed_changes_the_plan_hash(change: dict[str, object]) -> None:
    """規則與 maxDuration 在 plan.yaml 中，映像 digest、資源與牆鐘上限都算（§20.2）。"""
    assert plan_hash(_plan(**change)) != plan_hash(_plan())


def test_fields_do_not_bleed_into_each_other() -> None:
    joined = _plan(arguments=("a", "b"))
    merged = _plan(arguments=("a b",))

    assert plan_hash(joined) != plan_hash(merged)
