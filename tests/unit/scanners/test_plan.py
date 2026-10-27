"""ExecutionPlan 的資料型別（docs/DECISIONS.md §14.3）：映像一律帶 tag 與 digest，上限是正整數。"""

import pytest

from secscan.scanners.domain.plan import ImageReference, InputFile, ResourceLimits

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
