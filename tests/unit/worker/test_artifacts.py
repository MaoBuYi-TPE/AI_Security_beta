"""worker 讀 runner 收集好的輸出（docs/DECISIONS.md §14.5、§16.5）。

只讀 manifest 列出的檔案，大小與 sha256 必須相符；不跟隨 symlink；超過上限、不符或讀不到都當成
沒有輸出（None）。
"""

import hashlib
import json
import os
from pathlib import Path
from uuid import UUID

import pytest

from secscan.worker.artifacts import ArtifactReader

RUN = UUID(int=7)


def _collect(runs: Path, files: dict[str, bytes], *, manifest: object = None) -> Path:
    out = runs / str(RUN) / "out"
    out.mkdir(parents=True)
    for name, content in files.items():
        (out / name).write_bytes(content)
    document = (
        manifest
        if manifest is not None
        else {
            "files": [
                {"path": name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
                for name, content in files.items()
            ],
            "run_id": str(RUN),
            "total_bytes": sum(len(content) for content in files.values()),
        }
    )
    (runs / str(RUN) / "manifest.json").write_text(json.dumps(document))
    return out


def test_listed_files_are_read(tmp_path: Path) -> None:
    _collect(tmp_path, {"authenticated.http": b"HTTP/1.1 200 OK\r\n\r\n{}"})

    content = ArtifactReader(tmp_path).read(RUN, "authenticated.http", max_bytes=1024)

    assert content == b"HTTP/1.1 200 OK\r\n\r\n{}"


def test_unlisted_or_missing_files_are_none(tmp_path: Path) -> None:
    out = _collect(tmp_path, {"a.http": b"a"})
    (out / "b.http").write_bytes(b"b")
    reader = ArtifactReader(tmp_path)

    assert reader.read(RUN, "b.http", max_bytes=10) is None
    assert reader.read(RUN, "c.http", max_bytes=10) is None
    assert reader.read(UUID(int=8), "a.http", max_bytes=10) is None


def test_changed_files_are_none(tmp_path: Path) -> None:
    out = _collect(tmp_path, {"a.http": b"original"})
    (out / "a.http").write_bytes(b"replaced")

    assert ArtifactReader(tmp_path).read(RUN, "a.http", max_bytes=100) is None


def test_files_over_the_limit_are_none(tmp_path: Path) -> None:
    _collect(tmp_path, {"a.http": b"x" * 11})

    assert ArtifactReader(tmp_path).read(RUN, "a.http", max_bytes=10) is None


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    secret = tmp_path / "elsewhere"
    secret.write_bytes(b"secret")
    out = _collect(tmp_path, {})
    os.symlink(secret, out / "a.http")
    manifest = {
        "files": [{"path": "a.http", "sha256": hashlib.sha256(b"secret").hexdigest(), "size": 6}],
        "run_id": str(RUN),
        "total_bytes": 6,
    }
    (tmp_path / str(RUN) / "manifest.json").write_text(json.dumps(manifest))

    assert ArtifactReader(tmp_path).read(RUN, "a.http", max_bytes=100) is None


@pytest.mark.parametrize("manifest", [[], {"files": "x"}, {"files": [{"path": "a.http"}]}])
def test_malformed_manifests_are_none(tmp_path: Path, manifest: object) -> None:
    _collect(tmp_path, {"a.http": b"a"}, manifest=manifest)

    assert ArtifactReader(tmp_path).read(RUN, "a.http", max_bytes=10) is None


@pytest.mark.parametrize("name", ["../manifest.json", "sub/a.http", "", "."])
def test_only_plain_names_are_read(tmp_path: Path, name: str) -> None:
    _collect(tmp_path, {"a.http": b"a"})

    with pytest.raises(ValueError, match="檔名"):
        ArtifactReader(tmp_path).read(RUN, name, max_bytes=10)


def test_deeply_nested_manifests_are_none(tmp_path: Path) -> None:
    _collect(tmp_path, {"a.http": b"a"}, manifest={"files": []})
    (tmp_path / str(RUN) / "manifest.json").write_bytes(b"[" * 100_000 + b"]" * 100_000)

    assert ArtifactReader(tmp_path).read(RUN, "a.http", max_bytes=10) is None
