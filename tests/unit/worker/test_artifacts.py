"""worker 讀 runner 收集好的輸出（docs/DECISIONS.md §14.5、§16.5）。

只讀 manifest 列出的檔案，大小與 sha256 必須相符；不跟隨 symlink；超過上限、不符或讀不到都當成
沒有輸出（None）。
"""

import hashlib
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from secscan.worker.artifacts import ArtifactReader, ManifestFile, RunManifest

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


# --- manifest（docs/DECISIONS.md §19.7）------------------------------------------------------


def _write_manifest(runs: Path, content: bytes) -> UUID:
    run_id = uuid4()
    (runs / str(run_id)).mkdir()
    (runs / str(run_id) / "manifest.json").write_bytes(content)
    return run_id


def _manifest_document(**changes: object) -> bytes:
    document: dict[str, object] = {
        "exit_code": 2,
        "files": [{"path": "a.json", "size": 1, "sha256": "ab" * 32, "redactions": 3}],
        "inputs": [{"path": "plan.yaml", "size": 2, "sha256": "cd" * 32}],
        "run_id": "ignored",
        "total_bytes": 1,
    }
    return json.dumps({**document, **changes}).encode()


def test_the_manifest_is_read_with_the_exit_code(tmp_path: Path) -> None:
    run_id = _write_manifest(tmp_path, _manifest_document())

    manifest = ArtifactReader(tmp_path).manifest(run_id)

    assert manifest == RunManifest(
        exit_code=2,
        files=(ManifestFile("a.json", 1, "ab" * 32, 3),),
        inputs=(ManifestFile("plan.yaml", 2, "cd" * 32),),
    )
    assert manifest is not None
    assert manifest.lists("a.json")
    assert not manifest.lists("plan.yaml")


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[]",
        b"\xff",
        b'{"exit_code": ' + b"1" * 5000 + b"}",
        _manifest_document(exit_code=None),
        _manifest_document(exit_code=True),
        _manifest_document(exit_code=256),
        _manifest_document(exit_code=-1),
        _manifest_document(files=None),
        _manifest_document(inputs=None),
        _manifest_document(files=["x"]),
        _manifest_document(files=[{"path": "", "size": 1, "sha256": "ab" * 32}]),
        _manifest_document(files=[{"path": "a", "size": -1, "sha256": "ab" * 32}]),
        _manifest_document(files=[{"path": "a", "size": True, "sha256": "ab" * 32}]),
        _manifest_document(files=[{"path": "a", "size": 1, "sha256": "zz"}]),
        _manifest_document(files=[{"path": "a", "size": 1, "sha256": "ab" * 32, "redactions": -1}]),
        _manifest_document(files=[{"path": 1, "size": 1, "sha256": "ab" * 32}]),
    ],
    ids=lambda raw: repr(raw[:24]),
)
def test_a_malformed_manifest_is_unusable(tmp_path: Path, raw: bytes) -> None:
    assert ArtifactReader(tmp_path).manifest(_write_manifest(tmp_path, raw)) is None


def test_a_missing_run_has_no_manifest(tmp_path: Path) -> None:
    assert ArtifactReader(tmp_path).manifest(uuid4()) is None


def test_a_huge_integer_in_the_manifest_does_not_stop_a_read(tmp_path: Path) -> None:
    """read 也經過同一個解析：超長的整數是 ValueError，不是 JSONDecodeError（順手修正）。"""
    document = b'{"files": [{"path": "a", "size": ' + b"1" * 5000 + b"}]}"
    run_id = _write_manifest(tmp_path, document)

    assert ArtifactReader(tmp_path).read(run_id, "a", max_bytes=10) is None
