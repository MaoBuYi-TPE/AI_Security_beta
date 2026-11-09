"""benchmarks/results 的加密（BSEAL-01、BSEAL-02、BSEAL-03；docs/DECISIONS.md §30.7）。

- 金鑰檔：位置、類型、擁有者與權限的檢查；O_EXCL 建立、不覆寫；金鑰一律不輸出。
- 寫入：結果目錄中只有加密檔與 SHA256SUMS，位元組中沒有明文的 canary；manifest 記下雙重 sha256。
- 讀取：金鑰不對、遺失、截斷、竄改、改名或搬到別的結果目錄都清楚報錯；拒絕明文的結果目錄。
- bench-seal：只寫 partial 目錄，驗證之後才 rename；原目錄不動；失敗時刪掉 partial，中斷時留著。
單元測試只用 pytest 暫存目錄中的金鑰檔，不讀預設的位置。
"""

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from benchmarks import legacy
from benchmarks.legacy import seal_legacy
from benchmarks.results import (
    CHECKSUMS,
    ResultsError,
    SecretLeakError,
    read_bytes,
    read_json,
    reserve,
    verify,
    write_bytes,
    write_checksums,
    write_json,
)
from benchmarks.sealing import (
    DEFAULT_KEY_FILE,
    KEY_FILE_VARIABLE,
    BenchKeys,
    SealingError,
    create_key_file,
    key_file_path,
)

CANARY = "canary-bench-result-8d3a"


def _key() -> str:
    return Fernet.generate_key().decode()


@pytest.fixture
def keys() -> BenchKeys:
    return BenchKeys([_key()])


def _all_bytes(directory: Path) -> bytes:
    return b"\n".join(
        path.name.encode() + b"\n" + path.read_bytes() for path in sorted(directory.iterdir())
    )


# --- 金鑰檔（BSEAL-01）---------------------------------------------------------------------------


def test_the_key_file_comes_from_the_environment_or_the_default(tmp_path: Path) -> None:
    assert key_file_path({}) == DEFAULT_KEY_FILE.expanduser()
    assert key_file_path({KEY_FILE_VARIABLE: str(tmp_path / "k")}) == tmp_path / "k"
    assert key_file_path({KEY_FILE_VARIABLE: ""}) == DEFAULT_KEY_FILE.expanduser()


def test_a_new_key_file_is_private_and_never_overwritten(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config" / "bench-keys"

    create_key_file(path, forbidden=())

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    before = path.read_bytes()
    with pytest.raises(SealingError, match="不覆寫"):
        create_key_file(path, forbidden=())
    assert path.read_bytes() == before
    assert before.strip().decode() not in capsys.readouterr().out
    assert repr(BenchKeys.load(path, forbidden=())) == "BenchKeys(keys=1)"


FIVE_KEYS = "\n".join(_key() for _ in range(5))


@pytest.mark.parametrize(
    ("content", "mode", "message"),
    [
        (None, 0o600, "找不到"),
        (_key(), 0o644, "0600"),
        ("not-a-key\n", 0o600, "第 1 把"),
        ("", 0o600, "1 到 4"),
        (FIVE_KEYS, 0o600, "1 到 4"),
    ],
)
def test_bad_key_files_are_refused_without_echoing_them(
    tmp_path: Path, content: str | None, mode: int, message: str
) -> None:
    path = tmp_path / "bench-keys"
    if content is not None:
        path.write_text(content)
        path.chmod(mode)

    with pytest.raises(SealingError, match=message) as raised:
        BenchKeys.load(path, forbidden=())

    for line in (content or "").splitlines():
        if len(line) > 8:
            assert line not in str(raised.value)


def test_a_directory_is_not_a_key_file(tmp_path: Path) -> None:
    (tmp_path / "bench-keys").mkdir()

    with pytest.raises(SealingError, match="一般檔案"):
        BenchKeys.load(tmp_path / "bench-keys", forbidden=())


def test_duplicated_and_symlinked_key_files_are_refused(tmp_path: Path) -> None:
    key = _key()
    duplicated = tmp_path / "duplicated"
    duplicated.write_text(f"{key}\n{key}\n")
    duplicated.chmod(0o600)
    with pytest.raises(SealingError, match="重複"):
        BenchKeys.load(duplicated, forbidden=())
    link = tmp_path / "link"
    link.symlink_to(duplicated)
    with pytest.raises(SealingError, match="symlink"):
        BenchKeys.load(link, forbidden=())


def test_key_files_inside_the_repository_are_refused(tmp_path: Path) -> None:
    path = tmp_path / "bench-keys"
    path.write_text(_key())
    path.chmod(0o600)

    with pytest.raises(SealingError, match="repo"):
        BenchKeys.load(path, forbidden=(tmp_path,))
    with pytest.raises(SealingError, match="repo"):
        create_key_file(tmp_path / "other", forbidden=(tmp_path,))


# --- 寫入（BSEAL-01）----------------------------------------------------------------------------


def test_results_are_sealed_with_double_digests_and_no_plaintext(
    tmp_path: Path, keys: BenchKeys
) -> None:
    directory = reserve(tmp_path, "run")

    digests = write_json(directory, "scan-001.json", {"note": CANARY}, keys=keys)
    spec = write_bytes(directory, "spec.yaml", f"name: {CANARY}\n".encode(), keys=keys)
    write_checksums(directory)

    assert {path.name for path in directory.iterdir()} == {
        "scan-001.json.sealed",
        "spec.yaml.sealed",
        CHECKSUMS,
    }
    assert CANARY.encode() not in _all_bytes(directory)
    sealed = (directory / "scan-001.json.sealed").read_bytes()
    assert digests.sealed_sha256 == hashlib.sha256(sealed).hexdigest()
    assert read_json(directory, "scan-001.json", keys=keys) == {"note": CANARY}
    plain = read_bytes(directory, "spec.yaml", keys=keys)
    assert spec.sha256 == hashlib.sha256(plain).hexdigest()
    assert stat.S_IMODE((directory / "spec.yaml.sealed").stat().st_mode) == 0o600
    assert verify(directory) == {
        "scan-001.json.sealed": digests.sealed_sha256,
        "spec.yaml.sealed": spec.sealed_sha256,
    }


def test_secrets_and_keys_are_refused_before_anything_is_written(
    tmp_path: Path, keys: BenchKeys
) -> None:
    directory = reserve(tmp_path, "run")
    own = _key()
    mine = BenchKeys([own])

    for document, kind in (
        ({"leak": own}, "fernet_key"),
        ({"leak": f"x{own}x"}, "bench_key"),
    ):
        with pytest.raises(SecretLeakError, match=kind) as raised:
            write_json(directory, "x.json", document, keys=mine)
        assert own not in str(raised.value)
    assert list(directory.iterdir()) == []


def test_written_files_are_never_overwritten(tmp_path: Path, keys: BenchKeys) -> None:
    directory = reserve(tmp_path, "run")
    write_json(directory, "a.json", {}, keys=keys)

    with pytest.raises(ResultsError, match="不覆寫"):
        write_json(directory, "a.json", {"b": 1}, keys=keys)


# --- 讀取（BSEAL-02）----------------------------------------------------------------------------


def test_reading_needs_the_right_key_and_the_right_place(tmp_path: Path, keys: BenchKeys) -> None:
    directory = reserve(tmp_path, "run")
    write_json(directory, "a.json", {"x": 1}, keys=keys)
    write_json(directory, "b.json", {"y": 2}, keys=keys)

    with pytest.raises(SealingError, match="解不開"):
        read_json(directory, "a.json", keys=BenchKeys([_key()]))
    (directory / "b.json.sealed").chmod(0o600)
    (directory / "b.json.sealed").write_bytes((directory / "a.json.sealed").read_bytes())
    with pytest.raises(SealingError, match="位置"):
        read_json(directory, "b.json", keys=keys)
    moved = tmp_path / "moved"
    directory.rename(moved)
    with pytest.raises(SealingError, match="位置"):
        read_json(moved, "a.json", keys=keys)


@pytest.mark.parametrize("damage", ["truncate", "flip"])
def test_damaged_files_fail_the_checksums_and_decryption(
    tmp_path: Path, keys: BenchKeys, damage: str
) -> None:
    directory = reserve(tmp_path, "run")
    write_json(directory, "a.json", {"x": CANARY}, keys=keys)
    write_checksums(directory)
    path = directory / "a.json.sealed"
    token = path.read_bytes()
    path.chmod(0o600)
    path.write_bytes(token[:-10] if damage == "truncate" else token[:-5] + b"AAAAA")

    with pytest.raises(ResultsError, match="不符"):
        verify(directory)
    with pytest.raises(SealingError):
        read_json(directory, "a.json", keys=keys)


def test_a_plaintext_results_directory_is_refused(tmp_path: Path) -> None:
    directory = reserve(tmp_path, "old")
    (directory / "manifest.json").write_text("{}")
    (directory / CHECKSUMS).write_text("")

    with pytest.raises(ResultsError, match="明文"):
        verify(directory)


# --- bench-seal（BSEAL-03）--------------------------------------------------------------------


def _legacy_directory(root: Path, name: str = "old") -> Path:
    """T23a 之前的明文結果目錄：manifest 版本 1、明文的 SHA256SUMS。"""
    directory = root / name
    directory.mkdir(parents=True)
    files = {
        "spec.yaml": f"name: {CANARY}\n".encode(),
        "scan-001.json": json.dumps({"note": CANARY}).encode(),
    }
    manifest = {
        "manifest_version": 1,
        "files": {n: hashlib.sha256(c).hexdigest() for n, c in files.items()},
        "disclosures": ["results_not_encrypted"],
    }
    files["manifest.json"] = json.dumps(manifest).encode()
    for file_name, content in files.items():
        (directory / file_name).write_bytes(content)
    lines = "".join(f"{hashlib.sha256(c).hexdigest()}  {n}\n" for n, c in sorted(files.items()))
    (directory / CHECKSUMS).write_text(lines)
    return directory


def _snapshot(directory: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in directory.iterdir()}


def test_legacy_results_are_sealed_into_a_new_directory(tmp_path: Path, keys: BenchKeys) -> None:
    source = _legacy_directory(tmp_path / "plain")
    before = _snapshot(source)
    root = tmp_path / "results"

    sealed = seal_legacy(source, root, "old-sealed", keys)

    assert sealed == root / "old-sealed"
    assert _snapshot(source) == before
    assert sorted(path.name for path in root.iterdir()) == ["old-sealed"]
    assert CANARY.encode() not in _all_bytes(sealed)
    verify(sealed)
    manifest = read_json(sealed, "manifest.json", keys=keys)
    assert manifest["manifest_version"] == 2
    assert "results_encrypted_with_local_bench_key" in manifest["disclosures"]
    assert (
        manifest["sealed_from"]["manifest_sha256"]
        == hashlib.sha256(before["manifest.json"]).hexdigest()
    )
    assert read_json(sealed, "scan-001.json", keys=keys) == {"note": CANARY}
    assert set(manifest["files"]) == {"spec.yaml", "scan-001.json"}


def test_sealing_refuses_damaged_or_unfinished_sources(tmp_path: Path, keys: BenchKeys) -> None:
    source = _legacy_directory(tmp_path / "plain")
    (source / "scan-001.json").write_text("{}")

    with pytest.raises(ResultsError, match="不符"):
        seal_legacy(source, tmp_path / "results", "x", keys)
    (source / CHECKSUMS).unlink()
    with pytest.raises(ResultsError, match="SHA256SUMS"):
        seal_legacy(source, tmp_path / "results", "x", keys)
    assert not (tmp_path / "results").exists() or not list((tmp_path / "results").iterdir())


def test_sealing_never_reuses_a_name(tmp_path: Path, keys: BenchKeys) -> None:
    source = _legacy_directory(tmp_path / "plain")
    root = tmp_path / "results"
    (root / "taken").mkdir(parents=True)

    with pytest.raises(ResultsError, match="已經存在"):
        seal_legacy(source, root, "taken", keys)


def test_a_failed_verification_removes_only_the_partial_directory(
    tmp_path: Path, keys: BenchKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _legacy_directory(tmp_path / "plain")
    before = _snapshot(source)
    root = tmp_path / "results"

    def broken(*_args: object, **_kwargs: object) -> None:
        raise ResultsError("轉換之後的內容和原目錄不符")

    monkeypatch.setattr(legacy, "_check", broken)

    with pytest.raises(ResultsError, match="不符"):
        seal_legacy(source, root, "new", keys)

    assert list(root.iterdir()) == []
    assert _snapshot(source) == before


def test_an_interrupted_seal_leaves_a_marked_partial_directory(
    tmp_path: Path, keys: BenchKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _legacy_directory(tmp_path / "plain")
    root = tmp_path / "results"

    def interrupted(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(legacy, "_check", interrupted)

    with pytest.raises(KeyboardInterrupt):
        seal_legacy(source, root, "new", keys)

    [left] = list(root.iterdir())
    assert left.name.startswith("new.partial-")
    assert not (root / "new").exists()
    assert sorted(os.listdir(source)) == sorted(_snapshot(source))
