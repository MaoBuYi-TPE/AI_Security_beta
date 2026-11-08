"""結果目錄（BENCH-03）：獨占建立、權限、秘密檢查、SHA256SUMS。"""

import hashlib
import stat
from pathlib import Path

import pytest

from benchmarks.results import (
    CHECKSUMS,
    ResultsError,
    SecretLeakError,
    canonical_json,
    find_secrets,
    read_json,
    reserve,
    seal,
    verify,
    write_bytes,
    write_json,
)

# 以程式組出平台 key 的格式：pre-commit 會擋下任何檔案中完整格式的 key。
PLATFORM_KEY = "secscan_" + "0" * 16 + "_" + "f" * 64
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJhbGljZSJ9" + ".c2lnbmF0dXJlLXZhbHVl"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_a_results_directory_is_created_once_with_private_permissions(tmp_path: Path) -> None:
    directory = reserve(tmp_path / "results", "t31-smoke")

    assert directory.is_dir()
    assert _mode(directory) == 0o700
    with pytest.raises(ResultsError, match="已經存在"):
        reserve(tmp_path / "results", "t31-smoke")


@pytest.mark.parametrize("name", ["../x", ".hidden", "a/b", ""])
def test_a_results_directory_name_is_plain(tmp_path: Path, name: str) -> None:
    with pytest.raises(ResultsError, match="名稱"):
        reserve(tmp_path, name)


def test_files_are_written_exclusively_with_private_permissions(tmp_path: Path) -> None:
    directory = reserve(tmp_path, "run")

    digest = write_json(directory, "scan.json", {"b": 1, "a": "名稱"})

    path = directory / "scan.json"
    assert _mode(path) == 0o600
    assert path.read_bytes() == canonical_json({"a": "名稱", "b": 1})
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    assert read_json(directory, "scan.json") == {"a": "名稱", "b": 1}
    with pytest.raises(ResultsError, match="不覆寫"):
        write_json(directory, "scan.json", {})


def test_canonical_json_is_stable_and_refuses_nan() -> None:
    assert canonical_json({"b": [1, 2], "a": None}) == canonical_json({"a": None, "b": [1, 2]})
    with pytest.raises(ValueError, match="JSON"):
        canonical_json({"x": float("nan")})


@pytest.mark.parametrize("name", ["../x.json", ".x", "a/b.json", CHECKSUMS, "x" * 129])
def test_file_names_are_plain_and_cannot_replace_the_checksums(tmp_path: Path, name: str) -> None:
    with pytest.raises(ResultsError, match="檔名"):
        write_bytes(tmp_path, name, b"{}")


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        (f"key={PLATFORM_KEY}", "platform_api_key"),
        ("Authorization: Bearer abcdefghijklmnop0123", "bearer_token"),
        (f"token {JWT}", "jwt"),
    ],
)
def test_secret_patterns_are_found(text: str, kind: str) -> None:
    assert find_secrets(text) == [kind]


def test_known_session_secrets_are_found_without_echoing_them(tmp_path: Path) -> None:
    secret = "operator-key-value-123"

    with pytest.raises(SecretLeakError) as caught:
        write_json(tmp_path, "x.json", {"note": f"prefix {secret}"}, known=[secret])

    assert secret not in str(caught.value)
    assert "session_secret" in str(caught.value)
    assert not (tmp_path / "x.json").exists()


def test_short_known_values_are_not_matched() -> None:
    assert find_secrets("status ok", known=["ok"]) == []


def test_ordinary_results_have_no_secrets() -> None:
    assert find_secrets('{"status": "timed_out", "plan_hash": "' + "a" * 64 + '"}') == []


def test_seal_and_verify_detect_changes(tmp_path: Path) -> None:
    directory = reserve(tmp_path, "run")
    write_json(directory, "a.json", {"x": 1})
    write_json(directory, "b.json", {"y": 2})

    digests = seal(directory)

    assert sorted(digests) == ["a.json", "b.json"]
    assert verify(directory) == digests
    assert _mode(directory / CHECKSUMS) == 0o600
    (directory / "a.json").chmod(0o600)
    (directory / "a.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ResultsError, match="不符"):
        verify(directory)


def test_verify_detects_extra_and_missing_files(tmp_path: Path) -> None:
    directory = reserve(tmp_path, "run")
    write_json(directory, "a.json", {"x": 1})
    seal(directory)
    write_json(directory, "extra.json", {})

    with pytest.raises(ResultsError, match="不符"):
        verify(directory)


def test_verify_needs_the_checksums(tmp_path: Path) -> None:
    with pytest.raises(ResultsError, match="SHA256SUMS"):
        verify(reserve(tmp_path, "run"))


def test_only_regular_files_are_allowed(tmp_path: Path) -> None:
    directory = reserve(tmp_path, "run")
    (directory / "nested").mkdir()

    with pytest.raises(ResultsError, match="一般檔案"):
        seal(directory)


def test_read_json_refuses_paths(tmp_path: Path) -> None:
    with pytest.raises(ResultsError, match="檔名"):
        read_json(tmp_path, "../etc/passwd")
