"""BlobCipher：單一 token 與分塊串流的加密、驗證與換版（SEAL-01、SEAL-02；DECISIONS §30.4）。

分塊的測試把 CHUNK_BYTES 改小（幾個 bytes），以少量資料涵蓋多塊、整除與空檔案的情況。
"""

import hashlib
import io
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from hypothesis import given
from hypothesis import strategies as st

from secscan.security import blob_cipher
from secscan.security.blob_cipher import (
    MAX_BLOB_BYTES,
    STREAM_MAGIC,
    BlobCipher,
    SealedDataUnreadableError,
    StreamInfo,
    max_sealed_blob_bytes,
)
from secscan.security.secret_cipher import InvalidEncryptionKeysError

SETTING = "EVIDENCE_ENCRYPTION_KEYS"
CONTEXT = "evidence:6f1c2d3e-4b5a-4c6d-8e7f-001122334455"
OTHER_CONTEXT = "evidence:00000000-0000-4000-8000-000000000000"
PATH = "out/zap-report.json"
CANARY = b"canary-plaintext-7c1e0b"
NOW = 1_800_000_000


def _key() -> str:
    return Fernet.generate_key().decode()


def _cipher(*keys: str) -> BlobCipher:
    setting = ",".join(keys or (_key(),))
    return BlobCipher.from_setting(setting, setting_name=SETTING, purpose="測試")


@contextmanager
def _chunks(size: int) -> Iterator[None]:
    with patch.object(blob_cipher, "CHUNK_BYTES", size):
        yield


def _seal(cipher: BlobCipher, data: bytes, *, context: str = CONTEXT, path: str = PATH) -> bytes:
    sink = io.BytesIO()
    cipher.seal_stream(io.BytesIO(data), sink, context=context, path=path, now=NOW)
    return sink.getvalue()


def _unseal(cipher: BlobCipher, sealed: bytes, **kwargs: str) -> tuple[bytes, StreamInfo]:
    sink = io.BytesIO()
    info = cipher.unseal_stream(io.BytesIO(sealed), sink, context=kwargs.get("context", CONTEXT))
    return sink.getvalue(), info


def _lines(sealed: bytes) -> list[bytes]:
    """格式標記之後的每一行（第一個是標頭，之後是各塊）。"""
    assert sealed.startswith(STREAM_MAGIC)
    return sealed[len(STREAM_MAGIC) :].splitlines(keepends=True)


def _join(lines: list[bytes]) -> bytes:
    return STREAM_MAGIC + b"".join(lines)


# --- 單一 token --------------------------------------------------------------------------------


def test_a_blob_round_trips_and_differs_every_time() -> None:
    cipher = _cipher()

    first = cipher.seal(CANARY, context="report:1", max_bytes=1024)
    second = cipher.seal(CANARY, context="report:1", max_bytes=1024)

    assert first != second
    assert first.startswith(b"gAAAAA")
    assert CANARY not in first
    assert cipher.unseal(first, context="report:1", max_bytes=1024) == CANARY


@pytest.mark.parametrize("data", [b"", b"\n", b"report:1\nnested", bytes(range(256))])
def test_binary_and_empty_blobs_round_trip(data: bytes) -> None:
    cipher = _cipher()

    token = cipher.seal(data, context="report:1", max_bytes=1024)

    assert cipher.unseal(token, context="report:1", max_bytes=1024) == data


def test_a_blob_moved_to_another_place_is_unreadable() -> None:
    cipher = _cipher()
    token = cipher.seal(CANARY, context="report:1", max_bytes=1024)

    with pytest.raises(SealedDataUnreadableError, match="context"):
        cipher.unseal(token, context="report:2", max_bytes=1024)


def test_a_tampered_or_foreign_blob_is_unreadable_without_echoing_it() -> None:
    cipher = _cipher()
    token = cipher.seal(CANARY, context="report:1", max_bytes=1024)
    tampered = token[:-6] + (b"A" if token[-6:-5] != b"A" else b"B") + token[-5:]

    for candidate, reader in ((tampered, cipher), (token, _cipher())):
        with pytest.raises(SealedDataUnreadableError) as raised:
            reader.unseal(candidate, context="report:1", max_bytes=1024)
        message = str(raised.value)
        assert CANARY.decode() not in message
        assert candidate.decode() not in message
        assert raised.value.__cause__ is None


def test_blob_limits_are_enforced_on_both_sides() -> None:
    cipher = _cipher()

    with pytest.raises(ValueError, match="不可超過"):
        cipher.seal(b"x" * 11, context="report:1", max_bytes=10)
    with pytest.raises(ValueError, match="上限"):
        cipher.seal(b"", context="report:1", max_bytes=MAX_BLOB_BYTES + 1)
    big = cipher.seal(b"x" * 100, context="report:1", max_bytes=100)
    with pytest.raises(SealedDataUnreadableError):
        cipher.unseal(big, context="report:1", max_bytes=10)
    assert len(big) <= max_sealed_blob_bytes(context_length=len("report:1"), max_bytes=100)


@pytest.mark.parametrize("context", ["", "has space", "x" * 257, "中文"])
def test_contexts_are_short_visible_ascii(context: str) -> None:
    with pytest.raises(ValueError, match="context"):
        _cipher().seal(b"", context=context, max_bytes=1)


def test_rotation_moves_blobs_to_the_first_key() -> None:
    old, new = _key(), _key()
    token = _cipher(old).seal(CANARY, context="report:1", max_bytes=1024)

    rotated = _cipher(new, old).rotate(token, context="report:1", max_bytes=1024)

    assert _cipher(new).unseal(rotated, context="report:1", max_bytes=1024) == CANARY
    with pytest.raises(SealedDataUnreadableError):
        _cipher(new).unseal(token, context="report:1", max_bytes=1024)


def test_rotation_refuses_what_it_cannot_verify() -> None:
    old, new = _key(), _key()
    token = _cipher(old).seal(CANARY, context="report:1", max_bytes=1024)

    with pytest.raises(SealedDataUnreadableError, match="context"):
        _cipher(new, old).rotate(token, context="report:2", max_bytes=1024)
    with pytest.raises(SealedDataUnreadableError) as raised:
        _cipher(new).rotate(token, context="report:1", max_bytes=1024)
    assert CANARY.decode() not in str(raised.value)


# --- 分塊串流 ----------------------------------------------------------------------------------


@given(data=st.binary(max_size=80), chunk=st.integers(min_value=1, max_value=9))
def test_streams_round_trip_for_any_chunking(data: bytes, chunk: int) -> None:
    cipher = _cipher()
    with _chunks(chunk):
        sealed = _seal(cipher, data)
        plain, info = _unseal(cipher, sealed)

    assert plain == data
    assert (info.path, info.size, info.sealed_at) == (PATH, len(data), NOW)
    assert len(_lines(sealed)) == 1 + max(1, -(-len(data) // chunk))


@pytest.mark.parametrize("size", [0, 4, 8, 9])
def test_empty_exact_and_partial_last_chunks(size: int) -> None:
    """長度剛好是塊的整數倍時，最後一個完整的塊就是最後一塊；空檔案也有一個最後一塊。"""
    cipher = _cipher()
    data = bytes(range(size))
    with _chunks(4):
        sealed = _seal(cipher, data)
        plain, info = _unseal(cipher, sealed)

    assert plain == data
    assert info.size == size
    assert len(_lines(sealed)) == 1 + max(1, -(-size // 4))


def test_the_canary_never_appears_in_the_sealed_bytes() -> None:
    cipher = _cipher()
    with _chunks(4):
        sealed = _seal(cipher, CANARY * 3, path="out/canary-name.txt")

    assert CANARY not in sealed
    assert b"canary-name" not in sealed


def test_partial_reads_from_a_pipe_still_fill_whole_chunks() -> None:
    class Trickle(io.BytesIO):
        def read(self, size: int | None = -1, /) -> bytes:
            return super().read(1 if size is None or size < 0 else min(size, 1))

    cipher = _cipher()
    with _chunks(4):
        sink = io.BytesIO()
        cipher.seal_stream(Trickle(b"abcdefghij"), sink, context=CONTEXT, path=PATH, now=NOW)
        assert len(_lines(sink.getvalue())) == 1 + 3
        assert _unseal(cipher, sink.getvalue())[0] == b"abcdefghij"


def _tamper_cases(cipher: BlobCipher) -> dict[str, bytes]:
    with _chunks(4):
        header, *chunks = _lines(_seal(cipher, b"0123456789AB"))
        other_header, *other_chunks = _lines(_seal(cipher, b"0123456789AB", path="out/b"))
    flipped = chunks[1][:20] + (b"A" if chunks[1][20:21] != b"A" else b"B") + chunks[1][21:]
    return {
        "flipped byte": _join([header, chunks[0], flipped, chunks[2]]),
        "swapped": _join([header, chunks[1], chunks[0], chunks[2]]),
        "duplicated": _join([header, chunks[0], chunks[0], chunks[1], chunks[2]]),
        "missing middle": _join([header, chunks[0], chunks[2]]),
        "missing final": _join([header, chunks[0], chunks[1]]),
        "header only": _join([header]),
        "trailing data": _join([header, *chunks, chunks[2]]),
        "trailing bytes": _join([header, *chunks]) + b"x",
        "chunk from another file": _join([header, other_chunks[0], chunks[1], chunks[2]]),
        "header from another file": _join([other_header, *chunks]),
        "no newline": _join([header, *chunks])[:-1],
        "wrong magic": b"x" + _join([header, *chunks])[1:],
        "overlong line": _join([header, b"g" * (blob_cipher._MAX_CHUNK_LINE + 5) + b"\n"]),
        "empty": b"",
    }


@pytest.mark.parametrize(
    "case",
    [
        "flipped byte",
        "swapped",
        "duplicated",
        "missing middle",
        "missing final",
        "header only",
        "trailing data",
        "trailing bytes",
        "chunk from another file",
        "header from another file",
        "no newline",
        "wrong magic",
        "overlong line",
        "empty",
    ],
)
def test_tampered_streams_are_unreadable(case: str) -> None:
    cipher = _cipher()
    sealed = _tamper_cases(cipher)[case]

    with _chunks(4), pytest.raises(SealedDataUnreadableError):
        cipher.unseal_stream(io.BytesIO(sealed), None, context=CONTEXT, path=PATH)


def test_a_stream_moved_to_another_run_or_file_is_unreadable() -> None:
    cipher = _cipher()
    sealed = _seal(cipher, CANARY)

    with pytest.raises(SealedDataUnreadableError, match="context"):
        cipher.unseal_stream(io.BytesIO(sealed), None, context=OTHER_CONTEXT)
    with pytest.raises(SealedDataUnreadableError, match="路徑"):
        cipher.unseal_stream(io.BytesIO(sealed), None, context=CONTEXT, path="out/other.json")
    with pytest.raises(SealedDataUnreadableError):
        _cipher().unseal_stream(io.BytesIO(sealed), None, context=CONTEXT)


def test_the_header_alone_gives_the_verified_path_and_time() -> None:
    cipher = _cipher()
    sealed = _seal(cipher, CANARY, path="out/長檔名.txt")

    header = cipher.read_stream_header(io.BytesIO(sealed), context=CONTEXT)

    assert (header.path, header.sealed_at) == ("out/長檔名.txt", NOW)
    with pytest.raises(SealedDataUnreadableError):
        _cipher().read_stream_header(io.BytesIO(sealed), context=CONTEXT)


def test_undecodable_file_names_survive_the_header() -> None:
    """檔案系統的名稱不一定是 UTF-8：以 surrogateescape 保存，還原成同樣的 bytes。"""
    cipher = _cipher()
    path = "out/" + b"\xff\xfename".decode("utf-8", "surrogateescape")

    _plain, info = _unseal(cipher, _seal(cipher, b"x", path=path))

    assert info.path == path


@pytest.mark.parametrize(
    "path", ["", "/etc/passwd", "out/../x", "out//x", "./x", "a/\x00b", "x" * 4097]
)
def test_paths_must_be_clean_relative_paths(path: str) -> None:
    with pytest.raises(ValueError, match="路徑"):
        _cipher().seal_stream(io.BytesIO(b""), io.BytesIO(), context=CONTEXT, path=path)


def test_stream_rotation_keeps_the_content_and_moves_to_the_first_key() -> None:
    old, new = _key(), _key()
    with _chunks(4):
        sealed = _seal(_cipher(old), b"0123456789")
        sink = io.BytesIO()
        info = _cipher(new, old).rotate_stream(io.BytesIO(sealed), sink, context=CONTEXT)
        plain, after = _unseal(_cipher(new), sink.getvalue())
        with pytest.raises(SealedDataUnreadableError):
            _unseal(_cipher(new), sealed)

    assert plain == b"0123456789"
    assert info == after
    assert after.sealed_at == NOW


@pytest.mark.parametrize("case", ["missing final", "swapped", "chunk from another file"])
def test_stream_rotation_refuses_broken_streams(case: str) -> None:
    old = _key()
    sealed = _tamper_cases(_cipher(old))[case]

    with _chunks(4), pytest.raises(SealedDataUnreadableError):
        _cipher(_key(), old).rotate_stream(io.BytesIO(sealed), io.BytesIO(), context=CONTEXT)


def test_stream_rotation_reports_keys_that_are_gone() -> None:
    sealed = _seal(_cipher(), CANARY)

    with pytest.raises(SealedDataUnreadableError) as raised:
        _cipher().rotate_stream(io.BytesIO(sealed), io.BytesIO(), context=CONTEXT)
    assert CANARY.decode() not in str(raised.value)


# --- 金鑰的設定 --------------------------------------------------------------------------------


def test_a_missing_setting_names_the_ring_and_its_purpose() -> None:
    with pytest.raises(InvalidEncryptionKeysError, match=f"缺少 {SETTING}.*原始證據"):
        BlobCipher.from_setting(None, setting_name=SETTING, purpose="原始證據")


def test_malformed_settings_name_the_ring_without_echoing_keys() -> None:
    key = _key()
    for setting in (f"{key},not-a-key", f"{key},{key}", ",".join(_key() for _ in range(5))):
        with pytest.raises(InvalidEncryptionKeysError, match="CONTENT_ENCRYPTION_KEYS") as raised:
            BlobCipher.from_setting(setting, setting_name="CONTENT_ENCRYPTION_KEYS", purpose="x")
        assert key not in str(raised.value)


def test_repr_shows_only_the_ring_and_the_key_count() -> None:
    key = _key()
    cipher = _cipher(key, _key())

    assert repr(cipher) == f"BlobCipher({SETTING}, keys=2)"
    assert key not in repr(cipher)
    assert cipher.setting_name == SETTING


def test_an_empty_key_list_is_refused() -> None:
    with pytest.raises(InvalidEncryptionKeysError, match=SETTING):
        BlobCipher([], setting_name=SETTING)


# --- 持有金鑰者偽造的格式（驗證不只靠 Fernet 的 HMAC）----------------------------------------


def _forged(cipher: BlobCipher, plaintext: bytes) -> bytes:
    return cipher._fernet.encrypt(plaintext)


@pytest.mark.parametrize(
    "plaintext",
    [b"not-the-magic", blob_cipher.BLOB_MAGIC + b"no-separator", blob_cipher.BLOB_MAGIC],
)
def test_forged_blob_plaintexts_are_refused(plaintext: bytes) -> None:
    cipher = _cipher()

    with pytest.raises(SealedDataUnreadableError, match="格式"):
        cipher.unseal(_forged(cipher, plaintext), context="report:1", max_bytes=1024)


def test_a_forged_oversized_blob_is_refused() -> None:
    cipher = _cipher()
    token = _forged(cipher, blob_cipher.BLOB_MAGIC + b"report:1\n" + b"x" * 11)

    with pytest.raises(SealedDataUnreadableError, match="上限"):
        cipher.unseal(token, context="report:1", max_bytes=10)


def _header(**fields: object) -> bytes:
    payload: dict[str, object] = {
        "context": CONTEXT,
        "path": PATH,
        "sealed_at": NOW,
        "stream": "0" * 32,
        "v": 1,
    }
    payload.update(fields)
    return blob_cipher._HEADER_MAGIC + json.dumps(payload).encode()


@pytest.mark.parametrize(
    "plaintext",
    [
        b"not-a-header",
        blob_cipher._HEADER_MAGIC + b"{not json",
        blob_cipher._HEADER_MAGIC + b"[]",
        blob_cipher._HEADER_MAGIC + b'{"v": 1}',
        _header(v=True),
        _header(v=2),
        _header(sealed_at=-1),
        _header(sealed_at=1.5),
        _header(path=7),
        _header(stream="XYZ"),
        _header(stream=None),
        _header(path="../escape"),
    ],
)
def test_forged_headers_are_refused(plaintext: bytes) -> None:
    cipher = _cipher()
    sealed = STREAM_MAGIC + _forged(cipher, plaintext) + b"\n"

    with pytest.raises(SealedDataUnreadableError, match="標頭"):
        cipher.read_stream_header(io.BytesIO(sealed), context=CONTEXT)


def _with_chunk(cipher: BlobCipher, build: Callable[[bytes], bytes]) -> bytes:
    header = _header()
    binding = hashlib.sha256(header).digest()
    return STREAM_MAGIC + _forged(cipher, header) + b"\n" + _forged(cipher, build(binding)) + b"\n"


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (lambda binding: b"short", "格式"),
        (lambda binding: b"x" * 80, "格式"),
        (lambda binding: blob_cipher._chunk(binding, 0, True, b"")[:-1] + b"\x02", "格式"),
        (lambda binding: blob_cipher._chunk(binding, 0, True, b"x" * 5), "上限"),
    ],
)
def test_forged_chunks_are_refused(build: Callable[[bytes], bytes], message: str) -> None:
    cipher = _cipher()
    sealed = _with_chunk(cipher, build)

    with _chunks(4), pytest.raises(SealedDataUnreadableError, match=message):
        cipher.unseal_stream(io.BytesIO(sealed), None, context=CONTEXT)


def test_paths_the_file_system_cannot_encode_are_refused() -> None:
    with pytest.raises(ValueError, match="編碼"):
        _cipher().seal_stream(io.BytesIO(b""), io.BytesIO(), context=CONTEXT, path="out/\ud800")
