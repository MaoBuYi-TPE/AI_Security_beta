"""原始證據、報告內容與人工複測摘錄的加密（docs/DECISIONS.md §30.3、§30.4）。

和 secret_cipher 一樣以 MultiFernet 加密（第一個金鑰加密，每個金鑰都能解密），但內容是 bytes：

- 單一 token（seal／unseal／rotate）：放得進記憶體的內容（報告 ≤ 8 MiB、摘錄）。明文是
  `BLOB_MAGIC + context + "\\n" + 內容`：Fernet 沒有 associated data，以 context 綁定位置
  （例如 `report:<id>`），搬到別處就解不開。
- 分塊串流（seal_stream／unseal_stream／rotate_stream）：runs volume 中的檔案。runner 的記憶體上限是
  256m，檔案可能很大，所以每 1 MiB 一塊，各自是一個 Fernet token（一行一個）：
  - 第一行是格式標記（不加密）；
  - 第一個 token 是標頭：context、原本的相對路徑、加密時間與隨機的 stream id（JSON）；
  - 之後每一塊的明文都以標頭明文的 sha256、塊的序號與「最後一塊」旗標開頭。
  所以竄改、調換順序、截斷、重複、少了最後一塊，或把一塊、整個檔案搬到別的檔案或別的 run，都解不開。
- 金鑰的格式與 secret_cipher 相同（parse_keys）；三組金鑰各自建立自己的 cipher。
- 例外不帶明文、金鑰或密文，也不接上 cryptography 的原始例外。
"""

import hashlib
import json
import os
import re
import secrets
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, Self

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from secscan.security.secret_cipher import (
    CONTEXT_MAX_LENGTH,
    InvalidEncryptionKeysError,
    max_token_bytes,
    parse_keys,
)

BLOB_MAGIC = b"secscan.blob/1\n"
# 加密檔的第一行（不加密）：用來辨認格式，不是驗證。
STREAM_MAGIC = b"secscan.sealed-stream/1\n"
_HEADER_MAGIC = b"secscan.stream-header/1\n"
_CHUNK_MAGIC = b"secscan.stream-chunk/1\n"
STREAM_VERSION = 1
# 和 runner/workspace.py 遮罩時的區塊一樣大：記憶體用量有上限。
CHUNK_BYTES = 1024 * 1024
# 單一 token 的絕對上限（呼叫者另外指定自己的上限，例如報告 8 MiB）。
MAX_BLOB_BYTES = 16 * 1024 * 1024
# 原始路徑（檔案系統的 bytes）最長 4096 bytes（Linux 的 PATH_MAX）。
MAX_PATH_BYTES = 4096
_CONTEXT = re.compile(rf"[!-~]{{1,{CONTEXT_MAX_LENGTH}}}")
_STREAM_ID = re.compile(r"[0-9a-f]{32}")
_DIGEST_BYTES = 32
_INDEX_BYTES = 8
_HEADER_KEYS = frozenset({"context", "path", "sealed_at", "stream", "v"})
# 標頭的 JSON：路徑的每個 byte 跳脫之後最多 6 個字元（\\udcXX），加上 context 與其他欄位。
_MAX_HEADER_LINE = max_token_bytes(
    len(_HEADER_MAGIC) + CONTEXT_MAX_LENGTH + 6 * MAX_PATH_BYTES + 256
)
_CHUNK_PREFIX_BYTES = len(_CHUNK_MAGIC) + _DIGEST_BYTES + _INDEX_BYTES + 1
_MAX_CHUNK_LINE = max_token_bytes(_CHUNK_PREFIX_BYTES + CHUNK_BYTES)


class SealedDataUnreadableError(Exception):
    """密文解不開：金鑰不對、內容被改過或被截斷，或不屬於這個位置。"""


class Source(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...

    def readline(self, size: int = -1, /) -> bytes: ...


class Sink(Protocol):
    def write(self, data: bytes, /) -> object: ...


@dataclass(frozen=True, slots=True)
class StreamHeader:
    """加密檔的標頭（已驗證）：原本的相對路徑與加密的時間（epoch 秒）。"""

    path: str
    sealed_at: int


@dataclass(frozen=True, slots=True)
class StreamInfo:
    """串流的明文：路徑、大小、sha256 與加密的時間。"""

    path: str
    size: int
    sha256: str
    sealed_at: int


class BlobCipher:
    """一組金鑰（例如 EVIDENCE_ENCRYPTION_KEYS）的 cipher；repr 只顯示設定名稱與金鑰的數量。"""

    def __init__(self, keys: Sequence[Fernet], *, setting_name: str) -> None:
        if not keys:
            raise InvalidEncryptionKeysError(f"{setting_name} 至少要有一個金鑰")
        self._fernet = MultiFernet(list(keys))
        self._setting_name = setting_name
        self._key_count = len(keys)

    @classmethod
    def from_setting(cls, setting: str | None, *, setting_name: str, purpose: str) -> Self:
        """由一組金鑰的設定建立；沒有設定或不合規則時拋出 InvalidEncryptionKeysError。"""
        if setting is None:
            raise InvalidEncryptionKeysError(
                f"缺少 {setting_name}：請執行 make env，或依 README 設定（以它加密{purpose}）"
            )
        return cls(parse_keys(setting, setting_name), setting_name=setting_name)

    @property
    def setting_name(self) -> str:
        return self._setting_name

    def __repr__(self) -> str:
        return f"BlobCipher({self._setting_name}, keys={self._key_count})"

    # --- 單一 token ------------------------------------------------------------------------

    def seal(self, data: bytes, *, context: str, max_bytes: int) -> bytes:
        """以第一個金鑰加密；每次都用新的 IV。"""
        _check_context(context)
        _check_limit(max_bytes)
        if len(data) > max_bytes:
            raise ValueError(f"要加密的內容不可超過 {max_bytes:,} bytes")
        return self._fernet.encrypt(BLOB_MAGIC + context.encode("ascii") + b"\n" + data)

    def unseal(self, token: bytes, *, context: str, max_bytes: int) -> bytes:
        """解密並確認 context；不符或解不開時拋出 SealedDataUnreadableError。"""
        _check_context(context)
        _check_limit(max_bytes)
        if len(token) > max_sealed_blob_bytes(context_length=len(context), max_bytes=max_bytes):
            raise _unreadable()
        return _unwrap_blob(self._decrypt(token), context, max_bytes)

    def rotate(self, token: bytes, *, context: str, max_bytes: int) -> bytes:
        """先確認解得開而且 context 相符，再改用第一個金鑰重新加密（保留原本的時間戳記）。"""
        self.unseal(token, context=context, max_bytes=max_bytes)
        return self._rotate_token(token)

    # --- 分塊串流 --------------------------------------------------------------------------

    def seal_stream(
        self, source: Source, sink: Sink, *, context: str, path: str, now: int | None = None
    ) -> StreamInfo:
        """把 source 的內容加密寫進 sink；回傳明文的大小與 sha256。"""
        _check_context(context)
        _check_path(path)
        sealed_at = int(time.time()) if now is None else now
        header = _header_plaintext(context, path, sealed_at)
        binding = hashlib.sha256(header).digest()
        sink.write(STREAM_MAGIC)
        sink.write(self._fernet.encrypt(header) + b"\n")
        digest, size, index = hashlib.sha256(), 0, 0
        block = _read_full(source)
        while True:
            following = _read_full(source) if len(block) == CHUNK_BYTES else b""
            final = not following
            sink.write(self._fernet.encrypt(_chunk(binding, index, final, block)) + b"\n")
            digest.update(block)
            size += len(block)
            if final:
                return StreamInfo(path, size, digest.hexdigest(), sealed_at)
            block, index = following, index + 1

    def read_stream_header(self, source: Source, *, context: str) -> StreamHeader:
        """只驗證標頭（路徑與加密時間）；不讀後面的塊。"""
        _plaintext, header = self._start(source, context, rewrite=None)
        return header

    def unseal_stream(
        self, source: Source, sink: Sink | None, *, context: str, path: str | None = None
    ) -> StreamInfo:
        """驗證並解密整個串流，明文寫進 sink（None 時只驗證）；path 有值時也核對原本的路徑。

        sink 會先收到前面的塊，最後才知道整個串流是否完整：呼叫者在例外時必須丟棄 sink 的內容。
        """
        return self._walk(source, context, path=path, sink=sink, rewrite=None)

    def rotate_stream(self, source: Source, sink: Sink, *, context: str) -> StreamInfo:
        """逐塊改用第一個金鑰重新加密（保留時間戳記），並驗證結構；結果和原本的明文相同。

        和 unseal_stream 一樣，例外時 sink 已經寫了一部分：呼叫者必須丟棄。
        """
        return self._walk(source, context, path=None, sink=None, rewrite=sink)

    # --- 內部 ------------------------------------------------------------------------------

    def _walk(
        self,
        source: Source,
        context: str,
        *,
        path: str | None,
        sink: Sink | None,
        rewrite: Sink | None,
    ) -> StreamInfo:
        plaintext, header = self._start(source, context, rewrite=rewrite)
        if path is not None and header.path != path:
            raise SealedDataUnreadableError("密文不屬於這個檔案（路徑不符）")
        binding = hashlib.sha256(plaintext).digest()
        digest, size, index = hashlib.sha256(), 0, 0
        while True:
            chunk = self._next(source, _MAX_CHUNK_LINE, rewrite, missing="缺少最後一塊")
            final, data = _unwrap_chunk(chunk, binding, index)
            if sink is not None:
                sink.write(data)
            digest.update(data)
            size += len(data)
            if final:
                break
            index += 1
        if source.read(1):
            raise SealedDataUnreadableError("最後一塊之後還有資料")
        return StreamInfo(header.path, size, digest.hexdigest(), header.sealed_at)

    def _start(
        self, source: Source, context: str, *, rewrite: Sink | None
    ) -> tuple[bytes, StreamHeader]:
        _check_context(context)
        if source.read(len(STREAM_MAGIC)) != STREAM_MAGIC:
            raise SealedDataUnreadableError("不是加密檔的格式")
        if rewrite is not None:
            rewrite.write(STREAM_MAGIC)
        plaintext = self._next(source, _MAX_HEADER_LINE, rewrite, missing="缺少標頭")
        return plaintext, _parse_header(plaintext, context)

    def _next(self, source: Source, limit: int, rewrite: Sink | None, *, missing: str) -> bytes:
        """下一個 token 的明文；rewrite 有值時先改用第一個金鑰重新加密並寫出。"""
        token = _read_token(source, limit)
        if token is None:
            raise SealedDataUnreadableError(f"密文被截斷：{missing}")
        if rewrite is not None:
            token = self._rotate_token(token)
            rewrite.write(token + b"\n")
        return self._decrypt(token)

    def _decrypt(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken:
            raise _unreadable() from None

    def _rotate_token(self, token: bytes) -> bytes:
        try:
            return self._fernet.rotate(token)
        except InvalidToken:
            raise _unreadable() from None


def max_sealed_blob_bytes(*, context_length: int, max_bytes: int) -> int:
    """seal 的結果最多多長（DB 的 CHECK 用）。"""
    return max_token_bytes(len(BLOB_MAGIC) + context_length + 1 + max_bytes)


def _unwrap_blob(plaintext: bytes, context: str, max_bytes: int) -> bytes:
    if not plaintext.startswith(BLOB_MAGIC):
        raise SealedDataUnreadableError("密文的內容不是預期的格式")
    found, separator, data = plaintext[len(BLOB_MAGIC) :].partition(b"\n")
    if not separator:
        raise SealedDataUnreadableError("密文的內容不是預期的格式")
    if found != context.encode("ascii"):
        raise SealedDataUnreadableError("密文不屬於這個位置（context 不符）")
    if len(data) > max_bytes:
        raise SealedDataUnreadableError("密文的內容超過上限")
    return data


def _header_plaintext(context: str, path: str, sealed_at: int) -> bytes:
    payload = {
        "context": context,
        "path": path,
        "sealed_at": sealed_at,
        "stream": secrets.token_hex(16),
        "v": STREAM_VERSION,
    }
    text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return _HEADER_MAGIC + text.encode("ascii")


def _parse_header(plaintext: bytes, context: str) -> StreamHeader:
    if not plaintext.startswith(_HEADER_MAGIC):
        raise SealedDataUnreadableError("密文的標頭不是預期的格式")
    try:
        payload = json.loads(plaintext[len(_HEADER_MAGIC) :])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SealedDataUnreadableError("密文的標頭不是預期的格式") from None
    if not isinstance(payload, dict) or payload.keys() != _HEADER_KEYS:
        raise SealedDataUnreadableError("密文的標頭不是預期的格式")
    version, path, sealed_at = payload["v"], payload["path"], payload["sealed_at"]
    # bool 是 int 的子類別：必須比對型別。
    if type(version) is not int or version != STREAM_VERSION:
        raise SealedDataUnreadableError("密文的標頭不是預期的格式")
    if type(sealed_at) is not int or sealed_at < 0 or not isinstance(path, str):
        raise SealedDataUnreadableError("密文的標頭不是預期的格式")
    stream = payload["stream"]
    if not isinstance(stream, str) or _STREAM_ID.fullmatch(stream) is None:
        raise SealedDataUnreadableError("密文的標頭不是預期的格式")
    if payload["context"] != context:
        raise SealedDataUnreadableError("密文不屬於這個位置（context 不符）")
    try:
        _check_path(path)
    except ValueError:
        raise SealedDataUnreadableError("密文的標頭不是預期的格式") from None
    return StreamHeader(path=path, sealed_at=sealed_at)


def _chunk(binding: bytes, index: int, final: bool, data: bytes) -> bytes:
    flag = b"\x01" if final else b"\x00"
    return _CHUNK_MAGIC + binding + index.to_bytes(_INDEX_BYTES, "big") + flag + data


def _unwrap_chunk(plaintext: bytes, binding: bytes, index: int) -> tuple[bool, bytes]:
    if len(plaintext) < _CHUNK_PREFIX_BYTES or not plaintext.startswith(_CHUNK_MAGIC):
        raise SealedDataUnreadableError("密文的塊不是預期的格式")
    offset = len(_CHUNK_MAGIC)
    if plaintext[offset : offset + _DIGEST_BYTES] != binding:
        raise SealedDataUnreadableError("密文的塊不屬於這個檔案")
    offset += _DIGEST_BYTES
    if int.from_bytes(plaintext[offset : offset + _INDEX_BYTES], "big") != index:
        raise SealedDataUnreadableError("密文的塊順序不符")
    offset += _INDEX_BYTES
    flag = plaintext[offset : offset + 1]
    if flag not in (b"\x00", b"\x01"):
        raise SealedDataUnreadableError("密文的塊不是預期的格式")
    data = plaintext[offset + 1 :]
    if len(data) > CHUNK_BYTES:
        raise SealedDataUnreadableError("密文的塊超過上限")
    return flag == b"\x01", data


def _read_full(source: Source) -> bytes:
    """讀滿一塊（pipe 可能一次只回一部分）；只有到結尾時才會少於 CHUNK_BYTES。"""
    parts: list[bytes] = []
    remaining = CHUNK_BYTES
    while remaining:
        part = source.read(remaining)
        if not part:
            break
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)


def _read_token(source: Source, limit: int) -> bytes | None:
    """一行一個 token；到結尾時回傳 None，太長或沒有換行時視為格式錯誤。"""
    line = source.readline(limit + 1)
    if not line:
        return None
    if len(line) > limit or not line.endswith(b"\n"):
        raise SealedDataUnreadableError("密文的格式不符")
    return line[:-1]


def _check_context(context: str) -> None:
    if _CONTEXT.fullmatch(context) is None:
        raise ValueError(f"context 必須是 1 到 {CONTEXT_MAX_LENGTH} 個 ASCII 可見字元")


def _check_limit(max_bytes: int) -> None:
    if not 0 <= max_bytes <= MAX_BLOB_BYTES:
        raise ValueError(f"單一 token 的上限是 {MAX_BLOB_BYTES:,} bytes")


def _check_path(path: str) -> None:
    """相對路徑，沒有空的、. 或 .. 的部分，也沒有 NUL；檔案系統的 bytes 不超過上限。"""
    try:
        raw = os.fsencode(path)
    except UnicodeEncodeError:
        raise ValueError("路徑無法以檔案系統的編碼表示") from None
    parts = path.split("/")
    if not raw or len(raw) > MAX_PATH_BYTES or b"\x00" in raw or path.startswith("/"):
        raise ValueError(f"路徑必須是 1 到 {MAX_PATH_BYTES} bytes 的相對路徑")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("路徑不可有空的、. 或 .. 的部分")


def _unreadable() -> SealedDataUnreadableError:
    return SealedDataUnreadableError("密文解不開：金鑰不對，或內容被改過")
