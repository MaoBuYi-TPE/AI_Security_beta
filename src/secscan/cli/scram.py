"""PostgreSQL 的 SCRAM-SHA-256 verifier：核對與產生（migrate-db-roles；docs/DECISIONS.md §31.5）。

產生：CREATE ROLE 以 verifier 代替明文密碼（PostgreSQL 直接保存符合格式的 verifier），明文密碼就
不會送到伺服器、不會進入任何伺服器日誌。


owner 角色已存在、資料庫還由應用程式角色擁有時，owner 連不進任何資料庫（initdb 撤銷了 PUBLIC 的
CONNECT），在改變任何東西之前無法以登入確認 .env 的密碼。所以由 superuser 讀出 pg_authid 的
verifier（雜湊，不是密碼；不輸出），在本機以 RFC 5802／7677 的方式核對。

只接受可列印的 ASCII 密碼（make env 產生的是 hex）：其他字元 PostgreSQL 會先做 SASLprep，這裡
不實作，直接視為不相符（fail closed）。
"""

import base64
import binascii
import hashlib
import hmac
import re
import secrets

_VERIFIER = re.compile(
    r"SCRAM-SHA-256\$(?P<iterations>[1-9][0-9]{0,6}):(?P<salt>[A-Za-z0-9+/=]+)"
    r"\$(?P<stored>[A-Za-z0-9+/=]+):(?P<server>[A-Za-z0-9+/=]+)"
)
_PRINTABLE_ASCII = re.compile(r"[\x20-\x7e]+")
# PostgreSQL 的預設（scram_iterations）與 salt 長度。
ITERATIONS = 4096
SALT_BYTES = 16


class UnsupportedPasswordError(ValueError):
    """不是可列印的 ASCII（PostgreSQL 會先做 SASLprep，這裡不實作）。"""


def scram_verifier(password: str) -> str:
    if _PRINTABLE_ASCII.fullmatch(password) is None:
        raise UnsupportedPasswordError(
            "DB_OWNER_PASSWORD 只接受可列印的 ASCII（make env 產生的是 hex）"
        )
    salt = secrets.token_bytes(SALT_BYTES)
    stored, server = _keys(password, salt, ITERATIONS)
    encode = base64.b64encode
    return (
        f"SCRAM-SHA-256${ITERATIONS}:{encode(salt).decode()}"
        f"${encode(stored).decode()}:{encode(server).decode()}"
    )


def scram_matches(verifier: str | None, password: str) -> bool:
    if verifier is None or _PRINTABLE_ASCII.fullmatch(password) is None:
        return False
    match = _VERIFIER.fullmatch(verifier)
    if match is None:
        return False
    try:
        salt, stored, server = (
            base64.b64decode(match[name], validate=True) for name in ("salt", "stored", "server")
        )
    except binascii.Error:
        return False
    stored_key, server_key = _keys(password, salt, int(match["iterations"]))
    stored_matches = hmac.compare_digest(stored_key, stored)
    return stored_matches and hmac.compare_digest(server_key, server)


def _keys(password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """RFC 5802／7677：StoredKey = H(HMAC(SaltedPassword, "Client Key"))、ServerKey。"""
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    return hashlib.sha256(client_key).digest(), server_key
