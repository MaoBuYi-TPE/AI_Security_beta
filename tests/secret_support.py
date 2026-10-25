"""測試用的加密金鑰：每個測試程序在 import 時產生一把，不寫死在檔案裡。

API 的 fixture（create_app）與整合測試的 Seeder 用同一把，測試才解得開 API 寫入的密文。
（函式名稱不以 test_ 開頭：被 import 進測試模組時，pytest 會把它們當成測試。）
"""

from uuid import UUID

from cryptography.fernet import Fernet
from pydantic import SecretStr

from secscan.auth_profiles.domain.credentials import AuthType, Credential
from secscan.auth_profiles.domain.model import secret_context
from secscan.security.secret_cipher import SecretCipher

TEST_SECRET_ENCRYPTION_KEYS = Fernet.generate_key().decode()


def encryption_keys() -> SecretStr:
    return SecretStr(TEST_SECRET_ENCRYPTION_KEYS)


def shared_cipher() -> SecretCipher:
    return SecretCipher.from_setting(TEST_SECRET_ENCRYPTION_KEYS)


def bearer_context(profile_id: UUID) -> str:
    """bearer 類型的 profile 的密文 context（綁定 profile 與送出方式）。"""
    return secret_context(profile_id, Credential(AuthType.BEARER))
