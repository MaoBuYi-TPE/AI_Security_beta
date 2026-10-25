"""目前的 SecretCipher：create_app 依 SECRET_ENCRYPTION_KEYS 建立，放在 app.state.secret_cipher。"""

from typing import Annotated

from fastapi import Depends, Request

from secscan.security.secret_cipher import SecretCipher


def secret_cipher(request: Request) -> SecretCipher:
    cipher = getattr(request.app.state, "secret_cipher", None)
    if not isinstance(cipher, SecretCipher):
        # 沒有金鑰就不能加密：直接失敗，不以明文或其他方式保存 secret。
        raise RuntimeError("加密元件尚未初始化（create_app 應設定 app.state.secret_cipher）")
    return cipher


CurrentCipher = Annotated[SecretCipher, Depends(secret_cipher)]
