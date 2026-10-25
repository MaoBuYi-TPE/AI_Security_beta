"""auth profile 的驗證錯誤。"""


class InvalidAuthProfileError(ValueError):
    """不合規則的認證設定。訊息以欄位名稱開頭、只說明原因，不含輸入的值（可能就是 secret），
    可以直接回給 client（422 INVALID_REQUEST）。"""
