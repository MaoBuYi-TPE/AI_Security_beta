"""finding 連結的具名錯誤；不包含觀察或分類表的原始內容。"""


class MappingChangedError(ValueError):
    """run 已凍結不同的 mapping，不能以目前版本補寫尚未連結的觀察。"""
