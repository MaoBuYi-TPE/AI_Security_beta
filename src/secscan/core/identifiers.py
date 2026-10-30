"""標準格式的 UUID：檔名、container label 這類外部的文字，只接受 str(UUID) 的寫法。

大寫、去掉連字號、大括號、urn 前綴都不算（同一個 run 只有一種寫法，比對時不會有兩個名字）。
"""

from uuid import UUID


def canonical_uuid(text: str) -> UUID | None:
    try:
        value = UUID(text)
    except ValueError:
        return None
    return value if str(value) == text else None
