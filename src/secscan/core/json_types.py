"""JSON 值的型別。只用標準函式庫，domain 模組可以安全 import。"""

type JsonValue = str | int | float | bool | list[JsonValue] | dict[str, JsonValue] | None
type JsonObject = dict[str, JsonValue]
