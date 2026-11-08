"""嚴格的 YAML 讀取：safe_load 之外，拒絕重複的鍵、非字串的鍵、別名與過大的檔案。

PyYAML 的 safe_load 遇到重複的鍵會靜默以後者覆蓋：實驗規格、ground truth 與標記檔中重複的鍵
可能讓評估改用另一個值而沒有人發現，所以一律拒絕（fail closed）。
"""

from typing import Any

import yaml
from yaml.nodes import MappingNode, Node

MAX_YAML_BYTES = 256 * 1024


class StrictYamlError(ValueError):
    """YAML 不符合嚴格的規則；訊息說明規則，不回顯內容。"""


class _StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        if self.check_event(yaml.events.AliasEvent):
            raise StrictYamlError("不接受 YAML 的別名（*alias）")
        return super().compose_node(parent, index)


def _mapping(loader: _StrictLoader, node: MappingNode) -> dict[Any, Any]:
    seen: set[str] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str):
            raise StrictYamlError("mapping 的鍵必須是字串")
        if key in seen:
            raise StrictYamlError("mapping 有重複的鍵")
        seen.add(key)
    return loader.construct_mapping(node, deep=True)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def load_strict_yaml(content: bytes) -> object:
    """UTF-8 的 YAML 位元組 → Python 物件（只有一份文件）。"""
    if len(content) > MAX_YAML_BYTES:
        raise StrictYamlError(f"YAML 超過 {MAX_YAML_BYTES} 位元組")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise StrictYamlError("YAML 必須是 UTF-8") from None
    try:
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - _StrictLoader 是 SafeLoader
    except yaml.YAMLError as error:
        raise StrictYamlError("YAML 的語法不正確") from error
