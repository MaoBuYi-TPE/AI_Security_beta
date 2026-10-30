"""預覽開關開啟的引擎（create_app 依設定建立，放在 app.state.preview_engines；§18.9）。"""

from typing import Annotated

from fastapi import Depends, Request

from secscan.scans.domain.catalog import Engine


def preview_engines(request: Request) -> frozenset[Engine]:
    engines: object = getattr(request.app.state, "preview_engines", frozenset())
    if not isinstance(engines, frozenset) or not all(isinstance(e, Engine) for e in engines):
        raise RuntimeError("preview_engines 的格式不對（create_app 應設定 app.state）")
    return frozenset(engine for engine in engines if isinstance(engine, Engine))


PreviewEngines = Annotated[frozenset[Engine], Depends(preview_engines)]
