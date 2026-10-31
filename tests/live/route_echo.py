"""Run only in the locked VAmPI image; expose its actual Flask/Werkzeug routing."""

import importlib.metadata
import json
import time
from typing import Any

from flask import Flask, jsonify, request  # type: ignore[import-not-found]

app = Flask(__name__)


def echo(**_parameters: str) -> Any:
    return jsonify(route=str(request.url_rule), parameters=request.view_args)


def record(response: Any) -> Any:
    print(  # noqa: T201 - fixed synthetic probe evidence in an isolated container
        json.dumps(
            {
                "kind": "request",
                "time": time.time(),
                "method": request.method,
                "target": request.environ.get("RAW_URI"),
                "path": request.path,
                "peer": request.remote_addr,
                "route": str(request.url_rule),
                "parameters": request.view_args,
                "status": response.status_code,
            }
        ),
        flush=True,
    )
    return response


for rule in ("/a/<x>", "/a/<x>/<y>", "/users/v1/<username>", "/ready"):
    app.add_url_rule(rule, endpoint=rule, view_func=echo)
app.after_request(record)

if __name__ == "__main__":
    print(  # noqa: T201
        json.dumps(
            {
                "kind": "versions",
                "Flask": importlib.metadata.version("Flask"),
                "Werkzeug": importlib.metadata.version("Werkzeug"),
            }
        ),
        flush=True,
    )
    app.run(host="0.0.0.0", port=8080, debug=False)  # noqa: S104 - isolated lab only
