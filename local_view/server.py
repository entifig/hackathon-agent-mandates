"""Local board for the running hackathon stack.

Serves one page and talks to the gateway. Private keys stay on disk: the page
receives claims, public JWKs, and call decisions. On the host it binds
127.0.0.1. Compose sets BOARD_HOST=0.0.0.0 and points GATEWAY_URL and MCP_URL
at the gateway and backend services.

The hackathon walkthrough in frontend/ is left as it shipped.

    uv run python local_view/server.py
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import attacks  # noqa: E402

from questions import catalog, execute, execute_all, labels_in_force, mandates  # noqa: E402

STATE = ROOT / "gateway" / "state"
PAGE = Path(__file__).with_name("index.html")
ATTACK_PAGE = Path(__file__).with_name("attack.html")
GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8082")
MCP = os.environ.get("MCP_URL", "http://127.0.0.1:8080")
HOST = os.environ.get("BOARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("BOARD_PORT", "8090"))
HTTP_OK = 200
RUN_ONE = re.compile(r"^/api/questions/(\d+)/run$")


def _fetch(req: urllib.request.Request, timeout: float) -> tuple[int, object]:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read()
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"error": raw.decode(errors="replace")}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return 0, {"error": str(exc)}


def _get(url: str, timeout: float = 8) -> tuple[int, object]:
    return _fetch(urllib.request.Request(url), timeout)  # noqa: S310


def _gateway_post(body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(  # noqa: S310
        f"{GATEWAY}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )
    status, payload = _fetch(req, timeout=20)
    return status, payload if isinstance(payload, dict) else {}


def _files() -> list[dict]:
    if not STATE.is_dir():
        return []
    return [
        {"name": str(path.relative_to(STATE)), "private": path.suffix == ".pem", "bytes": path.stat().st_size}
        for path in sorted(STATE.rglob("*"))
        if path.is_file() and path.name != ".gitkeep"
    ]


def health() -> dict:
    mcp_status, _ = _get(f"{MCP}/api/healthcheck", timeout=2)
    gw_status, _ = _get(f"{GATEWAY}/healthcheck", timeout=2)
    return {
        "mcp": {"up": mcp_status == HTTP_OK, "url": MCP},
        "gateway": {"up": gw_status == HTTP_OK, "url": GATEWAY},
        "files": _files(),
    }


GET_ROUTES = {
    "/api/health": health,
    "/api/issuer": lambda: _get(f"{GATEWAY}/demo/issuer")[1],
    "/api/trust": lambda: _get(f"{GATEWAY}/demo/trust")[1],
    "/api/describe": lambda: _get(f"{GATEWAY}/describe", timeout=20)[1],
    "/api/mandates": lambda: {"mandates": mandates()},
    "/api/labels": labels_in_force,
    "/api/questions": lambda: {"questions": catalog()},
    "/api/attack/vectors": lambda: {"vectors": attacks.catalog()},
    "/api/attack/targets": lambda: {"targets": attacks.targets()},
}


def _attack_post(path: str, body: dict) -> object:
    # Saving a vector never touches a gateway, so it needs no target.
    if path == "/api/attack/save-vector":
        return attacks.save_vector(body.get("spec") or {})
    # Own target fires at the board's own gateway; a BYO target carries its own URL (request wins over config).
    target = attacks.load_target(body.get("target", "own"), body.get("url") or None)
    http = attacks.bind_http(target.url or GATEWAY)
    if path == "/api/attack/run":
        vector = next((v for v in attacks.catalog() if v["id"] == body.get("vector_id")), None)
        if vector is None:
            return {"error": f"no such vector: {body.get('vector_id')!r}"}
        return attacks.run_vector(target, vector, http)
    if path == "/api/attack/run-all":
        group = body.get("group")
        findings = attacks.run_group(target, group, http) if group else attacks.run_all(target, http)
        return {"findings": findings}
    if path == "/api/attack/compose":
        return attacks.compose(target, body.get("spec") or {}, http)
    return {"error": "not found"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args

    def _send(self, status: int, payload: object, content_type: str = "application/json") -> None:
        raw = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(raw)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _answer(self, route) -> None:
        try:
            self._send(HTTP_OK, route())
        except Exception as exc:  # noqa: BLE001  the page shows the error instead of waiting on a dropped socket
            self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

    def _body(self) -> dict:
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._send(HTTP_OK, PAGE.read_text(), "text/html; charset=utf-8")
        elif path in ("/attack", "/attack.html"):
            self._send(HTTP_OK, ATTACK_PAGE.read_text(), "text/html; charset=utf-8")
        elif path in GET_ROUTES:
            self._answer(GET_ROUTES[path])
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        one = RUN_ONE.match(path)
        if one:
            self._answer(lambda: execute(int(one.group(1)), _gateway_post))
        elif path == "/api/questions/run":
            self._answer(lambda: {"questions": execute_all(_gateway_post)})
        elif path.startswith("/api/attack/"):
            body = self._body()
            self._answer(lambda: _attack_post(path, body))
        else:
            self._send(404, {"error": "not found"})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write(f"local board  http://{HOST}:{PORT}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
