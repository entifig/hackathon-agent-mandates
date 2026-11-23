"""Local board for the running hackathon stack.

Binds 127.0.0.1 only. Serves one page and talks to the gateway. Private keys
stay on disk: the page receives claims, public JWKs, and call decisions.

The hackathon walkthrough in frontend/ is left as it shipped. This board is
separate because that UI needs Node.

    uv run python local_view/server.py
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gateway.cli import sign_request  # noqa: E402
from gateway.eval import run_cases  # noqa: E402
from gateway.lib.common import b64u_decode, priv_from_pem  # noqa: E402

STATE = ROOT / "gateway" / "state"
PAGE = Path(__file__).with_name("index.html")
PACK = ROOT / "eval_pack"
GATEWAY = "http://127.0.0.1:8082"
MCP = "http://127.0.0.1:8080"
HOST = "127.0.0.1"
PORT = 8090
HTTP_OK = 200


def _get(url: str, timeout: float = 8) -> tuple[int, object]:
    req = urllib.request.Request(url)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = resp.read()
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw.decode(errors="replace")}
        return exc.code, parsed
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return 0, {"error": str(exc)}


def _post(url: str, payload: dict) -> tuple[int, object]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(  # noqa: S310
        url, data=data, headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"error": raw.decode(errors="replace")}
        return exc.code, parsed
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return 0, {"error": str(exc)}


def _jwt_parts(token: str) -> dict:
    header_b, payload_b, _sig = token.split(".")
    return {
        "header": json.loads(b64u_decode(header_b)),
        "claims": json.loads(b64u_decode(payload_b)),
    }


def _files() -> list[dict]:
    if not STATE.is_dir():
        return []
    rows = []
    for path in sorted(STATE.iterdir()):
        if not path.is_file():
            continue
        private = path.suffix == ".pem"
        rows.append({"name": path.name, "private": private, "bytes": path.stat().st_size})
    return rows


def health() -> dict:
    mcp_status, mcp_body = _get(f"{MCP}/api/healthcheck", timeout=2)
    gw_status, gw_body = _get(f"{GATEWAY}/healthcheck", timeout=2)
    return {
        "mcp": {"up": mcp_status == HTTP_OK, "status": mcp_status, "body": mcp_body, "url": MCP},
        "gateway": {"up": gw_status == HTTP_OK, "status": gw_status, "body": gw_body, "url": GATEWAY},
        "files": _files(),
    }


def mandate() -> dict:
    path = STATE / "mandate.jwt"
    if not path.is_file():
        return {"error": "no mandate.jwt"}
    return _jwt_parts(path.read_text().strip())


def call(body: dict) -> dict:
    tool = body.get("tool")
    arguments = body.get("arguments") or {}
    if not isinstance(tool, str) or not isinstance(arguments, dict):
        return {"error": "need tool and arguments"}
    key_path = STATE / "agent.pem"
    mandate_path = STATE / "mandate.jwt"
    if not key_path.is_file() or not mandate_path.is_file():
        return {"error": "team key or mandate is missing"}
    signed = sign_request(
        priv_from_pem(key_path.read_bytes()),
        server="pupil-data",
        tool=tool,
        arguments=arguments,
        mandate=mandate_path.read_text().strip(),
    )
    status, payload = _post(f"{GATEWAY}/tools/call", signed)
    result = payload.get("result") if isinstance(payload, dict) else None
    preview = result
    count = None
    if isinstance(result, list):
        count = len(result)
        preview = result[:5]
    shown = payload if isinstance(payload, dict) else {"raw": payload}
    shown = {**shown, "result": preview}
    return {"status": status, "body": shown, "result_count": count}


def eval_run() -> dict:
    if not PACK.is_dir():
        return {"error": "eval_pack is missing"}

    def post(body: dict):
        status, payload = _post(f"{GATEWAY}/tools/call", body)
        return status, payload if isinstance(payload, dict) else {}

    results = run_cases(PACK, post)
    lines = [{"ok": ok, "line": line} for ok, line in results]
    questions = []
    for question in range(6):
        oks = [ok for ok, line in results if line.startswith(f"Q{question} ")]
        if oks:
            questions.append({"question": question, "passed": sum(oks), "total": len(oks)})
    return {"passed": sum(ok for ok, _ in results), "total": len(results), "questions": questions, "lines": lines}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args

    def _send(self, status: int, payload: object, content_type: str) -> None:
        if isinstance(payload, (dict, list)):
            raw = json.dumps(payload).encode()
            content_type = "application/json"
        elif isinstance(payload, str):
            raw = payload.encode()
        else:
            raw = payload  # type: ignore[assignment]
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(raw)))
        self.send_header("cache-control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._send(HTTP_OK, PAGE.read_text(), "text/html; charset=utf-8")
            return
        routes = {
            "/api/health": health,
            "/api/issuer": lambda: _get(f"{GATEWAY}/demo/issuer")[1],
            "/api/trust": lambda: _get(f"{GATEWAY}/demo/trust")[1],
            "/api/describe": lambda: _get(f"{GATEWAY}/describe", timeout=20)[1],
            "/api/mandate": mandate,
        }
        if self.path not in routes:
            self._send(404, {"error": "not found"}, "application/json")
            return
        self._send(HTTP_OK, routes[self.path](), "application/json")

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, {"error": "bad json"}, "application/json")
            return
        if self.path == "/api/call":
            self._send(HTTP_OK, call(body), "application/json")
            return
        if self.path == "/api/eval":
            self._send(HTTP_OK, eval_run(), "application/json")
            return
        self._send(404, {"error": "not found"}, "application/json")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write(f"local view  http://{HOST}:{PORT}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
