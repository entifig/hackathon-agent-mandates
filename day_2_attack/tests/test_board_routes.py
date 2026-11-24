"""Exercise board routes with a local HTTP server and stubbed gateway calls."""

import importlib.util
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx


def test_anonymous_board_request_cannot_run_signed_gateway_calls(monkeypatch):
    board_dir = Path(__file__).resolve().parents[2] / "local_view"
    questions_spec = importlib.util.spec_from_file_location("board_questions", board_dir / "questions.py")
    questions = importlib.util.module_from_spec(questions_spec)
    questions_spec.loader.exec_module(questions)
    monkeypatch.setitem(sys.modules, "questions", questions)
    board_spec = importlib.util.spec_from_file_location("board_under_test", board_dir / "server.py")
    board = importlib.util.module_from_spec(board_spec)
    board_spec.loader.exec_module(board)
    calls = []

    def execute(question, post):
        del post
        calls.append(question)
        return {"question": question}

    monkeypatch.setattr(board, "execute", execute)
    with ThreadingHTTPServer(("127.0.0.1", 0), board.Handler) as server:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            response = httpx.post(f"http://127.0.0.1:{server.server_port}/api/questions/8/run", timeout=5)
        finally:
            server.shutdown()
            thread.join()
    assert response.status_code in (401, 403, 404)
    assert calls == []
