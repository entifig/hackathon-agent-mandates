"""The attack lab, replayed offline.

`make attack_scan` fires the whole vector catalogue at a running gateway and scores each
reply. This test does the same against an in-process gateway wired to the real synthetic
upstream, so every control the lab checks is re-proven on each commit without a deployed
stack. It also exercises the remote-target engine end to end: the lab mints against a
pasted ``state/`` bundle — here a copy of ``gateway/state`` — exactly as it would against
a team's shared gateway state on the network.

Run: ``.venv/bin/python -m pytest day_2_attack/tests/test_attack_lab_scan.py``
"""

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from gateway import main
from local_view import attacks
from mcp_server.api.routes_mcp import mcp as pupil_data_upstream

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "gateway" / "state"

# Outcomes that mean a control the gateway owns failed, mirroring the headless _report:
# LANDED (an attack got through), BROKE (a request crashed it), OVER-DENY (a legitimate
# baseline request was refused). Everything else — HELD, DENIED, DATA, OK, RAN — is a pass.
FAILED_OUTCOMES = {"LANDED", "BROKE", "OVER-DENY"}


def _copy_state(dst: Path) -> Path:
    shutil.copytree(STATE, dst)
    return dst


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """An in-process gateway plus a byo self-test target that mints against a state bundle."""
    if not (STATE / "issuer_key.pem").is_file():
        pytest.skip("no gateway/state issuer key — initialise the gateway state first")

    # The gateway verifies against one copy; the lab mints against its own bundle copy. Both
    # share the issuer key, so a freshly minted mandate is accepted and never pre-revoked.
    app_state = _copy_state(tmp_path / "app_state")
    targets = tmp_path / "targets"
    _copy_state(targets / "selftest" / "state")
    (targets / "selftest" / "target.json").write_text(
        json.dumps({"label": "offline self-test", "url": "http://in-process"})
    )

    monkeypatch.setattr(main, "STATE_DIR", app_state)
    monkeypatch.setattr(main, "MCP_SERVERS", {"pupil-data": pupil_data_upstream})
    monkeypatch.setattr(attacks, "TARGETS", targets)

    with TestClient(main.app, raise_server_exceptions=False) as client:

        def http(path: str, body: object = None) -> tuple[int, object]:
            response = client.get(path) if body is None else client.post(path, json=body)
            try:
                return response.status_code, response.json()
            except ValueError:
                return response.status_code, {}

        yield attacks.load_target("selftest"), http


def test_the_full_catalogue_holds_against_the_gateway(lab):
    target, http = lab
    findings = attacks.run_all(target, http)

    # The whole catalogue runs; only the own-only revoke vector is skipped for a byo target.
    assert len(findings) >= 1000, f"expected the full catalogue, ran {len(findings)}"

    errored = [(f["id"], f["error"]) for f in findings if f["error"]]
    assert not errored, f"vectors errored instead of scoring: {errored[:10]}"

    failed = [
        (f["id"], f["outcome"], f["status"], f["got"] or f["reason"])
        for f in findings
        if f["outcome"] in FAILED_OUTCOMES
    ]
    assert not failed, f"the gateway let a control fail on: {failed[:20]}"
