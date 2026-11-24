"""Private keys created by the CLI must be readable only by their owner."""

import os
import stat

from gateway import cli


def test_cli_creates_owner_only_private_keys(tmp_path):
    state = tmp_path / "state"
    generated_agent = tmp_path / "keygen_agent.pem"

    # Exercise the common shell umask, under which a plain write creates 0644 files.
    previous_umask = os.umask(0o022)
    try:
        cli.main(["--state", str(state), "init"])
        cli.main(["--state", str(state), "keygen", "-o", str(generated_agent)])
        cli.main(
            [
                "--state",
                str(state),
                "issue",
                "--agent-key",
                str(state / "agent.pem"),
                "--clearance",
                "4",
                "-o",
                str(state / "mandate.jwt"),
            ]
        )
    finally:
        os.umask(previous_umask)

    insecure_keys = []
    for key in (state / "issuer_key.pem", state / "gateway_key.pem", generated_agent, state / "agent.pem"):
        mode = stat.S_IMODE(key.stat().st_mode)
        if mode != 0o600:
            insecure_keys.append(f"{key.name}: {mode:04o}")
    assert not insecure_keys, f"private keys must have mode 0600; found {', '.join(insecure_keys)}"
