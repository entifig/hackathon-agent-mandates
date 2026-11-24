# Day 2 deploy checklist

Commands first, run from the repo root on the server. The gateway deploys just as it does on `main`: one container, one
uvicorn worker, as user `appuser` (uid 1000), with its state on the `./gateway/state` volume.

## 1. A fresh server

```bash
git clone <repo> && cd hackathon-agent-mandates && git checkout <your branch>
cp .env.example .env          # leave GATEWAY_DEMO unset: /demo mints and revokes mandates with the issuer key
uv sync --extra fastapi --extra gateway     # for the cli and the eval only; the containers build their own
```

## 2. Keys, a mandate and the eval pack, then hand the state to the container

```bash
make gateway_init             # issuer keys, trusted list, status list (once; --force would replace them)
make gateway_issue            # the default SCH01 mandate for gateway/state/agent.pem
make eval_build               # eval_pack/, minted from this issuer
sudo chown -R 1000:$(id -g) gateway/state && sudo chmod -R g+rwX gateway/state
```

The container writes `nonces.jsonl` and `budget_ledger.json` there as uid 1000. The group bits let you keep running
`cli issue` and `cli revoke` from the host. Run `id -u`: if it prints 1000, the `chown` changes nothing.

## 3. Start it

```bash
docker compose up -d --wait backend gateway     # the frontend is not needed
curl -s localhost:8082/healthcheck              # {"status":"ok"}
```

`--wait` fails loudly if the state dir is not writable: the healthcheck answers `503` with the reason, and every call
would be refused with `NONCE_UNAVAILABLE`. To fix it, rerun the `chown` and then `docker compose restart gateway`.

Open only port 8082 to the outside. Port 8080 is the MCP server with no access control (it is the known bypass), and
8081 is the demo UI.

## 4. Check it from outside

```bash
make eval_run GATEWAY_URL=https://<your gateway>   # questions 0 to 5 must all PASS
```

Pass the URL as a make argument. `.env` sets `GATEWAY_URL=http://localhost:8082`, and an environment variable in
front of `make` would lose to that.

## 5. Mandates for the attackers

```bash
# one <team>.jwk per attacking team, as each team posted it
cp <team>.jwk day_2_attack/keys/
make attack_mandates \
  FEATURE_SCOPE=day_2_attack/feature_q11/feature_scope.json \
  FEATURE_CLAIMS=day_2_attack/feature_q11/feature_claims.json
```

This writes `day_2_attack/mandates/<team>.jwt` (the default) and `<team>.feature.jwt` (the run budget), each valid for
24 hours, and prints each status idx. Every feature mandate gets its own budget of 40 pupils and 100 calls.

## 6. What to post

- The gateway URL.
- `day_2_attack/mandates/`, the mandates folder.
- [`feature_q11/NOTE.md`](feature_q11/NOTE.md), which says what the feature mandate enforces.
- If anyone asks for public keys, `gateway/state/trusted_list.json` and `gateway/state/gateway.pub`.

**Never post or commit `gateway/state/*.pem`**: they hold the issuer key, the gateway key and the agent key. Also keep
`nonces.jsonl` and `budget_ledger.json` to yourself.

## 7. Keep it to one process

- Run one container with one uvicorn worker. Do not add `--workers`, replicas or autoscaling. The nonce store and the
  budget ledger live in that one process and its files, so a second process would have its own copy: a replayed
  request would be accepted there, and a budget could be spent twice.
- Keep `gateway/state` on a persistent disk. If it is wiped, every budget resets and the replay protection is lost
  for the 5-minute timestamp window.

## 8. Revoke one team

```bash
uv run python -m gateway.cli decode day_2_attack/mandates/<team>.jwt         | grep '"idx"'
uv run python -m gateway.cli decode day_2_attack/mandates/<team>.feature.jwt | grep '"idx"'
uv run python -m gateway.cli revoke --idx <N>      # once for each idx
```

The gateway re-reads the status list on every call, so the next call answers `REVOKED`. No restart is needed. Other
teams' mandates are not affected.
