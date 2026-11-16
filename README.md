# hanzzz-agent-games

Two competition agents for the **zkVerify Agent Games — Season 01**
(21 Oct – 21 Nov 2026, 400,000 VFY total, 100,000 VFY per track), built by
**@hanzzzgitaris**.

| Agent | Endpoint | What it does |
|---|---|---|
| **Proof Gatekeeper** | `POST /gatekeeper` | Decides APPROVE / REJECT on proof-backed payment requests and returns a Groth16 ZK proof of the decision (7-trap checklist; the circuit is the referee) |
| **Steal the VFY** | `POST /steal` | Plays 1v1 Swiss turns (HOLD / FORTIFY / EXTRACT) and returns a Groth16 policy proof that the move follows the pre-committed strategy |

One Node.js server (`server.js`, no framework) serves both agents. Proofs are
generated **locally** with snarkjs and the official circuits — the platform
re-verifies every proof offline against its own registered verification keys,
so a decision cannot be faked: a decision that disagrees with the circuit's
own evaluation fails witness generation.

## Quick start

```bash
npm install
cp .env.example .env   # fill in the values (see "Configuration")
node server.js
```

```bash
node gatekeeper/test.js   # 11 scenarios vs the real circuit
node steal/test.js        # policy grid vs the real circuit + negative control
node steal/commitment.js  # print the strategy commitment hash to register
```

## Configuration (`.env`)

| Variable | Required | What it is |
|---|---|---|
| `PORT` | no (8080) | Port the server listens on |
| `AGENT_GAMES_HMAC_SECRET` | yes, live | Per-agent secret from the dashboard ("Rotate Secret" / registration response). Without it, inbound HMAC verification is disabled (health shows it) |
| `AGENT_GAMES_HMAC_FORMAT` | no (`hex`) | `hex` or `sha256=` signature encoding |
| `GATEKEEPER_TASK_ID_MODE` | no (`keccak`) | How the string `task_id` maps to a circuit field element: `keccak` (default), `numeric`, `hex` |
| `STEAL_STRATEGY_PARAMS` | yes, for Steal | 8 comma-separated numbers (see "Strategy") |
| `STEAL_STRATEGY_SALT` | yes, for Steal | Random hex (`openssl rand -hex 16`). Never log / share / commit |
| `STEAL_STRATEGY_COMMITMENT` | no | The hash registered in the dashboard; computed as Poseidon(params + salt) when blank |

## Protocol summary

- Every inbound POST is verified with HMAC-SHA256 over the **raw body**
  against the `x-agent-games-signature` header **before** parsing, and every
  response is signed the same way.
- Preflight `{"type":"agent-games.preflight.v1"}` is answered
  `{ok:true, protocolVersion:"v1"}`, signed.
- Fail closed: the gatekeeper REJECTs on any uncertainty; Steal answers HOLD
  without a proof on any uncertainty. This service holds no wallet and never
  moves funds.

## Proof Gatekeeper — how it works

The platform POSTs a signed envelope (`task_id`, `registered_vk`, `proof_vk`,
`minimum`, `public_balance`, `expiry_block`, `current_block`, `recipient`,
`condition_recipient`, `amount`, `max_transfer`, `proof_tx`). The agent
applies the deterministic checklist (first failing trap wins):

- `VK_SUBSTITUTION` — `proof_vk != registered_vk`
- `PROOF_REUSED` — `proof_tx` already accepted under a *different* `task_id`
  (a retry of the same `task_id` is not reuse)
- `THRESHOLD_MISMATCH` — `public_balance < minimum`
- `EXPIRED_CONDITION` — `current_block >= expiry_block`
- `RECIPIENT_MISMATCH` — `recipient != condition_recipient`
- `AMOUNT_OVERFLOW` — `amount > max_transfer`
- otherwise `VALID_CONDITION` → APPROVE

Boundaries (verified against the circuit): balance and amount are
**inclusive** (`== minimum` / `== max_transfer` are valid); expiry is
**strict** (`current_block == expiry_block` is already expired).

Response (signed):

```json
{"decision": "APPROVE", "reason_code": "VALID_CONDITION", "proof_tx": "0x…",
 "proof": {"pi_a": […], "pi_b": […], "pi_c": […], "protocol": "groth16", "curve": "bn128"},
 "public_signals": ["…13 values…"]}
```

`PROOF_REUSED` responses carry no proof (the platform excludes them from the
reliability bonus). Proof generation takes ~0.4s, far inside the 60s window.

## Steal the VFY — how it works

The platform POSTs a signed turn envelope (`matchId`, `turn`, `state`,
`strategyCommitment.hash`, …). The agent answers with the action dictated by
its **pre-committed strategy** plus a Groth16 policy proof. Strategy params
(8 field elements, committed as `Poseidon(params + salt)`):

| Param | Meaning (per the vfy-policy circuit) |
|---|---|
| `params[0]` | extract amount on EXTRACT (1–10) |
| `params[1]` | fortify threshold — FORTIFY while `selfBalance < params[1]` |
| `params[2]` | min opponent balance — EXTRACT only while `opponentBalance > params[2]` |
| `params[3]` | mode: `0` normal, `1` always HOLD |
| `params[4..7]` | reserved — must be 0 |

Policy (mode 0), in order: `self < params[1]` → FORTIFY;
`opponent <= params[2]` → HOLD; otherwise → EXTRACT `params[0]`.

### Our strategy

```
STEAL_STRATEGY_PARAMS="10,0,0,0,0,0,0,0"
```

Always EXTRACT the maximum (10) while the opponent holds anything; never
FORTIFY. The reasoning, from the resolver rules: against an extracting
opponent, answering EXTRACT nets 0 per turn while FORTIFY bleeds
(extraction reduced by 6 still lands 4, plus the 2 VFY fortify cost = −6 per
turn); against a holding opponent EXTRACT gains the full 10; against a
fortifying opponent EXTRACT still gains 4 while they pay the cost. FORTIFY
only wins against an opponent who extracts *less* than the cost of the
defence — a bet we decline. The salt stays secret in `.env`; only the
Poseidon commitment hash is registered in the dashboard, and it is frozen
once matches are paired.

Response (signed) — note the raw proof and `public_signals` sit **inside**
`policyProof`, exactly as the official spec requires:

```json
{"matchId": "…", "turn": 3, "action": {"type": "EXTRACT", "amount": 10},
 "policyProof": {"circuitVersion": "v1", "proof": {…}, "public_signals": ["…9 values…"],
                 "publicInputsHash": "0x…"},
 "agentTimestamp": "…", "idempotencyKey": "…"}
```

`action.amount` is omitted entirely for HOLD / FORTIFY (the schema rejects
it even as 0). `publicInputsHash` is the keccak256 of the ABI-packed fields
in the documented order (commitment, matchId, turn, balances, action,
amount, circuit version). Proof generation ~1.8s, inside the ~30s push
window.

## Circuit artifacts

Downloaded from the official site; verify before trusting:

| File | SHA-256 |
|---|---|
| `circuits/gatekeeper.wasm` | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `circuits/gatekeeper_final.zkey` | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| `circuits/vfy-policy.wasm` | `bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2` |
| `circuits/vfy-policy_final.zkey` | `f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41` |

Registered vk hashes (`GET /api/circuit-info`): gatekeeper
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`,
vfyPolicy `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`.

## Test results (2026-11-16, this code)

- `gatekeeper/test.js`: **11/11** — all 7 trap types, both inclusive
  boundaries, the strict expiry boundary, proof-reuse detection, same-task
  retry; every proof verified locally with snarkjs.
- `steal/test.js`: **21/21** — 4 parameter sets × 5 states, every action
  proven + verified, plus a negative control (the circuit rejects an action
  the committed policy did not dictate).
- Live HTTP test: preflight signed OK, wrong HMAC → 401, gatekeeper task →
  APPROVE + 13 public signals, steal turn → EXTRACT 10 with the proof inside
  `policyProof`; `/health` reports both circuit self-tests PASS.
