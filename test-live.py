import hmac, hashlib, json, urllib.request, urllib.error

KEY = b"test" + b"secret" + b"123"

def sign(b):
    return hmac.new(KEY, b, hashlib.sha256).hexdigest()

def post(path, obj, bad=False):
    body = json.dumps(obj).encode()
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-agent-games-signature", "deadbeef" if bad else sign(body))
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read()
            sig = r.headers.get("x-agent-games-signature")
            print(path, r.status, "resp-sig-ok:", sig == sign(data))
            return json.loads(data)
    except urllib.error.HTTPError as e:
        print(path, "HTTP", e.code, e.read()[:100])
        return None

r = post("/gatekeeper", {"type": "agent-games.preflight.v1", "agent_id": "agt_x", "issued_at": "2026-11-16T00:00:00Z", "nonce": "abc123"})
print("preflight:", r)
post("/gatekeeper", {"type": "agent-games.preflight.v1"}, bad=True)

VK = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"
task = {"type": "agent-games.proof-gatekeeper.v1", "task_id": "gk_live_1", "mode": "practice", "issued_at": "x", "deadline_at": "y",
        "input": {"registered_vk": VK, "proof_vk": VK, "minimum": "1000", "public_balance": "1460", "expiry_block": 8430000, "current_block": 8420000,
                  "recipient": "0x1111111111111111111111111111111111111111", "condition_recipient": "0x1111111111111111111111111111111111111111",
                  "amount": "500", "max_transfer": "1000", "proof_tx": "0xlive1"}}
r = post("/gatekeeper", task)
print("gatekeeper:", r["decision"], r["reason_code"], "signals:", len(r.get("public_signals", [])), "proof:", bool(r.get("proof")))

turn = {"protocolVersion": "v1", "eventId": "steal-the-vfy", "mode": "practice", "matchId": "123e4567-e89b-12d3-a456-426614174000", "turn": 3,
        "issuedAt": "x", "deadlineAt": "y", "state": {"selfBalance": "95", "opponentBalance": "105", "selfFortifiedUntilTurn": None, "opponentFortifiedUntilTurn": None},
        "strategyCommitment": {"hash": "0x2884a6033256d29d043fd06c9c20487254995d318388288a8d6246aeb0f8d4f2"}, "resolverVersion": "v1", "nonce": "3c2f1a"}
r = post("/steal", turn)
print("steal:", r["action"], "policyProof keys:", list(r["policyProof"].keys()), "signals:", len(r["policyProof"].get("public_signals", [])))
print("health:", urllib.request.urlopen("http://127.0.0.1:8080/health").read().decode()[:260])
