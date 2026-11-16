// hanzzzgitaris — Agent Games Season 01 server.
// One process serving both automated tracks of the zkVerify Agent Games:
//   POST /gatekeeper  Proof Gatekeeper tasks (60s deadline)
//   POST /steal       Steal the VFY turns (~30s push window)
//   GET  /health      readiness: secret set? strategy set? circuit self-tests?
//   GET  /            info
//
// Protocol (https://agentgames.zkverify.io/build):
//  - every inbound POST is HMAC-SHA256 verified over the RAW body against
//    the `x-agent-games-signature` header BEFORE parsing (when a secret is
//    configured), and every response is signed the same way;
//  - preflight {"type":"agent-games.preflight.v1"} is answered
//    {ok:true, protocolVersion:"v1"}, signed;
//  - fail closed: the gatekeeper REJECTs on uncertainty, Steal answers HOLD
//    without a proof on uncertainty. This service holds no wallet and never
//    moves funds — it only answers game envelopes with ZK proofs.
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

// tiny .env loader (no dependency)
(function loadEnv() {
  try {
    for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* env vars only */ }
})();

const { verifySignature, signatureFor } = require('./lib/hmac');
const { verifyLocally } = require('./lib/snark');
const { keccak256Hex } = require('./lib/field');
const { decide } = require('./gatekeeper/decide');
const { proveTask } = require('./gatekeeper/prove');
const { policy, validateParams } = require('./steal/policy');
const { proveTurn, strategyCommitment } = require('./steal/prove');
const { toHexString } = require('./lib/field');

const envVal = (k) => process.env[k] || '';
const HMAC_SECRET = envVal('AGENT_GAMES_HMAC_SECRET');
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex';
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';

// ---- Steal strategy (env only; params + salt are never logged) ----
let stealParams = null;
let stealSalt = '';
let stealCommitment = '';
let stealReady = false;
let stealStatus = 'not-configured';
(function initSteal() {
  const raw = (process.env.STEAL_STRATEGY_PARAMS || '').trim();
  stealSalt = (process.env.STEAL_STRATEGY_SALT || '').trim();
  if (!raw || !stealSalt) {
    stealStatus = 'not-configured (STEAL_STRATEGY_PARAMS / STEAL_STRATEGY_SALT missing)';
    return;
  }
  const params = raw.split(',').map((s) => s.trim());
  const err = validateParams(params);
  if (err) {
    stealStatus = 'invalid: ' + err;
    return;
  }
  stealParams = params;
  stealSalt = toHexString(stealSalt);
  try {
    stealCommitment =
      toHexString((process.env.STEAL_STRATEGY_COMMITMENT || '').trim()) ||
      strategyCommitment(params, stealSalt);
  } catch (e) {
    stealStatus = 'invalid: commitment failed — ' + e.message;
    return;
  }
  stealReady = true;
  stealStatus = 'ready';
})();

let gatekeeperSelfTest = 'pending';
let stealSelfTest = 'pending';

// ---- Gatekeeper ----
async function handleGatekeeper(obj) {
  const task = { ...(obj.input || {}), task_id: obj.task_id };
  const required = ['registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block',
    'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer'];
  for (const f of required) {
    if (task[f] === undefined || task[f] === null || task[f] === '') {
      return { status: 200, body: { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: String(task.proof_tx || '') } };
    }
  }
  const { decision, reason_code } = decide(task);
  const proofTx = String(task.proof_tx || '');
  if (reason_code === 'PROOF_REUSED') {
    // No proof exists for a reused proof; the platform excludes these from
    // the reliability bonus instead of penalising the missing proof.
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx } };
  }
  try {
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx, proof, public_signals: publicSignals } };
  } catch (e) {
    console.error('[gatekeeper] proof generation failed (decision returned without proof):', e.message);
    return { status: 200, body: { decision, reason_code, proof_tx: proofTx } };
  }
}

// ---- Steal the VFY ----
async function handleSteal(obj) {
  const matchId = obj.matchId || '';
  const turn = obj.turn;
  const state = obj.state || {};
  const envelopeCommitment = obj.strategyCommitment && obj.strategyCommitment.hash;
  const idempotencyKey = keccak256Hex([Buffer.from(`${matchId}:${turn}:${obj.nonce || ''}`, 'utf8')]).slice(2);

  const hold = () => ({
    status: 200,
    body: {
      matchId, turn, action: { type: 'HOLD' },
      policyProof: { circuitVersion: 'v1' },
      agentTimestamp: new Date().toISOString(), idempotencyKey,
    },
  });

  if (!matchId || turn === undefined || turn === null ||
      state.selfBalance === undefined || state.opponentBalance === undefined) {
    return { status: 400, body: { error: 'malformed turn envelope' } };
  }
  if (!stealReady) {
    console.warn('[steal] strategy not configured — HOLD without proof');
    return hold();
  }
  if (envelopeCommitment && String(envelopeCommitment).toLowerCase() !== stealCommitment.toLowerCase()) {
    console.error('[steal] envelope commitment != registered commitment — HOLD without proof');
    return hold();
  }
  const action = policy({ selfBalance: state.selfBalance, opponentBalance: state.opponentBalance }, stealParams);
  try {
    const { proof, publicSignals, publicInputsHash } = await proveTurn(
      { matchId, turn, state }, action, stealCommitment, stealSalt, stealParams
    );
    const actionOut = { type: action.type };
    if (action.type === 'EXTRACT') actionOut.amount = action.amount;
    return {
      status: 200,
      body: {
        matchId, turn, action: actionOut,
        // Per the official /build spec the raw proof and public_signals sit
        // INSIDE policyProof — anywhere else scores the turn -2 as HOLD.
        policyProof: { circuitVersion: 'v1', proof, public_signals: publicSignals, publicInputsHash },
        agentTimestamp: new Date().toISOString(), idempotencyKey,
      },
    };
  } catch (e) {
    console.error('[steal] proof generation failed (HOLD):', e.message);
    return hold();
  }
}

// ---- startup self-tests: prove both circuits work before serving ----
async function selfTests() {
  try {
    const vk = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
    const task = {
      task_id: 'gk_selftest_1', registered_vk: vk, proof_vk: vk,
      minimum: '1000', public_balance: '1460', expiry_block: '8430000', current_block: '8420000',
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500', max_transfer: '1000', proof_tx: '0xselftest',
    };
    const { decision } = decide(task);
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    const ok = await verifyLocally('gatekeeper', publicSignals, proof);
    gatekeeperSelfTest = ok && decision === 'APPROVE' ? 'PASS' : 'FAIL';
  } catch (e) {
    gatekeeperSelfTest = 'FAIL: ' + e.message;
  }
  try {
    if (!stealReady) {
      stealSelfTest = 'SKIPPED (strategy not configured)';
      return;
    }
    const turn = { matchId: '00000000-0000-0000-0000-000000000001', turn: 1, state: { selfBalance: '100', opponentBalance: '100' } };
    const action = policy(turn.state, stealParams);
    const { proof, publicSignals } = await proveTurn(turn, action, stealCommitment, stealSalt, stealParams);
    const ok = await verifyLocally('vfyPolicy', publicSignals, proof);
    stealSelfTest = ok ? 'PASS' : 'FAIL';
  } catch (e) {
    stealSelfTest = 'FAIL: ' + e.message;
  }
}

// ---- HTTP plumbing ----
function sendJson(res, status, obj, sign = true) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body, HMAC_FORMAT);
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleRequest(req, res) {
  const url = new URL(req.url, 'http://localhost');
  if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/')) {
    return sendJson(res, 200, {
      ok: true,
      service: 'hanzzz-agent-games',
      tracks: ['proof-gatekeeper', 'steal-the-vfy'],
      hmacConfigured: Boolean(HMAC_SECRET),
      gatekeeperSelfTest,
      steal: { ready: stealReady, status: stealStatus, selfTest: stealSelfTest },
    }, false);
  }
  if (req.method !== 'POST') return sendJson(res, 404, { error: 'not found' }, false);

  const raw = await readBody(req);
  if (HMAC_SECRET && !verifySignature(HMAC_SECRET, raw, req.headers['x-agent-games-signature'], HMAC_FORMAT)) {
    return sendJson(res, 401, { error: 'invalid signature' });
  }
  let obj;
  try {
    obj = JSON.parse(raw.toString('utf8'));
  } catch {
    return sendJson(res, 400, { error: 'invalid json' });
  }
  if (obj && obj.type === 'agent-games.preflight.v1') {
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }
  try {
    if (url.pathname === '/gatekeeper' || (url.pathname === '/agent' && obj.type === 'agent-games.proof-gatekeeper.v1')) {
      const { status, body } = await handleGatekeeper(obj);
      return sendJson(res, status, body);
    }
    if (url.pathname === '/steal' || (url.pathname === '/agent' && obj.eventId === 'steal-the-vfy')) {
      const { status, body } = await handleSteal(obj);
      return sendJson(res, status, body);
    }
    return sendJson(res, 404, { error: 'unknown path' });
  } catch (e) {
    console.error('[server] handler error:', e.message);
    return sendJson(res, 500, { error: 'internal' });
  }
}

if (require.main === module) {
  const PORT = Number(process.env.PORT || 8080);
  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch((e) => {
      console.error('[server] fatal:', e.message);
      try { sendJson(res, 500, { error: 'internal' }, false); } catch { /* socket gone */ }
    });
  });
  server.listen(PORT, '0.0.0.0', () => console.log(`[server] listening on :${PORT}`));
  selfTests().then(() => console.log(`[selftest] gatekeeper=${gatekeeperSelfTest} steal=${stealSelfTest}`));
}

module.exports = { handleGatekeeper, handleSteal, selfTests };
