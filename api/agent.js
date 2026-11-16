// Vercel serverless adapter — unified agent endpoint.
// The dashboard registers ONE endpoint URL per agent; the platform posts
// both Gatekeeper tasks and Steal turns to it, distinguished by the
// envelope itself (type "agent-games.proof-gatekeeper.v1" vs
// eventId "steal-the-vfy"). Preflight is answered here too.
const { verifySignature, signatureFor } = require('../lib/hmac');
const { handleGatekeeper, handleSteal } = require('../server');

const envVal = (k) => process.env[k] || '';

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') { res.status(405).json({ error: 'method not allowed' }); return; }
  const secret = envVal('AGENT_GAMES_HMAC_SECRET');
  const format = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex';
  const raw = await readRaw(req);
  const send = (status, obj) => {
    const body = JSON.stringify(obj);
    if (secret) res.setHeader('x-agent-games-signature', signatureFor(secret, body, format));
    res.status(status).setHeader('Content-Type', 'application/json').send(body);
  };
  if (secret && !verifySignature(secret, raw, req.headers['x-agent-games-signature'], format)) {
    send(401, { error: 'invalid signature' });
    return;
  }
  let obj;
  try { obj = JSON.parse(raw.toString('utf8')); } catch { send(400, { error: 'invalid json' }); return; }
  if (obj && obj.type === 'agent-games.preflight.v1') { send(200, { ok: true, protocolVersion: 'v1' }); return; }
  if (obj && obj.type === 'agent-games.proof-gatekeeper.v1') {
    const { status, body } = await handleGatekeeper(obj);
    send(status, body);
    return;
  }
  if (obj && (obj.eventId === 'steal-the-vfy' || obj.matchId)) {
    const { status, body } = await handleSteal(obj);
    send(status, body);
    return;
  }
  send(400, { error: 'unknown envelope' });
};
module.exports.config = { api: { bodyParser: false } };
