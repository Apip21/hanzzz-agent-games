// Vercel serverless adapter — Steal the VFY. See api/gatekeeper.js.
const { verifySignature, signatureFor } = require('../lib/hmac');
const { handleSteal } = require('../server');

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
  const { status, body } = await handleSteal(obj);
  send(status, body);
};
module.exports.config = { api: { bodyParser: false } };
