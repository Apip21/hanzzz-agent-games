// HMAC-SHA256 signing for Agent Games envelopes.
// The platform signs every inbound request with the per-agent secret
// (dashboard "Rotate Secret") in the `x-agent-games-signature` header,
// computed over the RAW request body. We verify before parsing, and sign
// every response the same way over the raw response body.
// Default format is lowercase hex; AGENT_GAMES_HMAC_FORMAT=sha256= switches
// to the `sha256=<hex>` form if the platform's preflight rejects hex.
const crypto = require('crypto');

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signatureFor(secret, rawBody, format) {
  const hex = hmacHex(secret, rawBody);
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

function verifySignature(secret, rawBody, headerValue, format) {
  if (!secret || !headerValue) return false;
  const expected = signatureFor(secret, rawBody, format);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(headerValue));
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

module.exports = { hmacHex, signatureFor, verifySignature };
