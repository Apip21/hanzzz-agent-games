// Field helpers for the BN254 (alt_bn128) scalar field used by both
// Agent Games circuits, plus keccak256 / Poseidon utilities.
const { keccak_256 } = require('js-sha3');
const { poseidon9 } = require('poseidon-lite');

const FIELD_PRIME = BigInt(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617'
);

function toField(x) {
  let b;
  if (typeof x === 'bigint') b = x;
  else if (typeof x === 'number') b = BigInt(x);
  else if (typeof x === 'string' && x.startsWith('0x')) b = BigInt(x);
  else b = BigInt(x);
  const r = b % FIELD_PRIME;
  return r < 0n ? r + FIELD_PRIME : r;
}

// Bare-hex aware conversion (salts are often pasted as bare hex).
function toFieldHex(x) {
  if (typeof x === 'string' && !x.startsWith('0x') && /^[0-9a-fA-F]+$/.test(x)) {
    return toField(BigInt('0x' + x));
  }
  return toField(x);
}

function toHexString(x) {
  const s = String(x || '');
  if (s.startsWith('0x')) return s;
  if (/^[0-9a-fA-F]+$/.test(s)) return '0x' + s;
  return s;
}

function to32Bytes(x) {
  const b = toField(x);
  return Buffer.from(b.toString(16).padStart(64, '0'), 'hex');
}

function keccak256Hex(buffers) {
  return '0x' + keccak_256(Buffer.concat(buffers));
}

function keccak256ModP(buffers) {
  return toField(BigInt(keccak256Hex(buffers)));
}

// Steal the VFY strategy commitment: Poseidon(params[0..7], salt).
// Ordering (params first, salt last) is the one the official vfy-policy
// circuit accepts — witness calculation fails for any other ordering.
function strategyCommitment(params, salt) {
  if (!Array.isArray(params) || params.length !== 8) {
    throw new Error('strategyCommitment needs exactly 8 strategy params');
  }
  const inputs = [...params.map((p) => toField(p)), toFieldHex(salt)];
  const h = poseidon9(inputs);
  return '0x' + BigInt(h).toString(16).padStart(64, '0');
}

module.exports = { FIELD_PRIME, toField, toFieldHex, toHexString, to32Bytes, keccak256Hex, keccak256ModP, strategyCommitment };
