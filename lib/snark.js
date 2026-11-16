// snarkjs wrapper: local Groth16 proving + verification against the
// official circuit artifacts in ../circuits (downloaded from
// https://agentgames.zkverify.io/circuits, SHA-256 pinned in README).
const path = require('path');
const snarkjs = require('snarkjs');

const CIRCUITS_DIR = path.join(__dirname, '..', 'circuits');

const CIRCUITS = {
  gatekeeper: {
    wasm: path.join(CIRCUITS_DIR, 'gatekeeper.wasm'),
    zkey: path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey'),
  },
  vfyPolicy: {
    wasm: path.join(CIRCUITS_DIR, 'vfy-policy.wasm'),
    zkey: path.join(CIRCUITS_DIR, 'vfy-policy_final.zkey'),
  },
};

const vkCache = {};

async function getVerificationKey(name) {
  if (!vkCache[name]) {
    vkCache[name] = await snarkjs.zKey.exportVerificationKey(CIRCUITS[name].zkey);
  }
  return vkCache[name];
}

// Throws when the witness cannot be generated — i.e. the inputs violate the
// circuit (for the gatekeeper, a decision that disagrees with the circuit's
// own evaluation). Callers must fail closed.
async function prove(name, input) {
  const { wasm, zkey } = CIRCUITS[name];
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
  return { proof, publicSignals };
}

async function verifyLocally(name, publicSignals, proof) {
  const vk = await getVerificationKey(name);
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { CIRCUITS, getVerificationKey, prove, verifyLocally };
