// Steal harness: the policy function is checked against the vfy-policy
// circuit itself — for each (params, state) the policy's action must produce
// a witness (fullProve must not throw) and a locally verifying proof, and a
// deliberately wrong action MUST fail witness generation.
// Run: node steal/test.js   (uses the strategy from .env / env, plus grids)
const crypto = require('crypto');
const { policy, validateParams } = require('./policy');
const { proveTurn } = require('./prove');
const { strategyCommitment } = require('../lib/field');
const { prove, verifyLocally } = require('../lib/snark');

const PARAM_SETS = [
  ['10', '0', '0', '0', '0', '0', '0', '0'],   // ours: always extract max
  ['5', '50', '0', '0', '0', '0', '0', '0'],   // fortify while poor
  ['7', '20', '30', '0', '0', '0', '0', '0'],  // mixed
  ['3', '0', '0', '1', '0', '0', '0', '0'],    // mode 1: always HOLD
];
const STATES = [
  { selfBalance: '100', opponentBalance: '100' },
  { selfBalance: '10', opponentBalance: '100' },
  { selfBalance: '100', opponentBalance: '0' },
  { selfBalance: '45', opponentBalance: '25' },
  { selfBalance: '0', opponentBalance: '80' },
];

(async () => {
  let pass = 0, fail = 0;
  const salt = '0x' + crypto.randomBytes(16).toString('hex');
  for (const params of PARAM_SETS) {
    const err = validateParams(params);
    if (err) { console.log('FAIL params', err); fail++; continue; }
    const commitment = strategyCommitment(params, salt);
    for (const state of STATES) {
      const turn = { matchId: '123e4567-e89b-12d3-a456-426614174000', turn: 3, state };
      const action = policy(state, params);
      try {
        const { proof, publicSignals, publicInputsHash } = await proveTurn(turn, action, commitment, salt, params);
        const ok = await verifyLocally('vfyPolicy', publicSignals, proof);
        console.log(`${ok ? 'PASS' : 'FAIL'}  params=[${params.slice(0, 4)}] self=${state.selfBalance} opp=${state.opponentBalance} -> ${action.type}${action.amount ? ' ' + action.amount : ''} proof=${ok} hash=${publicInputsHash.slice(0, 10)}…`);
        ok ? pass++ : fail++;
      } catch (e) {
        console.log(`FAIL  params=[${params.slice(0, 4)}] self=${state.selfBalance} opp=${state.opponentBalance} -> ${action.type} threw: ${e.message}`);
        fail++;
      }
    }
  }
  // Negative control: a wrong action for the committed params must be
  // rejected by the circuit (witness generation throws).
  const params = PARAM_SETS[0];
  const commitment = strategyCommitment(params, salt);
  const turn = { matchId: '123e4567-e89b-12d3-a456-426614174000', turn: 1, state: { selfBalance: '100', opponentBalance: '100' } };
  try {
    await prove('vfyPolicy', {
      commitment: String(commitment),
      matchId: '0x' + turn.matchId.replace(/-/g, ''),
      turnNumber: '1', selfBalance: '100', opponentBalance: '100',
      action: '0', amount: '0', circuitVersion: '1', salt,
      strategyParams: params.map(String),
    });
    console.log('FAIL  negative control: HOLD proof generated for an EXTRACT-committed state');
    fail++;
  } catch {
    console.log('PASS  negative control: circuit rejects an action the policy did not dictate');
    pass++;
  }
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
