// Steal the VFY — deterministic policy.
//
// The vfy-policy circuit is the referee: for a given (state, strategyParams)
// it accepts exactly the action this function returns. Parameter semantics
// (validated against the circuit over a state/param grid in test.js):
//   params[0] extractAmount      — amount taken on EXTRACT (1..10)
//   params[1] fortifyThreshold   — FORTIFY while selfBalance < this
//   params[2] minOpponentBalance — EXTRACT only while opponentBalance > this
//   params[3] mode               — 0 = normal, 1 = always HOLD; >= 2 invalid
//   params[4..7] reserved        — must be 0 (any nonzero value makes every
//                                  action invalid in the circuit)
//
// Policy (mode 0), in order:
//   1. selfBalance < params[1]      -> FORTIFY
//   2. opponentBalance <= params[2] -> HOLD
//   3. otherwise                    -> EXTRACT params[0]
// Mode 1: always HOLD.
// FORTIFY depends on OWN balance only — opponent fortification is not a
// circuit input.
const ACTIONS = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

function validateParams(params) {
  if (!Array.isArray(params) || params.length !== 8) {
    return 'STRATEGY_PARAMS must be exactly 8 numbers';
  }
  const [p0, p1, p2, p3, p4, p5, p6, p7] = params.map((x) => BigInt(x));
  if (p0 < 1n || p0 > 10n) return 'params[0] (extract amount) must be 1..10';
  if (p1 < 0n) return 'params[1] (fortify threshold) must be >= 0';
  if (p2 < 0n) return 'params[2] (min opponent balance) must be >= 0';
  if (p3 !== 0n && p3 !== 1n) return 'params[3] (mode) must be 0 or 1';
  if (p4 !== 0n || p5 !== 0n || p6 !== 0n || p7 !== 0n) {
    return 'params[4..7] must be 0 (reserved)';
  }
  return null;
}

function policy(state, params) {
  // Returns { type, amount? } — amount present ONLY for EXTRACT (the
  // platform schema rejects an amount field on HOLD/FORTIFY, even 0).
  const [p0, p1, p2, p3] = params.map((x) => BigInt(x));
  const self = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  if (p3 === 1n) return { type: 'HOLD' };
  if (self < p1) return { type: 'FORTIFY' };
  if (opp <= p2) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: Number(p0) };
}

module.exports = { ACTIONS, validateParams, policy };
