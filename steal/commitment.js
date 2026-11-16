// Print ONLY the Steal the VFY strategy commitment hash to register in the
// dashboard. Reads STEAL_STRATEGY_PARAMS / STEAL_STRATEGY_SALT from the
// environment or ./.env. The params and salt are never printed.
//   commitment = Poseidon(strategyParams[0..7], salt)
// Generate a salt with: openssl rand -hex 16  (keep it in .env, never commit)
const fs = require('fs');
const path = require('path');

(function loadEnv() {
  try {
    for (const line of fs.readFileSync(path.join(__dirname, '..', '.env'), 'utf8').split('\n')) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* no .env */ }
})();

const { strategyCommitment } = require('../lib/field');
const { validateParams } = require('./policy');

const raw = (process.env.STEAL_STRATEGY_PARAMS || '').trim();
const salt = (process.env.STEAL_STRATEGY_SALT || '').trim();
if (!raw || !salt) {
  console.error('Set STEAL_STRATEGY_PARAMS and STEAL_STRATEGY_SALT first (in .env or env).');
  process.exit(1);
}
const params = raw.split(',').map((s) => s.trim());
const err = validateParams(params);
if (err) {
  console.error('Invalid STRATEGY_PARAMS: ' + err);
  process.exit(1);
}
console.log(strategyCommitment(params, salt));
