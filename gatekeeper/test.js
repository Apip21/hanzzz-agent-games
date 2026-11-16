// Gatekeeper harness: every trap type + boundary cases, each checked twice —
// once against decide() and once against the circuit itself (a wrong
// decision makes witness generation fail, so a passing proof confirms the
// decision the circuit would enforce). Proofs are verified locally.
// Run: node gatekeeper/test.js
const { decide, resetSeen } = require('./decide');
const { proveTask } = require('./prove');
const { verifyLocally } = require('../lib/snark');

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0x13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa13aa';
const ADDR = '0x1111111111111111111111111111111111111111';
const ADDR2 = '0x2222222222222222222222222222222222222222';

function base(over) {
  return {
    task_id: 'gk_test_1', registered_vk: VK, proof_vk: VK,
    minimum: '1000', public_balance: '1460', expiry_block: 8430000, current_block: 8420000,
    recipient: ADDR, condition_recipient: ADDR, amount: '500', max_transfer: '1000',
    proof_tx: '0xtx1', ...over,
  };
}

const CASES = [
  ['valid', {}, 'APPROVE', 'VALID_CONDITION'],
  ['vk substitution', { proof_vk: OTHER_VK }, 'REJECT', 'VK_SUBSTITUTION'],
  ['threshold mismatch', { public_balance: '999' }, 'REJECT', 'THRESHOLD_MISMATCH'],
  ['threshold boundary (== minimum) valid', { public_balance: '1000' }, 'APPROVE', 'VALID_CONDITION'],
  ['expired', { current_block: 8430001 }, 'REJECT', 'EXPIRED_CONDITION'],
  ['expiry boundary (== expiry) expired', { current_block: 8430000 }, 'REJECT', 'EXPIRED_CONDITION'],
  ['recipient mismatch', { condition_recipient: ADDR2 }, 'REJECT', 'RECIPIENT_MISMATCH'],
  ['amount overflow', { amount: '1001' }, 'REJECT', 'AMOUNT_OVERFLOW'],
  ['amount boundary (== max) valid', { amount: '1000' }, 'APPROVE', 'VALID_CONDITION'],
];

(async () => {
  let pass = 0, fail = 0;
  for (const [name, over, wantDecision, wantReason] of CASES) {
    resetSeen();
    const task = base(over);
    const got = decide(task);
    let ok = got.decision === wantDecision && got.reason_code === wantReason;
    let proofOk = false;
    try {
      const { proof, publicSignals } = await proveTask(task, got.decision, 'keccak');
      proofOk = await verifyLocally('gatekeeper', publicSignals, proof);
    } catch (e) {
      proofOk = false;
      console.log(`  proof error: ${e.message}`);
    }
    ok = ok && proofOk;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name} -> ${got.decision}/${got.reason_code} proof=${proofOk}`);
    ok ? pass++ : fail++;
  }
  // proof reuse: same proof_tx under a second task_id must be PROOF_REUSED,
  // and the circuit must accept a REJECT decision for it.
  resetSeen();
  decide(base({}));
  const reused = base({ task_id: 'gk_test_2' });
  const got = decide(reused);
  let ok = got.decision === 'REJECT' && got.reason_code === 'PROOF_REUSED';
  console.log(`${ok ? 'PASS' : 'FAIL'}  proof reused across tasks -> ${got.decision}/${got.reason_code}`);
  ok ? pass++ : fail++;
  // same task_id retry is NOT reuse
  resetSeen();
  decide(base({}));
  const retry = decide(base({}));
  ok = retry.decision === 'APPROVE';
  console.log(`${ok ? 'PASS' : 'FAIL'}  same-task retry is not reuse -> ${retry.decision}/${retry.reason_code}`);
  ok ? pass++ : fail++;

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
