// Proof Gatekeeper — deterministic decision logic.
//
// The gatekeeper circuit is the referee: it constrains decision == 1 if and
// only if every check below passes, so this checklist must mirror the
// circuit exactly (boundaries verified against the circuit in test.js):
//   - balance threshold is INCLUSIVE (public_balance == minimum is valid)
//   - transfer cap is INCLUSIVE (amount == max_transfer is valid)
//   - expiry is STRICT (current_block == expiry_block is already expired)
//
// First failing check wins and names the reason_code:
//   VK_SUBSTITUTION    proof_vk != registered_vk
//   PROOF_REUSED       proof_tx already accepted under a DIFFERENT task_id
//                      (a platform retry of the same task_id is not reuse)
//   THRESHOLD_MISMATCH public_balance < minimum
//   EXPIRED_CONDITION  current_block >= expiry_block
//   RECIPIENT_MISMATCH recipient != condition_recipient
//   AMOUNT_OVERFLOW    amount > max_transfer
//   otherwise VALID_CONDITION -> APPROVE
const seenProofTx = new Map(); // proof_tx (lowercased) -> task_id

function decide(input) {
  const registeredVk = String(input.registered_vk || '').toLowerCase();
  const proofVk = String(input.proof_vk || '').toLowerCase();
  const minimum = BigInt(input.minimum);
  const publicBalance = BigInt(input.public_balance);
  const expiryBlock = BigInt(input.expiry_block);
  const currentBlock = BigInt(input.current_block);
  const recipient = String(input.recipient || '').toLowerCase();
  const conditionRecipient = String(input.condition_recipient || '').toLowerCase();
  const amount = BigInt(input.amount);
  const maxTransfer = BigInt(input.max_transfer);
  const proofTx = String(input.proof_tx || '').toLowerCase();
  const taskId = String(input.task_id || '');

  if (proofVk !== registeredVk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };

  if (proofTx) {
    const prevTask = seenProofTx.get(proofTx);
    if (prevTask !== undefined && prevTask !== taskId) {
      return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
    }
    if (prevTask === undefined) seenProofTx.set(proofTx, taskId);
  }

  if (publicBalance < minimum) return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  if (currentBlock >= expiryBlock) return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  if (recipient !== conditionRecipient) return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  if (amount > maxTransfer) return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };

  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

function resetSeen() {
  seenProofTx.clear();
}

module.exports = { decide, resetSeen, seenProofTx };
