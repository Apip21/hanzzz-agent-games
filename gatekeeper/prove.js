// Proof Gatekeeper — Groth16 proof generation.
// Circuit inputs (13): registeredVkHash, proofVkHash, minimum, publicBalance,
// expiryBlock, currentBlock, recipient, conditionRecipient, amount,
// maxTransfer, decision (1 APPROVE / 0 REJECT), taskId, salt (private).
// Public signals (13): a salt-dependent binding hash, then the 12 task fields
// above (minus salt) in circuit order — the platform checks those against
// the envelope it sent.
//
// task_id mapping: the envelope's task_id is a string ("gk_24_9d1") but the
// circuit needs a field element. Default mode "keccak" =
// keccak256(utf8(task_id)) mod p. GATEKEEPER_TASK_ID_MODE can switch to
// "numeric" (digits only) or "hex" (hex chars only) if a practice task shows
// the platform expects a different mapping.
const crypto = require('crypto');
const { toField, keccak256ModP } = require('../lib/field');
const { prove } = require('../lib/snark');

function taskIdToField(taskId, mode) {
  const id = String(taskId || '');
  if (mode === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? toField(BigInt(digits)) : 0n;
  }
  if (mode === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? toField(BigInt('0x' + hex)) : 0n;
  }
  return keccak256ModP([Buffer.from(id, 'utf8')]);
}

function buildInput(task, decision, taskIdMode) {
  const salt = '0x' + crypto.randomBytes(32).toString('hex');
  return {
    registeredVkHash: String(task.registered_vk),
    proofVkHash: String(task.proof_vk),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: String(task.recipient),
    conditionRecipient: String(task.condition_recipient),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id, taskIdMode).toString(),
    salt,
  };
}

async function proveTask(task, decision, taskIdMode) {
  const input = buildInput(task, decision, taskIdMode);
  return prove('gatekeeper', input);
}

module.exports = { taskIdToField, buildInput, proveTask };
