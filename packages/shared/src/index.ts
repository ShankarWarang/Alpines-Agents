// ============================================================
// @zkverify/shared - Barrel Export
// ============================================================

// Types
export type {
  Groth16Proof,
  ProofResult,
  ProverConfig,
  AgentRequest,
  PreflightResponse,
  GatekeeperPaymentRequest,
  GatekeeperIncomingProof,
  GatekeeperTask,
  GatekeeperDecision,
  GatekeeperReasonCode,
  GatekeeperResponse,
  StealAction,
  StealTask,
  StealResponse,
  MatchState,
  ActionProbabilities,
  ZkVerifyConfig,
  ZkVerifyVerifyResult,
} from './types.js';

// HMAC authentication
export { initHmac, signHmac, verifyHmac } from './hmac.js';

// Groth16 proof generator
export { initProver, generateProof } from './prover.js';

// zkVerify REST client
export {
  initZkVerify,
  verifyProof,
  checkFinalization,
  submitProof,
} from './zkverify-client.js';

// Logger
export { createLogger } from './logger.js';
