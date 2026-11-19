// ============================================================
// Shared Types for zkVerify Agent Games
// Alpines Keeper (Proof Gatekeeper) + Alpines Stealer (Steal the VFY)
// ============================================================

// -- Groth16 Proof ------------------------------------------

export interface Groth16Proof {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol?: string;
  curve?: string;
}

export interface ProofResult {
  proof: Groth16Proof;
  publicSignals: string[];
}

// -- Prover Config ------------------------------------------

export interface ProverConfig {
  wasmPath: string;
  zkeyPath: string;
  rapidsnarkBin?: string;
}

// -- Common Agent Games -------------------------------------

export interface AgentRequest {
  task_id: string;
  timestamp: number;
  event_type?: string;
  [key: string]: unknown;
}

export interface PreflightResponse {
  ok: boolean;
  protocolVersion: string;
}

// -- Proof Gatekeeper Types ---------------------------------

// -- Proof Gatekeeper Types ---------------------------------

export interface GatekeeperInput {
  registered_vk: string;        // VK hash registered on platform
  proof_vk: string;             // VK hash from the submitted proof
  minimum: string;              // minimum payment amount (decimal string)
  public_balance: string;       // public balance context (decimal string)
  expiry_block: number;         // block number at which payment expires
  current_block: number;        // current block number (provided by platform)
  recipient: string;            // expected payment recipient address
  condition_recipient: string;  // condition recipient (must match recipient for APPROVE)
  amount: string;               // payment amount (decimal string)
  max_transfer: string;         // max allowed transfer amount (decimal string)
  proof_tx: string;             // on-chain tx hash of the submitted proof
}

export interface GatekeeperTask extends AgentRequest {
  type: string;         // "agent-games.proof-gatekeeper.v1"
  task_id: string;
  mode: string;
  issued_at: string;
  deadline_at: string;
  input: GatekeeperInput;
}

export type GatekeeperDecision = 'APPROVE' | 'REJECT';

export type GatekeeperReasonCode =
  | 'SUCCESS'
  | 'VK_MISMATCH'
  | 'INVALID_PROOF_SYSTEM'
  | 'INVALID_PROOF'
  | 'PROOF_REUSED'
  | 'AMOUNT_BELOW_MINIMUM'
  | 'AMOUNT_OVERFLOW'
  | 'EXPIRED'
  | 'RECIPIENT_MISMATCH'
  | 'NOT_FINALIZED'
  | 'VALIDATION_ERROR';

export interface GatekeeperResponse {
  decision: GatekeeperDecision;
  reason_code: GatekeeperReasonCode;
  proof_tx?: string;  // echo input.proof_tx back to platform
}

// -- Steal the VFY Types ------------------------------------

export type StealAction = 'FORTIFY' | 'EXTRACT' | 'HOLD';

export interface StealGameState {
  selfBalance: string;              // current balance as decimal string
  opponentBalance: string;
  selfFortifiedUntilTurn: number | null;
  opponentFortifiedUntilTurn: number | null;
}

export interface StealTask extends AgentRequest {
  protocolVersion: string;          // "v1"
  eventId: string;                  // "steal-the-vfy"
  mode: string;
  matchId: string;
  turn: number;
  issuedAt: string;
  deadlineAt: string;
  state: StealGameState;
  strategyCommitment: { hash: string };
  resolverVersion: string;
  nonce: string;
  // Legacy / optional fields kept for compatibility
  total_turns?: number;
  opponent_last_action?: StealAction;
}

export interface StealActionObject {
  type: StealAction;
  amount?: number;  // only present for EXTRACT; omit for HOLD/FORTIFY
}

export interface StealResponse {
  matchId: string;
  turn: number;
  action: StealActionObject;
  idempotencyKey: string;   // must be a valid UUID v4
  agentTimestamp: string;
  policyProof: {            // REQUIRED - always present, even if proof is invalid
    circuitVersion: 'v1';
    proof: Groth16Proof | { pi_a: string[]; pi_b: string[][]; pi_c: string[]; protocol: string; curve: string };
    public_signals: string[];
    publicInputsHash: string;  // REQUIRED: keccak256 of ABI-packed game state (platform pre-screens this)
    proofReference?: string;
  };
}

export interface MatchState {
  matchId: string;
  turn: number;
  totalTurns: number;
  myBalance: number;
  opponentBalance: number;
  myHistory: StealAction[];
  opponentHistory: StealAction[];
  lastUpdated: number;
}

// -- Strategy Types -----------------------------------------

export interface ActionProbabilities {
  FORTIFY: number;
  EXTRACT: number;
  HOLD: number;
}

// -- zkVerify Client ----------------------------------------

export interface ZkVerifyConfig {
  apiUrl: string;
  apiKey?: string;
}

export interface ZkVerifyVerifyResult {
  valid: boolean;
  finalized: boolean;
  txHash?: string;
}
