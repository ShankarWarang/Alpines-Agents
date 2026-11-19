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

export interface GatekeeperPaymentRequest {
  recipient: string;
  min_amount: string;
  max_amount?: string;
  deadline: number;
  rule_hash?: string;
}

export interface GatekeeperIncomingProof {
  proof: Groth16Proof;
  publicInputs: string[];
  proof_tx?: string;
  vk_hash?: string;
  proving_system?: string;
}

export interface GatekeeperTask extends AgentRequest {
  payment_request: GatekeeperPaymentRequest;
  incoming_proof: GatekeeperIncomingProof;
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
  proof?: Groth16Proof;
  public_signals?: string[];
  proof_tx?: string;
}

// -- Steal the VFY Types ------------------------------------

export type StealAction = 'FORTIFY' | 'EXTRACT' | 'HOLD';

export interface StealTask extends AgentRequest {
  match_id: string;
  turn: number;
  total_turns: number;
  my_balance: number;
  opponent_balance: number;
  opponent_last_action?: StealAction;
  strategy_hash?: string;
}

export interface StealResponse {
  action: StealAction;
  idempotencyKey: string;
  amount?: number;           // only for EXTRACT
  policyProof?: {
    circuitVersion: number;
    proof: Groth16Proof;
    public_signals: string[];
    publicInputsHash?: string;
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
