// Protocol constants (protocol-spec.md §0 "Protocol constants" table) and conformance
// constants (SPEC-conformance.md §5 generator, §2 integer widths). All consensus values are
// carried as `bigint` so they never transit a JS `number` (IEEE-754 double) on the value path.
//
// Cleanroom note: every value here is transcribed verbatim from the two spec docs. Anywhere the
// prose left a quantity implicit it is flagged in SPEC-RATIONALE.md, not silently guessed.

// ─── §0 protocol constants ───────────────────────────────────────────────────────────────────
export const DUST_FLOOR = 1n; // koinu — rate floor, min vote weight, RESERVE deposit-leg floor
export const RATE_CAP = 100_000_000n; // 1 DOGE in koinu — rate ceiling (§3.4)
export const REF_SIZE = 200n; // bytes — fee-per-byte → per-name rent (§3.4)
export const FEE_WINDOW = 10_081n; // blocks (~1 wk, ODD) — coinbase fee-per-byte median window
export const MIN_FEE_SAMPLE = 1_000n; // min fee-bearing (participant) count for a trusted median; below → DUST_FLOOR (§3.4, boundary inclusive)
export const LEASE_QUANTUM = 2_419_200n; // s (~28 d) — rent anchor: koinu per name per quantum
export const BILLING_UNIT = 86_400n; // s (1 d) — lease-extension granularity
export const MAX_LEASE = 31_536_000n; // s (~365 d) — cap on how far ahead a lease may extend
export const COMMIT_EXPIRY = 18_000n; // s (~5 h) — a commit's live window (INCLUSIVE, §3.2)
export const RESERVE_WINDOW = 18_000n; // s (~5 h) — reserve's exclusive-buy window; SELL window floor
export const DIRECT_WINDOW = 7_200n; // s (~2 h) — directed-sale (SELL_TO) offer window, FIXED
export const REORG_BUFFER = 7_200n; // s (~2 h) — margin keeping ordered time-boundaries apart
export const RESERVE_DEPOSIT_BPS = 100n; // 1.00 % total reserve deposit, bps of price
export const RESERVE_BURN_BPS = 50n; // 0.50 % deposit leg burned
export const RESERVE_PAY_BPS = 50n; // 0.50 % deposit leg paid to seller
export const MAX_ANCHOR_AGE = 1024n; // blocks — max staleness of a renew/transfer height anchor
export const BPS_DENOM = 10_000n;

// SELL price floor basis (§3.7): price ≥ 3 × DUST_FLOOR.
export const SELL_PRICE_FLOOR = 3n * DUST_FLOOR;

// Dogecoin host-consensus subsidy across the reachable FEE_WINDOW (§3.4): flat 10_000 DOGE.
export const DOGE_SUBSIDY = 10_000n * 100_000_000n; // koinu

// ─── §5 generator constants (SPEC-conformance.md §5) ─────────────────────────────────────────
// These pin MY generator's parameters. The *draw order* itself is deferred to impls/c/src/gen.c
// (forbidden), so my generator is internally consistent but will NOT reproduce the doc's seed
// goldens — stated plainly in README/SPEC-RATIONALE.md and never faked.
export const N_IDS = 16;
export const NAME_POOL = 400;
export const BASE_TS = 1_700_000_000n;
export const DEFAULT_ACTIVATION_HEIGHT = 0n; // §5: activation_height=0 for the SM model

// ─── Opcodes (§2 Action Registry) ────────────────────────────────────────────────────────────
export const OP = {
  VOTE_UP: 0x01,
  VOTE_DOWN: 0x02,
  COMMIT: 0x03,
  CLAIM: 0x04,
  RENEW: 0x05,
  TRANSFER: 0x06,
  SELL: 0x07,
  RESERVE: 0x08,
  SETTLE: 0x09,
  RELEASE: 0x0a,
  DECORATE: 0x0b,
  SELL_TO: 0x0c,
  PAY: 0x0d,
  AS: 0x0e,
  TRADE: 0x0f,
} as const;

export const OP_MIN = 0x01;
export const OP_MAX = 0x0f;

// Universal prefix bytes (§1): 0xFF 'P' 'N' <opcode>.
export const PREFIX0 = 0xff;
export const PREFIX1 = 0x50; // 'P'
export const PREFIX2 = 0x4e; // 'N'

// names-table state enum (SPEC-conformance.md §4): OWNED=0 LISTED=1 OFFERED=2 RESERVED=3.
export const ST = { OWNED: 0, LISTED: 1, OFFERED: 2, RESERVED: 3 } as const;

// secp256k1 order N and N/2 (Rule 4 low-S, §13 SECP_N_HALF) and field prime p (§13 SECP_P).
export const SECP_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const SECP_N_HALF = SECP_N >> 1n;
export const SECP_P =
  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
