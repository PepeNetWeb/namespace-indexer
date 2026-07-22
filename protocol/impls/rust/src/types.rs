//! Shared types across decode / fold / digest.

pub type Hash160 = [u8; 20];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ScriptType {
    P2pkh = 0,
    P2sh = 1,
}

impl ScriptType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// Opcodes (§2).
pub const OP_VOTE_UP: u8 = 0x01;
pub const OP_VOTE_DOWN: u8 = 0x02;
pub const OP_COMMIT: u8 = 0x03;
pub const OP_CLAIM: u8 = 0x04;
pub const OP_RENEW: u8 = 0x05;
pub const OP_TRANSFER: u8 = 0x06;
pub const OP_SELL: u8 = 0x07;
pub const OP_RESERVE: u8 = 0x08;
pub const OP_SETTLE: u8 = 0x09;
pub const OP_RELEASE: u8 = 0x0A;
pub const OP_DECORATE: u8 = 0x0B;
pub const OP_SELL_TO: u8 = 0x0C;
pub const OP_PAY: u8 = 0x0D;
pub const OP_AS: u8 = 0x0E;
pub const OP_TRADE: u8 = 0x0F;

// Protocol constants (§0 table).
pub const DUST_FLOOR: u64 = 1;
pub const RATE_CAP: u64 = 100_000_000; // 1 DOGE in koinu
pub const REF_SIZE: u64 = 200;
pub const FEE_WINDOW: usize = 10_081;
pub const MIN_FEE_SAMPLE: usize = 1_000; // min fee-bearing (participant) count for a trusted median; below → DUST_FLOOR (§3.4, boundary inclusive)
pub const LEASE_QUANTUM: u64 = 2_419_200;
pub const BILLING_UNIT: u64 = 86_400;
pub const MAX_LEASE: u64 = 31_536_000;
pub const COMMIT_EXPIRY: i64 = 18_000;
pub const RESERVE_WINDOW: i64 = 18_000;
pub const DIRECT_WINDOW: i64 = 7_200;
pub const REORG_BUFFER: i64 = 7_200;
pub const RESERVE_DEPOSIT_BPS: u64 = 100;
pub const RESERVE_BURN_BPS: u64 = 50;
pub const RESERVE_PAY_BPS: u64 = 50;
pub const MAX_ANCHOR_AGE: i64 = 1024;

pub const SUBSIDY_FLAT: u64 = 1_000_000_000_000; // 10_000 DOGE in koinu (flat reward window)

/// §1 pending DECORATE-record cap: the fold buffers DECORATE TLV records to bind to the
/// next body; only the first 64 pending records are retained (records past 64 are dropped,
/// parsing continues). Pinned across all 7 impls (2026-07-03).
pub const PEND_DECOR_MAX: usize = 64;

/// Validate a name per §3.1: charset [a-z0-9-] (a DNS label), length 1..=32, byte-for-byte
/// (no case-fold). Re-pin 2026-07-07: '.'/'_' dropped, '-' added (supersedes the 2026-07-02
/// dot rule). No structural rules — '-a', 'a-', 'xn--x' are valid names; uppercase stays invalid.
pub fn valid_name(b: &[u8]) -> bool {
    if b.is_empty() || b.len() > 32 {
        return false;
    }
    b.iter().all(|&c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}
