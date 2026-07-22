using System;

namespace Shibpost;

/// <summary>
/// Protocol constants (protocol-spec.md §0) and conformance encodings
/// (SPEC-conformance.md §3/§4). Every value here is pinned by the spec; a
/// divergence here forks ownership for every indexer, so they are centralized.
/// </summary>
public static class K
{
    public const ulong KOINU_PER_DOGE = 100_000_000UL;
    public const ulong DUST_FLOOR     = 1UL;                  // rent floor, min vote weight, deposit floor
    public const ulong RATE_CAP       = 100_000_000UL;        // 1 DOGE in koinu
    public const ulong REF_SIZE       = 200UL;                // bytes
    public const long  FEE_WINDOW     = 10_081L;              // blocks, ODD
    public const int   MIN_FEE_SAMPLE = 1_000;                // min fee-bearing (participant) count for a trusted median; below → DUST_FLOOR (§3.4, boundary inclusive)
    public const long  LEASE_QUANTUM  = 2_419_200L;           // seconds (~28 d)
    public const long  BILLING_UNIT   = 86_400L;              // seconds (1 d)
    public const long  MAX_LEASE      = 31_536_000L;          // seconds (~365 d)
    public const long  COMMIT_EXPIRY  = 18_000L;              // seconds (~5 h) — INCLUSIVE window
    public const long  RESERVE_WINDOW = 18_000L;              // seconds (~5 h)
    public const long  DIRECT_WINDOW  = 7_200L;               // seconds (~2 h) — fixed, no field
    public const long  REORG_BUFFER   = 7_200L;               // seconds (~2 h)
    public const ulong RESERVE_DEPOSIT_BPS = 100UL;           // 1.00%
    public const ulong RESERVE_BURN_BPS    = 50UL;            // 0.50%
    public const ulong RESERVE_PAY_BPS     = 50UL;            // 0.50%
    public const long  MAX_ANCHOR_AGE = 1024L;                // blocks

    // Dogecoin consensus subsidy across the reachable window: flat 10_000 DOGE.
    public const ulong SUBSIDY_KOINU  = 10_000UL * KOINU_PER_DOGE; // = 1_000_000_000_000

    // Opcodes (protocol-spec.md §2).
    public const byte OP_VOTE_UP   = 0x01;
    public const byte OP_VOTE_DOWN = 0x02;
    public const byte OP_COMMIT    = 0x03;
    public const byte OP_CLAIM     = 0x04;
    public const byte OP_RENEW     = 0x05;
    public const byte OP_TRANSFER  = 0x06;
    public const byte OP_SELL      = 0x07;
    public const byte OP_RESERVE   = 0x08;
    public const byte OP_SETTLE    = 0x09;
    public const byte OP_RELEASE   = 0x0A;
    public const byte OP_DECORATE  = 0x0B;
    public const byte OP_SELL_TO   = 0x0C;
    public const byte OP_PAY       = 0x0D;
    public const byte OP_AS        = 0x0E;
    public const byte OP_TRADE     = 0x0F;

    // Universal prefix: 0xFF 'P' 'N'
    public const byte PFX0 = 0xFF;
    public const byte PFX1 = 0x50; // 'P'
    public const byte PFX2 = 0x4E; // 'N'

    // st enum byte values (SPEC-conformance §4).
    public const byte ST_OWNED    = 0;
    public const byte ST_LISTED   = 1;
    public const byte ST_OFFERED  = 2;
    public const byte ST_RESERVED = 3;

    // seller_type / attribution template selector (SPEC-conformance §3/§13).
    public const byte TYPE_P2PKH = 0;
    public const byte TYPE_P2SH  = 1;
}
