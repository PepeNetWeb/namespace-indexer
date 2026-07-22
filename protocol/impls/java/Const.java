import java.math.BigInteger;

// Protocol constants (spec §0) + opcode/state/type enums. All derived from the
// docs/protocol-spec.md constant table and §2 registry.
final class Const {
    // koinu economics
    static final BigInteger DUST_FLOOR = BigInteger.ONE;                 // 1 koinu
    static final BigInteger RATE_CAP   = BigInteger.valueOf(100_000_000L); // 1 DOGE = 1e8 koinu
    static final BigInteger SUBSIDY    = BigInteger.valueOf(1_000_000_000_000L); // 10000 DOGE flat (§3.4)
    static final long REF_SIZE      = 200;
    static final long FEE_WINDOW    = 10_081;   // odd
    static final long MIN_FEE_SAMPLE= 1_000;    // min fee-bearing (participant) count for a trusted median; below → DUST_FLOOR (§3.4, boundary inclusive)
    static final long LEASE_QUANTUM = 2_419_200;
    static final long BILLING_UNIT  = 86_400;
    static final long MAX_LEASE     = 31_536_000;
    static final long COMMIT_EXPIRY = 18_000;
    static final long RESERVE_WINDOW= 18_000;
    static final long DIRECT_WINDOW = 7_200;
    static final long REORG_BUFFER  = 7_200;
    static final long RESERVE_DEPOSIT_BPS = 100;
    static final long RESERVE_BURN_BPS    = 50;
    static final long RESERVE_PAY_BPS     = 50;
    static final long MAX_ANCHOR_AGE = 1024;
    static final BigInteger BPS_DEN = BigInteger.valueOf(10000);

    static final long ACTIVATION_HEIGHT = 0; // generator uses activation_height=0 (§5)

    // SELL price floor = 3 * DUST_FLOOR (§3.7)
    static final BigInteger SELL_FLOOR = BigInteger.valueOf(3);

    // prefix
    static final byte P0 = (byte) 0xFF, P1 = (byte) 0x50, P2 = (byte) 0x4E;

    // opcodes
    static final int VOTE_UP=0x01, VOTE_DOWN=0x02, COMMIT=0x03, CLAIM=0x04, RENEW=0x05,
        TRANSFER=0x06, SELL=0x07, RESERVE=0x08, SETTLE=0x09, RELEASE=0x0A, DECORATE=0x0B,
        SELL_TO=0x0C, PAY=0x0D, AS=0x0E, TRADE=0x0F;

    // name-row state (digest §4): OWNED=0 LISTED=1 OFFERED=2 RESERVED=3
    static final int OWNED=0, LISTED=1, OFFERED=2, RESERVED=3;

    // script type — value mapping is NOT pinned by SPEC-conformance §4 (it only says
    // "u8 seller_type"). Natural reading P2PKH=0, P2SH=1. Recorded as a fork-risk note.
    static final int P2PKH=0, P2SH=1;

    // §1 DECORATE pending-record cap: records past 64 drop (parsing continues).
    static final int PEND_DECOR_MAX = 64;
    // Max raw DECORATE TLV payload bytes (SM_DEC_MAX in impls/c decode.c).
    static final int DEC_MAX = 80;

    // 2^64 and 2^128 for BigInteger narrowing / i128 serialization
    static final BigInteger TWO64  = BigInteger.ONE.shiftLeft(64);
    static final BigInteger TWO128 = BigInteger.ONE.shiftLeft(128);
    static final BigInteger I128_MIN = BigInteger.ONE.shiftLeft(127).negate();
    static final BigInteger I128_MAX = BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE);

    private Const() {}
}
