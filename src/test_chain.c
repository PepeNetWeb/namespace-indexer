// test_chain.c — end-to-end pipeline test on a REAL (self-signed) chain segment.
//
// Crafts a P2PKH key, signs real transactions (libsecp shim), wraps them in real
// Dogecoin blocks, and drives them through the production path
// chain.c → attrib.c → adapter.c → engine. Proves: §4 attribution recovers the
// signer, the OP_RETURN decode + fold mint a name via commit→claim, and ownership
// resolves — the whole new consensus-relevant layer, offline and deterministic.
#include "sm.h"
#include "chain.h"
#include "adapter.h"
#include "attrib.h"
#include "sha256.h"
#include "ripemd160.h"
#include "db.h"
#include "indexer.h"
#include "txcheck.h"
#include "mempool.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int secp_pubkey(const uint8_t priv[32], uint8_t pub33[33]);
int secp_ecdsa_sign(const uint8_t priv[32], const uint8_t h[32], uint8_t r32[32], uint8_t s32[32]);

static void sha256_1(const uint8_t *d, size_t n, uint8_t o[32]) { SHA256_CTX c; sha256_init(&c); sha256_update(&c, d, (unsigned)n); sha256_final(&c, o); }
static void hash160(const uint8_t *d, size_t n, uint8_t o[20]) { uint8_t t[32]; sha256_1(d, n, t); ripemd160(t, 32, o); }
static void dsha(const uint8_t *d, size_t n, uint8_t o[32]) { uint8_t t[32]; sha256_1(d, n, t); sha256_1(t, 32, o); }

// minimal byte emit
static void p(uint8_t *b, int *l, const uint8_t *d, int n) { memcpy(b + *l, d, (size_t)n); *l += n; }
static void p1(uint8_t *b, int *l, int v) { b[(*l)++] = (uint8_t)v; }
static void pu32(uint8_t *b, int *l, uint32_t v) { for (int i = 0; i < 4; i++) p1(b, l, (v >> (8*i)) & 0xff); }
static void pu64(uint8_t *b, int *l, uint64_t v) { for (int i = 0; i < 8; i++) p1(b, l, (v >> (8*i)) & 0xff); }
static void pvar(uint8_t *b, int *l, uint64_t v) { if (v < 0xFD) p1(b, l, (int)v); else if (v <= 0xFFFF) { p1(b, l, 0xFD); p1(b, l, v & 0xff); p1(b, l, (v >> 8) & 0xff); } else { p1(b, l, 0xFE); pu32(b, l, (uint32_t)v); } }

// DER-encode (r,s) from 32-byte BE scalars (minimal), append SIGHASH_ALL byte.
static int der_encode(const uint8_t r[32], const uint8_t s[32], uint8_t out[80]) {
    int ri = 0; while (ri < 31 && r[ri] == 0) ri++; int rl = 32 - ri; const uint8_t *R = r + ri;
    int si = 0; while (si < 31 && s[si] == 0) si++; int sl = 32 - si; const uint8_t *S = s + si;
    int rpad = (R[0] & 0x80) ? 1 : 0, spad = (S[0] & 0x80) ? 1 : 0;
    int o = 0; out[o++] = 0x30; out[o++] = 2 + rl + rpad + 2 + sl + spad;
    out[o++] = 0x02; out[o++] = rl + rpad; if (rpad) out[o++] = 0x00; memcpy(out + o, R, (size_t)rl); o += rl;
    out[o++] = 0x02; out[o++] = sl + spad; if (spad) out[o++] = 0x00; memcpy(out + o, S, (size_t)sl); o += sl;
    out[o++] = 0x01;                                       // SIGHASH_ALL
    return o;
}

// Build a 1-input P2PKH tx. Output 0 = OP_RETURN(action) at `value`. Optional
// output 1 = P2PKH payment of `pay_val` to `pay_h160` (NULL to omit).
static int build_tx(const uint8_t priv[32], const uint8_t pub33[33], const uint8_t h160[20],
                    const uint8_t *action, int alen, uint64_t value,
                    const uint8_t *pay_h160, uint64_t pay_val,
                    const uint8_t prev_txid[32], uint32_t prev_vout,
                    uint8_t *out, int *out_len) {
    int n_out = pay_h160 ? 2 : 1;
    // scriptPubKeys
    uint8_t spk0[83]; int spk0l = 0; p1(spk0, &spk0l, 0x6A);     // OP_RETURN
    if (alen < 76) p1(spk0, &spk0l, alen); else { p1(spk0, &spk0l, 0x4C); p1(spk0, &spk0l, alen); }
    p(spk0, &spk0l, action, alen);
    uint8_t spk1[25]; int spk1l = 0;
    if (pay_h160) { p1(spk1, &spk1l, 0x76); p1(spk1, &spk1l, 0xA9); p1(spk1, &spk1l, 0x14); p(spk1, &spk1l, pay_h160, 20); p1(spk1, &spk1l, 0x88); p1(spk1, &spk1l, 0xAC); }
    // scriptCode for sighash = standard P2PKH of signer
    uint8_t sc[25]; int scl = 0; p1(sc, &scl, 0x76); p1(sc, &scl, 0xA9); p1(sc, &scl, 0x14); p(sc, &scl, h160, 20); p1(sc, &scl, 0x88); p1(sc, &scl, 0xAC);

    // sighash preimage: tx with vin0.scriptSig = scriptCode
    uint8_t b[1024]; int l = 0;
    pu32(b, &l, 1);                                        // version
    pvar(b, &l, 1);                                        // 1 input
    p(b, &l, prev_txid, 32); pu32(b, &l, prev_vout);
    pvar(b, &l, scl); p(b, &l, sc, scl);
    pu32(b, &l, 0xFFFFFFFF);                               // sequence
    pvar(b, &l, n_out);
    pu64(b, &l, value); pvar(b, &l, spk0l); p(b, &l, spk0, spk0l);
    if (pay_h160) { pu64(b, &l, pay_val); pvar(b, &l, spk1l); p(b, &l, spk1, spk1l); }
    pu32(b, &l, 0);                                        // locktime
    pu32(b, &l, 1);                                        // hashtype 4-byte LE SIGHASH_ALL
    uint8_t sighash[32]; dsha(b, l, sighash);

    // sign
    uint8_t r[32], s[32]; if (!secp_ecdsa_sign(priv, sighash, r, s)) return 0;
    uint8_t der[80]; int derl = der_encode(r, s, der);
    // scriptSig = push(der) push(pub33)
    uint8_t ss[200]; int ssl = 0; p1(ss, &ssl, derl); p(ss, &ssl, der, derl); p1(ss, &ssl, 33); p(ss, &ssl, pub33, 33);

    // final tx
    int o = 0;
    pu32(out, &o, 1);
    pvar(out, &o, 1);
    p(out, &o, prev_txid, 32); pu32(out, &o, prev_vout);
    pvar(out, &o, ssl); p(out, &o, ss, ssl);
    pu32(out, &o, 0xFFFFFFFF);
    pvar(out, &o, n_out);
    pu64(out, &o, value); pvar(out, &o, spk0l); p(out, &o, spk0, spk0l);
    if (pay_h160) { pu64(out, &o, pay_val); pvar(out, &o, spk1l); p(out, &o, spk1, spk1l); }
    pu32(out, &o, 0);
    *out_len = o;
    return 1;
}

// Wrap one tx in a real (non-AuxPoW) Dogecoin block. time is the only field we use.
static int build_block(const uint8_t *tx, int txlen, uint32_t time, uint8_t *out, int *out_len) {
    int o = 0;
    pu32(out, &o, 1);                                      // version (no 0x100 → no AuxPoW)
    memset(out + o, 0, 32); o += 32;                       // prev
    memset(out + o, 0, 32); o += 32;                       // merkle
    pu32(out, &o, time);
    pu32(out, &o, 0x1e0ffff0);                             // bits
    pu32(out, &o, 0);                                      // nonce
    pvar(out, &o, 1);                                      // 1 tx
    p(out, &o, tx, txlen);
    *out_len = o;
    return 1;
}

struct foldctx { SmState *s; };
static void fold_cb(void *u, const IdxTx *tx, uint32_t txindex) { idx_adapt_tx(((struct foldctx *)u)->s, tx, txindex); }

int chain_selftest(void) {
    int fail = 0;
    #define CK(c, m) do { if (c) printf("  ok   %s\n", m); else { printf("  FAIL %s\n", m); fail++; } } while (0)

    // key
    uint8_t priv[32]; for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(i + 1);
    uint8_t pub[33]; CK(secp_pubkey(priv, pub), "derive pubkey");
    uint8_t h160[20]; hash160(pub, 33, h160);

    // ── §4 attribution round-trip on a real signed tx (COMMIT carrier) ───────
    uint8_t prev[32]; memset(prev, 0x11, 32);
    uint8_t commit0[36]; int vl = 0; uint8_t pre[4] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT };
    memcpy(commit0, pre, 4); vl = 4; memset(commit0 + vl, 0x22, 32); vl += 32;
    uint8_t tx[1024]; int txl;
    CK(build_tx(priv, pub, h160, commit0, vl, 0, NULL, 0, prev, 0, tx, &txl), "build signed COMMIT tx");
    IdxAttr a; int st = idx_attribute(tx, (size_t)txl, 0, &a);
    CK(st == IDX_ATTR_FOUND, "§4 attribute(vin0) = FOUND on real signature");
    CK(memcmp(a.identity, h160, 20) == 0 && a.type == 0, "recovered identity == signer hash160 (P2PKH)");

    // ── commit→claim mints a name end-to-end ─────────────────────────────────
    SmState *s = sm_new(2);                                // ACTIVATION_HEIGHT = 2
    struct foldctx fc = { s };
    const char *name = "alice"; int nlen = 5;
    uint8_t salt[32]; memset(salt, 0x07, 32);
    uint8_t cm_in[32 + 8 + 20]; int ci = 0; memcpy(cm_in + ci, salt, 32); ci += 32; memcpy(cm_in + ci, name, nlen); ci += nlen; memcpy(cm_in + ci, h160, 20); ci += 20;
    uint8_t commitment[32]; sha256_1(cm_in, ci, commitment);

    // block @ height 2: COMMIT (opcode 0x01)
    uint8_t commit[40]; int cl = 0; uint8_t cpre[4] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT }; memcpy(commit, cpre, 4); cl = 4; memcpy(commit + cl, commitment, 32); cl += 32;
    uint8_t txc[1024]; int txcl; build_tx(priv, pub, h160, commit, cl, 0, NULL, 0, prev, 1, txc, &txcl);
    uint8_t blk2[2048]; int blk2l; build_block(txc, txcl, 1000, blk2, &blk2l);
    IdxBlockMeta m2; sm_begin_block(s, 2, 1000, 1);        // mtp=1000, rate=1 (floor)
    CK(idx_parse_block(blk2, (size_t)blk2l, &m2, fold_cb, &fc), "parse+fold COMMIT block");

    // block @ height 3: CLAIM (commit is now 1 block deep; opcode 0x02)
    uint8_t claim[80]; int kl = 0; uint8_t kpre[4] = { 0xFF, 0x50, 0x4E, SM_OP_CLAIM }; memcpy(claim, kpre, 4); kl = 4; memcpy(claim + kl, salt, 32); kl += 32; memcpy(claim + kl, name, nlen); kl += nlen;
    uint8_t prev2[32]; memset(prev2, 0x33, 32);
    uint8_t txk[1024]; int txkl; build_tx(priv, pub, h160, claim, kl, 1, NULL, 0, prev2, 0, txk, &txkl); // value=1 → 28d at floor rate
    uint8_t blk3[2048]; int blk3l; build_block(txk, txkl, 2000, blk3, &blk3l);
    IdxBlockMeta m3; sm_begin_block(s, 3, 2000, 1);
    CK(idx_parse_block(blk3, (size_t)blk3l, &m3, fold_cb, &fc), "parse+fold CLAIM block");

    CK(sm_owns(s, h160, "alice"), "commit→claim minted 'alice' to the signer");
    const SmNameRow *row = sm_lookup(s, "alice");
    CK(row && row->st == SM_OWNED, "'alice' is OWNED after claim");

    // ── DB projection round-trip: load(save(state)) reproduces the digest ─────
    uint8_t d_before[32]; sm_state_digest(s, d_before);
    sqlite3 *db = idx_db_open(":memory:");
    CK(db != NULL, "open in-memory projection db");
    idx_db_project(db, s);
    SmState *s2 = sm_new(2);
    idx_db_load_state(db, s2);
    uint8_t d_after[32]; sm_state_digest(s2, d_after);
    CK(memcmp(d_before, d_after, 32) == 0, "projection is lossless (digest survives save→load)");
    CK(sm_owns(s2, h160, "alice"), "restored state still owns 'alice'");
    idx_db_close(db); sm_free(s2);
    sm_free(s);

    // ── reorg rollback: replay from stored carrier blocks reverts byte-exactly ─
    // Fold the same commit→claim through the production shape (oracle-fed mtp/rate,
    // raw carrier blocks persisted), snapshot the digest after each block, roll
    // back to the commit, then refold the claim: both digests must return.
    {
        sqlite3 *rdb = idx_db_open(":memory:");
        OracleFeed *of = oracle_new();
        SmState *rs = sm_new(2);
        struct foldctx rfc = { rs };
        uint8_t d2[32], d3[32], dg[32];
        const uint8_t *blks[2] = { blk2, blk3 }; const int blens[2] = { blk2l, blk3l };
        for (int i = 0; i < 2; i++) {
            int64_t hh = 2 + i, mtp; uint64_t rate; IdxBlockMeta mm;
            oracle_for_height(of, hh, &mtp, &rate);
            sm_begin_block(rs, hh, mtp, rate);
            idx_parse_block(blks[i], (size_t)blens[i], &mm, fold_cb, &rfc);
            oracle_record(of, hh, mm.time, mm.coinbase_out_total, mm.block_bytes);
            idx_db_block_put(rdb, hh, mm.block_hash, mm.time, mm.coinbase_out_total, mm.block_bytes, mm.bits);
            idx_db_rawblock_put(rdb, hh, blks[i], (size_t)blens[i]);   // both are carrier blocks
            sm_state_digest(rs, i == 0 ? d2 : d3);
        }
        CK(sm_owns(rs, h160, "alice"), "oracle-fed fold owns 'alice' pre-rollback");
        CK(idx_sync_rollback(&rs, rdb, of, 2, 2), "rollback to height 2 (drop the claim)");
        sm_state_digest(rs, dg);
        CK(memcmp(dg, d2, 32) == 0, "rolled-back digest == post-commit digest");
        CK(!sm_owns(rs, h160, "alice"), "'alice' unowned after rollback");
        // refold the claim as the new branch would deliver it
        { int64_t mtp; uint64_t rate; IdxBlockMeta mm; struct foldctx c2 = { rs };
          oracle_for_height(of, 3, &mtp, &rate);
          sm_begin_block(rs, 3, mtp, rate);
          idx_parse_block(blk3, (size_t)blk3l, &mm, fold_cb, &c2);
          oracle_record(of, 3, mm.time, mm.coinbase_out_total, mm.block_bytes); }
        sm_state_digest(rs, dg);
        CK(memcmp(dg, d3, 32) == 0, "refolded digest == original post-claim digest");
        CK(sm_owns(rs, h160, "alice"), "'alice' owned again after refold");
        oracle_free(of); sm_free(rs); idx_db_close(rdb);
    }

    // ── epochs projection: owner_of(name @ height) over claim/transfer/lapse ──
    // The fold path feeds idx_db_epochs_update per ownership-relevant block; here
    // the same calls are made directly (the projection's input is the state, so a
    // transfer/lapse can be simulated by mutating it — no §3 market txs needed).
    {
        sqlite3 *edb = idx_db_open(":memory:");
        SmState *es = sm_new(2);
        struct foldctx efc = { es };
        idx_db_epochs_mark(edb, 0);                       // complete-history db
        IdxBlockMeta mm;
        sm_begin_block(es, 2, 1000, 1);
        idx_parse_block(blk2, (size_t)blk2l, &mm, fold_cb, &efc);
        idx_db_epochs_update(edb, es, 2);                 // commit block: no ownership change
        sm_begin_block(es, 3, 2000, 1);
        idx_parse_block(blk3, (size_t)blk3l, &mm, fold_cb, &efc);
        idx_db_epochs_update(edb, es, 3);                 // claim: alice → signer @ 3
        uint8_t o[20]; uint8_t ot;
        CK(idx_db_owner_at(edb, "alice", 5, 3, o, &ot) == 1 && memcmp(o, h160, 20) == 0,
           "epochs: owner_at(claim height) = claimer");
        CK(idx_db_owner_at(edb, "alice", 5, 2, o, &ot) == 0,
           "epochs: pre-claim height is known-unowned (complete history)");
        CK(idx_db_owner_at(edb, "ghost", 5, 3, o, &ot) == 0,
           "epochs: never-claimed name is unowned");
        // re-running the same diff at the same height derives nothing new (the
        // reorg-replay idempotency property)
        idx_db_epochs_update(edb, es, 3);
        CK(idx_db_owner_at(edb, "alice", 5, 3, o, &ot) == 1 && memcmp(o, h160, 20) == 0,
           "epochs: re-derivation is idempotent");
        // transfer at height 10 (mutate the state the way a §3 TRANSFER would)
        uint8_t newown[20]; memset(newown, 0xAB, 20);
        SmNameRow *er = sm_find_name(es, "alice");
        memcpy(er->owner, newown, 20);
        idx_db_epochs_update(edb, es, 10);
        CK(idx_db_owner_at(edb, "alice", 5, 9, o, &ot) == 1 && memcmp(o, h160, 20) == 0,
           "epochs: pre-transfer height resolves the OLD owner (§4.2)");
        CK(idx_db_owner_at(edb, "alice", 5, 10, o, &ot) == 1 && memcmp(o, newown, 20) == 0,
           "epochs: transfer height resolves the NEW owner");
        // lapse at height 20: the name leaves the state → a NULL (unowned) row
        sm_remove_name(es, sm_find_name(es, "alice"));
        idx_db_epochs_update(edb, es, 20);
        CK(idx_db_owner_at(edb, "alice", 5, 20, o, &ot) == 0, "epochs: lapsed height is unowned");
        CK(idx_db_owner_at(edb, "alice", 5, 19, o, &ot) == 1 && memcmp(o, newown, 20) == 0,
           "epochs: pre-lapse height still resolves");
        // reorg: rows above the fork vanish, history below it stands
        idx_db_block_prune_above(edb, 9);
        CK(idx_db_owner_at(edb, "alice", 5, 10, o, &ot) == 1 && memcmp(o, h160, 20) == 0,
           "epochs: reorg prune reverts to the pre-fork owner");
        idx_db_close(edb); sm_free(es);
    }

    printf(fail ? "\nchain selftest: %d FAILED\n" : "\nchain selftest: all passed\n", fail);
    return fail;
}

// ── relay mempool: stateless validation + pool semantics ─────────────────────
// A generic raw-tx emitter (no signing — txcheck never checks signatures, so
// these exercise the context-free rules with hand-crafted scripts).
static int raw_tx(uint8_t *out, int nin, const uint8_t (*prev)[36],
                  const uint8_t **ss, const int *ssn,
                  int nout, const int64_t *val, const uint8_t **spk, const int *spkn) {
    int o = 0; pu32(out, &o, 1); pvar(out, &o, (uint64_t)nin);
    for (int i = 0; i < nin; i++) { p(out, &o, prev[i], 36); pvar(out, &o, (uint64_t)ssn[i]); if (ssn[i]) p(out, &o, ss[i], ssn[i]); pu32(out, &o, 0xFFFFFFFF); }
    pvar(out, &o, (uint64_t)nout);
    for (int i = 0; i < nout; i++) { pu64(out, &o, (uint64_t)val[i]); pvar(out, &o, (uint64_t)spkn[i]); p(out, &o, spk[i], spkn[i]); }
    pu32(out, &o, 0);
    return o;
}

int mempool_selftest(void) {
    int fail = 0;
    #define CK(c, m) do { if (c) printf("  ok   %s\n", m); else { printf("  FAIL %s\n", m); fail++; } } while (0)
    mempool_reset();

    uint8_t priv[32]; for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(i + 2);
    uint8_t pub[33]; secp_pubkey(priv, pub);
    uint8_t h160[20]; hash160(pub, 33, h160);
    uint8_t payh[20]; memset(payh, 0x55, 20);
    uint8_t commit[36]; { uint8_t pre[4] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT }; memcpy(commit, pre, 4); memset(commit + 4, 0x22, 32); }
    char why[128];

    // valid tx: OP_RETURN carrier (value 0) + a P2PKH payment ≥ dust
    uint8_t prevA[32]; memset(prevA, 0xA1, 32);
    uint8_t tx1[1024]; int tx1l;
    build_tx(priv, pub, h160, commit, 36, 0, payh, 100000000ULL, prevA, 0, tx1, &tx1l);
    uint8_t txid1[32];
    CK(mempool_accept(tx1, (size_t)tx1l, txid1, why, sizeof why) == 1, "accept a valid tx");
    CK(mempool_has(txid1), "pool has it");
    CK(mempool_count() == 1, "pool count == 1");
    size_t gl = 0; uint8_t *gc = mempool_get_copy(txid1, &gl);
    CK(gc && gl == (size_t)tx1l && !memcmp(gc, tx1, gl), "get_copy returns exact bytes"); free(gc);
    CK(mempool_accept(tx1, (size_t)tx1l, txid1, why, sizeof why) == 0, "reject duplicate (already in pool)");

    // conflicting tx: same input outpoint, different output → same prevout, new txid
    uint8_t tx2[1024]; int tx2l; uint8_t txid2[32];
    build_tx(priv, pub, h160, commit, 36, 0, payh, 200000000ULL, prevA, 0, tx2, &tx2l);
    CK(mempool_accept(tx2, (size_t)tx2l, txid2, why, sizeof why) == 0 && !strcmp(why, "conflicting input (double-spend)"),
       "reject conflicting input");

    // dust output (pay 1 koinu < 0.01)
    uint8_t prevB[32]; memset(prevB, 0xB2, 32);
    uint8_t txd[1024]; int txdl;
    build_tx(priv, pub, h160, commit, 36, 0, payh, 1ULL, prevB, 0, txd, &txdl);
    CK(txcheck_stateless(txd, (size_t)txdl, why, sizeof why) == 0 && !strcmp(why, "dust output"), "reject dust output");

    // coinbase (null prevout)
    uint8_t zero32[32] = { 0 };
    uint8_t txcb[1024]; int txcbl;
    build_tx(priv, pub, h160, commit, 36, 0, payh, 100000000ULL, zero32, 0xFFFFFFFF, txcb, &txcbl);
    CK(txcheck_stateless(txcb, (size_t)txcbl, why, sizeof why) == 0 && !strcmp(why, "coinbase tx"), "reject coinbase tx");

    // output value out of range (carrier output value > MAX_MONEY)
    uint8_t prevC[32]; memset(prevC, 0xC3, 32);
    uint8_t txv[1024]; int txvl;
    build_tx(priv, pub, h160, commit, 36, (uint64_t)TX_MAX_MONEY + 1, payh, 100000000ULL, prevC, 0, txv, &txvl);
    CK(txcheck_stateless(txv, (size_t)txvl, why, sizeof why) == 0 && !strcmp(why, "output value out of range"),
       "reject output value out of range");

    // hand-built raw txs for script-level rules
    uint8_t p2pkh[25]; { int l = 0; p1(p2pkh, &l, 0x76); p1(p2pkh, &l, 0xA9); p1(p2pkh, &l, 0x14); p(p2pkh, &l, payh, 20); p1(p2pkh, &l, 0x88); p1(p2pkh, &l, 0xAC); }
    const uint8_t *p2pkh_spk[1] = { p2pkh }; int p2pkh_len[1] = { 25 }; int64_t okval[1] = { 100000000 };
    uint8_t pin[36]; memset(pin, 0xD4, 36);
    uint8_t pushss[2] = { 0x01, 0xAB };                         // push 1 byte — push-only
    const uint8_t *ss1[1] = { pushss }; int ssn1[1] = { 2 };
    uint8_t raw[4096];

    // oversize scriptSig (> 1650)
    static uint8_t bigss[1651]; bigss[0] = 0x4D; bigss[1] = 0x60; bigss[2] = 0x06;  // PUSHDATA2 len 1648
    { const uint8_t (*prev)[36] = (const uint8_t(*)[36])pin; const uint8_t *bs[1] = { bigss }; int bl[1] = { 1651 };
      int n = raw_tx(raw, 1, prev, bs, bl, 1, okval, p2pkh_spk, p2pkh_len);
      CK(txcheck_stateless(raw, (size_t)n, why, sizeof why) == 0 && !strcmp(why, "scriptSig too large"), "reject oversize scriptSig"); }

    // non-push scriptSig (contains OP_RETURN)
    { const uint8_t (*prev)[36] = (const uint8_t(*)[36])pin; uint8_t np[1] = { 0x6A }; const uint8_t *nss[1] = { np }; int nl[1] = { 1 };
      int n = raw_tx(raw, 1, prev, nss, nl, 1, okval, p2pkh_spk, p2pkh_len);
      CK(txcheck_stateless(raw, (size_t)n, why, sizeof why) == 0 && !strcmp(why, "scriptSig not push-only"), "reject non-push scriptSig"); }

    // nonstandard scriptPubKey (bare OP_1)
    { const uint8_t (*prev)[36] = (const uint8_t(*)[36])pin; uint8_t bad[1] = { 0x51 }; const uint8_t *bspk[1] = { bad }; int blen[1] = { 1 };
      int n = raw_tx(raw, 1, prev, ss1, ssn1, 1, okval, bspk, blen);
      CK(txcheck_stateless(raw, (size_t)n, why, sizeof why) == 0 && !strcmp(why, "nonstandard scriptPubKey"), "reject nonstandard scriptPubKey"); }

    // duplicate prevout within the tx
    { uint8_t dup[2][36]; memset(dup[0], 0xE5, 36); memcpy(dup[1], dup[0], 36);
      const uint8_t *dss[2] = { pushss, pushss }; int dssn[2] = { 2, 2 };
      int n = raw_tx(raw, 2, dup, dss, dssn, 1, okval, p2pkh_spk, p2pkh_len);
      CK(txcheck_stateless(raw, (size_t)n, why, sizeof why) == 0 && !strcmp(why, "duplicate input"), "reject duplicate input"); }

    // block-fold eviction: a confirmed tx (and a pool tx it conflicts with) leaves
    mempool_reset();
    mempool_accept(tx1, (size_t)tx1l, txid1, why, sizeof why);
    { IdxTx pt; idx_tx_parse(tx1, (size_t)tx1l, &pt);
      mempool_on_confirmed_tx(pt.txid, &pt); idx_tx_free(&pt); }
    CK(!mempool_has(txid1) && mempool_count() == 0, "confirmed tx evicted from pool");

    mempool_accept(tx1, (size_t)tx1l, txid1, why, sizeof why);       // tx1 spends prevA
    { IdxTx pc; idx_tx_parse(tx2, (size_t)tx2l, &pc);                // tx2 also spends prevA
      mempool_on_confirmed_tx(pc.txid, &pc); idx_tx_free(&pc); }     // confirming tx2 evicts tx1
    CK(!mempool_has(txid1) && mempool_count() == 0, "conflicting pool tx evicted when its input confirms");

    mempool_reset();
    printf(fail ? "\nmempool selftest: %d FAILED\n" : "\nmempool selftest: all passed\n", fail);
    #undef CK
    return fail;
}

// Write the commit→claim scenario as two real binary block files (block 0 =
// COMMIT, block 1 = CLAIM) into `dir`, for an end-to-end `index` CLI test
// (run with activation_height 0). Returns 0 on success.
static int write_file(const char *path, const uint8_t *b, int n) { FILE *f = fopen(path, "wb"); if (!f) return 1; fwrite(b, 1, (size_t)n, f); fclose(f); return 0; }
int chain_mkblocks(const char *dir) {
    uint8_t priv[32]; for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(i + 1);
    uint8_t pub[33]; if (!secp_pubkey(priv, pub)) return 1;
    uint8_t h160[20]; hash160(pub, 33, h160);
    const char *name = "alice"; int nlen = 5;
    uint8_t salt[32]; memset(salt, 0x07, 32);
    uint8_t cm_in[60]; int ci = 0; memcpy(cm_in, salt, 32); ci = 32; memcpy(cm_in + ci, name, nlen); ci += nlen; memcpy(cm_in + ci, h160, 20); ci += 20;
    uint8_t commitment[32]; sha256_1(cm_in, ci, commitment);
    uint8_t prev[32]; memset(prev, 0x11, 32);

    uint8_t commit[40]; int cl = 0; uint8_t cpre[4] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT }; memcpy(commit, cpre, 4); cl = 4; memcpy(commit + cl, commitment, 32); cl += 32;
    uint8_t txc[1024]; int txcl; build_tx(priv, pub, h160, commit, cl, 0, NULL, 0, prev, 1, txc, &txcl);
    uint8_t blk0[2048]; int blk0l; build_block(txc, txcl, 1000, blk0, &blk0l);

    uint8_t claim[80]; int kl = 0; uint8_t kpre[4] = { 0xFF, 0x50, 0x4E, SM_OP_CLAIM }; memcpy(claim, kpre, 4); kl = 4; memcpy(claim + kl, salt, 32); kl += 32; memcpy(claim + kl, name, nlen); kl += nlen;
    uint8_t prev2[32]; memset(prev2, 0x33, 32);
    uint8_t txk[1024]; int txkl; build_tx(priv, pub, h160, claim, kl, 1, NULL, 0, prev2, 0, txk, &txkl);
    uint8_t blk1[2048]; int blk1l; build_block(txk, txkl, 2000, blk1, &blk1l);

    char p0[1024], p1[1024]; snprintf(p0, sizeof p0, "%s/blk0.bin", dir); snprintf(p1, sizeof p1, "%s/blk1.bin", dir);
    if (write_file(p0, blk0, blk0l) || write_file(p1, blk1, blk1l)) return 1;
    printf("wrote %s and %s (signer hash160=", p0, p1);
    for (int i = 0; i < 20; i++) printf("%02x", h160[i]); printf(")\n");
    return 0;
}
