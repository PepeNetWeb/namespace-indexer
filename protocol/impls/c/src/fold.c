// The §6 fold driver: begin_block + the per-tx carrier walk.
//
// apply_tx is a single forward pass over a tx's OP_RETURN carriers in vout
// order. It tracks the acting identity (vin[0] by default; re-pointed by AS
// markers, §3.10/Rule 1b) and a pending DECORATE buffer that binds to the next
// body (§1). Votes, posts, COMMIT and DECORATE are handled inline here; the
// heavier identity/market/trade ops dispatch to their modules.
#include "sm.h"
#include <string.h>

// ── synthetic per-tx id (pinned): txid = height(8 LE) ‖ txindex(4 LE) ‖ 0… ────
static void synth_txid(uint8_t out[32], int64_t height, uint32_t txindex) {
    memset(out, 0, 32);
    uint64_t h = (uint64_t)height;
    for (int i = 0; i < 8; i++) out[i]     = (uint8_t)(h >> (8 * i));
    for (int i = 0; i < 4; i++) out[8 + i] = (uint8_t)(txindex >> (8 * i));
}

// Does `who` control ≥1 name here? A listed/offered/reserved name is still the
// seller's (§3.7), so it counts. Used by the DECORATE name-ownership gate (§1).
static int owns_any(SmState *s, const uint8_t who[20]) {
    for (int i = 0; i < s->n_names; i++) {
        SmNameRow *r = &s->names[i];
        if (r->st == SM_OWNED) { if (memcmp(r->owner, who, 20) == 0) return 1; }
        else                   { if (memcmp(r->seller, who, 20) == 0) return 1; }
    }
    return 0;
}

// ── pending DECORATE records (bind to the next body, §1) ─────────────────────
typedef struct { uint8_t bytes[SM_DEC_MAX]; uint8_t len; } PendRec;
#define MAX_PEND SM_MAX_PEND_DECOR      // §1 pending-record cap (sm.h, pinned all 7 impls)
typedef struct { PendRec recs[MAX_PEND]; int n; } Pending;

// Parse one DECORATE carrier's TLV records (fail-closed on overrun) and append.
static void decorate_buffer(Pending *p, const SmAction *a) {
    size_t i = 0, len = a->dec_len;
    while (i + 3 <= len) {
        size_t rlen = (size_t)a->dec[i + 1] | ((size_t)a->dec[i + 2] << 8);
        size_t total = 3 + rlen;
        if (i + total > len) break;                 // len overruns payload → drop the rest
        if (p->n < MAX_PEND && total <= SM_DEC_MAX) {
            memcpy(p->recs[p->n].bytes, &a->dec[i], total);
            p->recs[p->n].len = (uint8_t)total;
            p->n++;
        }
        i += total;
    }
}

// Bind buffered records to the post at (txid, vout) iff `author` controls a name.
static void decorate_bind(SmState *s, Pending *p, const uint8_t txid[32], uint32_t vout,
                          const uint8_t *author /* NULL = anonymous */) {
    if (p->n && author && owns_any(s, author))
        for (int i = 0; i < p->n; i++)
            sm_decor_add(s, txid, vout, p->recs[i].bytes, p->recs[i].len);
    p->n = 0;                                        // bound or dropped — always clear
}

// ── driver ────────────────────────────────────────────────────────────────────

void sm_begin_block(SmState *s, int64_t height, int64_t mtp, uint64_t rate) {
    sm_preblock(s, height, mtp);                     // transitions BEFORE the block's txs (§6)
    s->cur_height = height; s->cur_mtp = mtp; s->cur_rate = rate;
    s->n_claimsc = 0;                                // §3.2 claim scratch is per-block
}

void sm_apply_tx(SmState *s, const SmTx *tx) {
    SmTxCtx cx;
    memset(&cx, 0, sizeof(cx));
    cx.tx = tx; cx.height = s->cur_height; cx.mtp = s->cur_mtp; cx.rate = s->cur_rate;
    cx.txindex = tx->txindex;
    synth_txid(cx.txid, s->cur_height, tx->txindex);

    // acting identity = vin[0] by default; valid iff it signs SIGHASH_ALL (Rule 3).
    if (tx->n_inputs > 0 && tx->in_sighash_all[0]) {
        memcpy(cx.actor, tx->inputs[0].h160, 20);
        cx.actor_type = tx->inputs[0].type;
        cx.actor_valid = 1;
    }

    Pending pend; pend.n = 0;

    for (int c = 0; c < tx->n_carriers; c++) {
        const SmCarrier *car = &tx->carriers[c];
        cx.car_value = car->value; cx.car_vout = car->vout;

        if (car->kind == SM_CAR_IGNORE) continue;

        if (car->kind == SM_CAR_POST) {
            if (car->value == 0) continue;           // zero-value → ignore (§1)
            // A post is consensus-irrelevant display data (not folded); its only
            // on-chain effect is to anchor co-located DECORATE records (§1). The
            // author is the acting identity (or anonymous), gating the binding.
            const uint8_t *author = cx.actor_valid ? cx.actor : NULL;
            decorate_bind(s, &pend, cx.txid, car->vout, author);
            continue;
        }

        // ACTION carrier.
        const SmAction *a = &car->act;
        const int op = a->op;

        // forward-only activation gate (§3.0): a gated op below the height drops.
        if (op >= SM_OP_FIRST_GATED && s->cur_height < (int64_t)s->activation_height)
            continue;

        if (op == SM_OP_AS) {                        // re-point acting identity (Rule 1b)
            pend.n = 0;                              // AS flushes the pending DECORATE buffer
            uint8_t k = a->as_index;
            if (k < tx->n_inputs && tx->in_sighash_all[k]) {
                memcpy(cx.actor, tx->inputs[k].h160, 20);
                cx.actor_type = tx->inputs[k].type;
                cx.actor_valid = 1;
            } else {
                cx.actor_valid = 0;                  // ⊥ → this segment's actions drop
                s->ev[SM_EV_AS_DROP]++;
            }
            continue;
        }

        if (op == SM_OP_DECORATE) { decorate_buffer(&pend, a); continue; }

        if (op == SM_OP_VOTE_UP || op == SM_OP_VOTE_DOWN) {
            if (!cx.actor_valid) continue;           // needs an attributable vin[0] (§3.8)
            if (car->value < (uint64_t)SM_DUST_FLOOR) continue;   // zero-weight → drop
            sm_vote_add(s, a->target_txid, a->target_vout,
                        op == SM_OP_VOTE_UP, car->value);
            continue;
        }

        // TRADE is attributed to its OWN named inputs (idxA/idxB), not the acting
        // identity, so it dispatches regardless of cx.actor_valid (§3.10).
        if (op == SM_OP_TRADE) { sm_op_trade(s, &cx, a); continue; }

        if (!cx.actor_valid) continue;               // every other op acts as the acting identity

        switch (op) {
        case SM_OP_COMMIT:
            sm_commit_add(s, a->commitment, s->cur_height, tx->txindex, s->cur_mtp);
            break;
        case SM_OP_CLAIM:    sm_op_claim(s, &cx, a);    break;
        case SM_OP_RENEW:    sm_op_renew(s, &cx, a);    break;
        case SM_OP_TRANSFER: sm_op_transfer(s, &cx, a); break;
        case SM_OP_SELL:     sm_op_sell(s, &cx, a);     break;
        case SM_OP_RESERVE:  sm_op_reserve(s, &cx, a);  break;
        case SM_OP_SETTLE:   sm_op_settle(s, &cx, a);   break;
        case SM_OP_RELEASE:  sm_op_release(s, &cx, a);  break;
        case SM_OP_SELL_TO:  sm_op_sell_to(s, &cx, a);  break;
        case SM_OP_PAY:      sm_op_pay(s, &cx, a);      break;
        default: break;                              // unknown opcode → ignore
        }
    }
    // end of tx: any unbound DECORATE records are orphans (dropped).
}
