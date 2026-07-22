// §3.2 mandatory commit→claim. COMMIT is recorded inline in fold.c; CLAIM mints
// here. Every CLAIM MUST be backed by a live matching commit in a STRICTLY
// earlier block (commit_height < claim_height — ≥1 block deep; no naked claims,
// no FCFS fallback). Contests resolve by the priority tuple
// (claim_height, commit_height, tx_index): a later block never displaces an
// earlier holder; within one block a smaller commit_height wins (tx_index the
// final tie-break), implemented as same-block displacement off the claim scratch.
#include "sm.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SmClaimWin *find_scratch(SmState *s, const char *name) {
    for (int i = 0; i < s->n_claimsc; i++)
        if (strcmp(s->claimsc[i].name, name) == 0) return &s->claimsc[i];
    return NULL;
}

static SmClaimWin *add_scratch(SmState *s, const char *name, int64_t ch, uint32_t ti, const uint8_t owner[20]) {
    if (s->n_claimsc == s->cap_claimsc) {
        int nc = s->cap_claimsc ? s->cap_claimsc * 2 : 16;
        SmClaimWin *p = realloc(s->claimsc, (size_t)nc * sizeof(SmClaimWin));
        s->claimsc = p; s->cap_claimsc = nc;
    }
    SmClaimWin *w = &s->claimsc[s->n_claimsc++];
    memset(w, 0, sizeof(*w));
    snprintf(w->name, sizeof(w->name), "%s", name);
    w->commit_height = ch; w->commit_tx_index = ti; memcpy(w->owner, owner, 20);
    return w;
}

void sm_op_claim(SmState *s, SmTxCtx *cx, const SmAction *a) {
    if (!sm_name_valid(a->name, a->name_len)) return;

    // commitment = SHA-256(salt ‖ name ‖ author_hash160) (§3.2 author-bound).
    uint8_t want[32]; SHA256_CTX h; sha256_init(&h);
    sha256_update(&h, a->salt, 32);
    sha256_update(&h, (const uint8_t *)a->name, a->name_len);
    sha256_update(&h, cx->actor, 20);
    sha256_final(&h, want);

    // earliest live commit in a STRICTLY earlier block (preblock already pruned
    // any expired ones, so a present row is live at this MTP).
    int found = 0; int64_t best_ch = 0; uint32_t best_ti = 0;
    for (int i = 0; i < s->n_commits; i++) {
        const SmCommit *c = &s->commits[i];
        if (c->commit_height < cx->height && memcmp(c->commitment, want, 32) == 0) {
            if (!found || c->commit_height < best_ch ||
                (c->commit_height == best_ch && c->tx_index < best_ti)) {
                found = 1; best_ch = c->commit_height; best_ti = c->tx_index;
            }
        }
    }
    if (!found) return;                                  // no ≥1-deep commit → drop (no FCFS)
    if (!sm_lease_covers_day(cx->car_value, cx->rate)) return;   // must buy ≥1 day

    SmNameRow *row  = sm_find_name(s, a->name);
    SmClaimWin *scr = find_scratch(s, a->name);

    if (scr) {
        // Name was minted THIS block. A smaller backing-commit priority
        // (commit_height, then commit tx_index — §3.2's tuple, NOT claim chain
        // order) displaces the provisional winner — but only while it is still
        // that winner's fresh OWNED mint (an intervening same-block move/list locks it in).
        int higher_priority = best_ch < scr->commit_height ||
            (best_ch == scr->commit_height && best_ti < scr->commit_tx_index);
        if (higher_priority && row && row->st == SM_OWNED &&
            memcmp(row->owner, scr->owner, 20) == 0) {
            memcpy(row->owner, cx->actor, 20); row->owner_type = cx->actor_type;
            row->lease_expiry = cx->mtp;                 // reset, re-buy below
            SmNameRow *rr = row; sm_waterfill(s, cx->mtp, cx->rate, cx->car_value, &rr, 1);
            sm_bump_mutation(s, cx->actor, cx->height);
            memcpy(scr->owner, cx->actor, 20); scr->commit_height = best_ch; scr->commit_tx_index = best_ti;
            s->ev[SM_EV_CLAIM_DISPLACE]++;
        }
        return;
    }

    if (row) return;                                     // already owned (earlier block) → drop

    SmNameRow *r = sm_add_name(s, a->name, a->name_len);
    memcpy(r->owner, cx->actor, 20); r->owner_type = cx->actor_type;
    r->st = SM_OWNED; r->lease_expiry = cx->mtp;         // 0 remaining; water-fill buys the lease
    SmNameRow *rr = r; sm_waterfill(s, cx->mtp, cx->rate, cx->car_value, &rr, 1);
    sm_bump_mutation(s, cx->actor, cx->height);
    add_scratch(s, a->name, best_ch, best_ti, cx->actor);
    s->ev[SM_EV_CLAIM_MINT]++;
}
