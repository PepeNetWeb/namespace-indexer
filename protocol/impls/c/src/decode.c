// §1/§2/§3 wire payload codec — the byte layer of the strict, fail-closed parse.
//
// The base fold (fold.c) consumes already-decoded SmCarriers; this file is the
// part a real indexer does FIRST: turn an OP_RETURN payload (the bytes of the
// single minimal push, §1) into ACTION / POST / IGNORE, deterministically and
// byte-for-byte identically across indexers (§0 "indexers MUST agree byte-for-byte
// on validity"). `sm fuzz` feeds millions of random + grammar-perturbed payloads
// through sm_decode_payload and cross-checks the result, so any parser/bounds
// divergence between languages surfaces here. The codec is pinned in
// SPEC-conformance.md §9; the field layouts mirror §2's registry exactly.
#include "sm.h"
#include <string.h>

// ── little-endian field readers/writers ──────────────────────────────────────
static uint32_t rd32(const uint8_t *b) { uint32_t v = 0; for (int i = 0; i < 4; i++) v |= (uint32_t)b[i] << (8*i); return v; }
static uint64_t rd64(const uint8_t *b) { uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8*i); return v; }
static uint64_t rd5 (const uint8_t *b) { uint64_t v = 0; for (int i = 0; i < 5; i++) v |= (uint64_t)b[i] << (8*i); return v; }
static void     wr32(uint8_t *b, uint32_t v) { for (int i = 0; i < 4; i++) b[i] = (uint8_t)(v >> (8*i)); }
static void     wr64(uint8_t *b, uint64_t v) { for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8*i)); }
static void     wr5 (uint8_t *b, uint64_t v) { for (int i = 0; i < 5; i++) b[i] = (uint8_t)(v >> (8*i)); }

// ── RFC 3629 strict UTF-8 (§1 text-post demux) ───────────────────────────────
// Reject overlong encodings, surrogates U+D800..U+DFFF, and code points > U+10FFFF.
// A whole-payload test: a payload valid up front but invalid later is NOT UTF-8.
int sm_valid_utf8(const uint8_t *p, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t c = p[i];
        if (c < 0x80) { i++; continue; }                       // ASCII
        int n; uint32_t cp, lo, hi;
        if      ((c & 0xE0) == 0xC0) { n = 1; cp = c & 0x1F; lo = 0x80;    hi = 0x7FF; }
        else if ((c & 0xF0) == 0xE0) { n = 2; cp = c & 0x0F; lo = 0x800;   hi = 0xFFFF; }
        else if ((c & 0xF8) == 0xF0) { n = 3; cp = c & 0x07; lo = 0x10000; hi = 0x10FFFF; }
        else return 0;                                         // 0x80..0xBF lead, or 0xF8+ → invalid
        if (i + (size_t)n >= len) return 0;                    // truncated: need n continuation bytes in-buffer
        for (int k = 1; k <= n; k++) {
            uint8_t cc = p[i + (size_t)k];
            if ((cc & 0xC0) != 0x80) return 0;                 // not a continuation byte
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (cp < lo || cp > hi) return 0;                      // overlong or out of range
        if (cp >= 0xD800 && cp <= 0xDFFF) return 0;            // surrogate half
        i += (size_t)n + 1;
    }
    return 1;
}

// ── action decode (the part after the 4-byte 0xFF 'P' 'N' opcode header) ─────
// b = payload+4, blen = len-4. Returns 1 with `a` filled (a->op set), else 0.
static int decode_action(const uint8_t *b, size_t blen, uint8_t op, SmAction *a) {
    memset(a, 0, sizeof *a);
    a->op = op;
    switch (op) {
    case SM_OP_VOTE_UP:
    case SM_OP_VOTE_DOWN:
        if (blen != 36) return 0;                              // txid(32) + vout(4)
        memcpy(a->target_txid, b, 32); a->target_vout = rd32(b + 32);
        return 1;
    case SM_OP_COMMIT:
        if (blen != 32) return 0;
        memcpy(a->commitment, b, 32);
        return 1;
    case SM_OP_CLAIM: {                                        // salt(32) + name(1..32)
        if (blen < 33 || blen > 64) return 0;
        memcpy(a->salt, b, 32);
        size_t nl = blen - 32;
        if (!sm_name_valid((const char *)(b + 32), nl)) return 0;
        memcpy(a->name, b + 32, nl); a->name[nl] = 0; a->name_len = (uint8_t)nl;
        return 1;
    }
    case SM_OP_RENEW:                                          // 0=all | 5=all-safe | 6..76=selective
        if (blen == 0) { a->has_anchor = 0; a->flags_len = 0; return 1; }
        if (blen == 5) { a->has_anchor = 1; a->anchor = rd5(b); a->flags_len = 0; return 1; }
        if (blen >= 6 && blen <= 76) {
            a->has_anchor = 1; a->anchor = rd5(b);
            size_t fl = blen - 5;                              // 1..71
            memcpy(a->flags, b + 5, fl); a->flags_len = (uint8_t)fl;
            return 1;
        }
        return 0;
    case SM_OP_TRANSFER:                                       // 20=all | 26..76=selective
        if (blen == 20) { memcpy(a->addr, b, 20); a->has_anchor = 0; return 1; }
        if (blen >= 26 && blen <= 76) {
            memcpy(a->addr, b, 20);
            a->has_anchor = 1; a->anchor = rd5(b + 20);
            size_t fl = blen - 25;                             // 1..51
            memcpy(a->flags, b + 25, fl); a->flags_len = (uint8_t)fl;
            return 1;
        }
        return 0;
    case SM_OP_SELL: {                                         // price(8)+window(4)+name(1..32)
        if (blen < 13 || blen > 44) return 0;
        a->price = rd64(b); a->window = rd32(b + 8);
        size_t nl = blen - 12;
        if (!sm_name_valid((const char *)(b + 12), nl)) return 0;
        memcpy(a->name, b + 12, nl); a->name[nl] = 0; a->name_len = (uint8_t)nl;
        return 1;
    }
    case SM_OP_RESERVE:
    case SM_OP_SETTLE:
    case SM_OP_PAY: {                                          // name(1..32)
        if (blen < 1 || blen > 32) return 0;
        if (!sm_name_valid((const char *)b, blen)) return 0;
        memcpy(a->name, b, blen); a->name[blen] = 0; a->name_len = (uint8_t)blen;
        return 1;
    }
    case SM_OP_RELEASE:                                        // anchor(5)+flags(1..71)
        if (blen < 6 || blen > 76) return 0;
        a->has_anchor = 1; a->anchor = rd5(b);
        { size_t fl = blen - 5; memcpy(a->flags, b + 5, fl); a->flags_len = (uint8_t)fl; }
        return 1;
    case SM_OP_DECORATE:                                       // raw TLV records (fold parses, fail-closed)
        if (blen > SM_DEC_MAX) return 0;                       // ≤ 76 in practice (len ≤ 80)
        memcpy(a->dec, b, blen); a->dec_len = (uint8_t)blen;
        return 1;
    case SM_OP_SELL_TO: {                                      // price(8)+buyer(20)+name(1..32)
        if (blen < 29 || blen > 60) return 0;
        a->price = rd64(b); memcpy(a->addr, b + 8, 20);
        size_t nl = blen - 28;
        if (!sm_name_valid((const char *)(b + 28), nl)) return 0;
        memcpy(a->name, b + 28, nl); a->name[nl] = 0; a->name_len = (uint8_t)nl;
        return 1;
    }
    case SM_OP_AS:                                             // index(1)
        if (blen != 1) return 0;
        a->as_index = b[0];
        return 1;
    case SM_OP_TRADE: {                                        // idxA(1)+idxB(1)+ nameA,nameB
        if (blen < 5) return 0;                                // 2 idx + "a,b" minimum
        a->idx_a = b[0]; a->idx_b = b[1];
        const uint8_t *body = b + 2; size_t bl = blen - 2;
        int comma = -1, count = 0;
        for (size_t i = 0; i < bl; i++) if (body[i] == 0x2C) { count++; comma = (int)i; }
        if (count != 1) return 0;                              // exactly one ','
        size_t la = (size_t)comma, lb = bl - (size_t)comma - 1;
        if (!sm_name_valid((const char *)body, la)) return 0;
        if (!sm_name_valid((const char *)(body + comma + 1), lb)) return 0;
        memcpy(a->name,   body, la);            a->name[la]   = 0; a->name_len   = (uint8_t)la;
        memcpy(a->name_b, body + comma + 1, lb); a->name_b[lb] = 0; a->name_b_len = (uint8_t)lb;
        return 1;
    }
    default:
        return 0;                                             // opcode 0x00 or > 0x0F
    }
}

void sm_decode_payload(const uint8_t *payload, size_t len, uint64_t value, SmCarrier *car) {
    memset(&car->act, 0, sizeof car->act);
    car->post_len = 0;
    car->kind = SM_CAR_IGNORE;

    // §1 action recognition: prefix 0xFF 'P' 'N' + opcode 0x01..0x0F.
    if (len >= 4 && payload[0] == 0xFF && payload[1] == 0x50 && payload[2] == 0x4E) {
        uint8_t op = payload[3];
        if (decode_action(payload + 4, len - 4, op, &car->act)) car->kind = SM_CAR_ACTION;
        else                                                    car->kind = SM_CAR_IGNORE;  // malformed action (0xFF ⇒ not a post)
        return;
    }
    // §1 text-post demux: whole-payload strict UTF-8 with a burn (value > 0).
    if (value > 0 && len >= 1 && sm_valid_utf8(payload, len)) {
        car->kind = SM_CAR_POST;
        size_t pl = len > SM_POST_MAX ? SM_POST_MAX : len;
        memcpy(car->post, payload, pl); car->post_len = (uint8_t)pl;
        return;
    }
    car->kind = SM_CAR_IGNORE;
}

// ── canonical action encoder (inverse of decode_action; grammar-aware fuzz) ──
size_t sm_encode_action(const SmAction *a, uint8_t out[80]) {
    out[0] = 0xFF; out[1] = 0x50; out[2] = 0x4E; out[3] = a->op;
    uint8_t *b = out + 4;
    switch (a->op) {
    case SM_OP_VOTE_UP:
    case SM_OP_VOTE_DOWN:
        memcpy(b, a->target_txid, 32); wr32(b + 32, a->target_vout); return 40;
    case SM_OP_COMMIT:
        memcpy(b, a->commitment, 32); return 36;
    case SM_OP_CLAIM:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        memcpy(b, a->salt, 32); memcpy(b + 32, a->name, a->name_len); return 36 + a->name_len;
    case SM_OP_RENEW:
        if (!a->has_anchor && a->flags_len == 0) return 4;                 // all
        if (a->has_anchor && a->flags_len == 0) { wr5(b, a->anchor); return 9; }   // all-safe
        if (a->has_anchor && a->flags_len >= 1 && a->flags_len <= 71) {
            wr5(b, a->anchor); memcpy(b + 5, a->flags, a->flags_len); return 9 + a->flags_len;
        }
        return 0;
    case SM_OP_TRANSFER:
        memcpy(b, a->addr, 20);
        if (!a->has_anchor) return 24;                                     // all
        if (a->flags_len >= 1 && a->flags_len <= 51) {
            wr5(b + 20, a->anchor); memcpy(b + 25, a->flags, a->flags_len); return 29 + a->flags_len;
        }
        return 0;
    case SM_OP_SELL:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        wr64(b, a->price); wr32(b + 8, a->window); memcpy(b + 12, a->name, a->name_len); return 16 + a->name_len;
    case SM_OP_RESERVE:
    case SM_OP_SETTLE:
    case SM_OP_PAY:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        memcpy(b, a->name, a->name_len); return 4 + a->name_len;
    case SM_OP_RELEASE:
        if (a->flags_len < 1 || a->flags_len > 71) return 0;
        wr5(b, a->anchor); memcpy(b + 5, a->flags, a->flags_len); return 9 + a->flags_len;
    case SM_OP_DECORATE:
        if (a->dec_len > SM_DEC_MAX) return 0;
        memcpy(b, a->dec, a->dec_len); return 4 + a->dec_len;
    case SM_OP_SELL_TO:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        wr64(b, a->price); memcpy(b + 8, a->addr, 20); memcpy(b + 28, a->name, a->name_len); return 32 + a->name_len;
    case SM_OP_AS:
        b[0] = a->as_index; return 5;
    case SM_OP_TRADE:
        if (a->name_len < 1 || a->name_len > 32 || a->name_b_len < 1 || a->name_b_len > 32) return 0;
        b[0] = a->idx_a; b[1] = a->idx_b;
        memcpy(b + 2, a->name, a->name_len);
        b[2 + a->name_len] = 0x2C;
        memcpy(b + 2 + a->name_len + 1, a->name_b, a->name_b_len);
        return 7 + a->name_len + a->name_b_len;   // header(4)+idxA+idxB + A + ',' + B
    default:
        return 0;
    }
}
