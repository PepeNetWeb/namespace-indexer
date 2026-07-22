// PepeNet headless indexer — CLI entry.
//
// The state machine is the protocol-sm fold (../../protocol-sm/impls/c), linked
// as the consensus engine. This binary adds the chain side the reference omits:
// real Dogecoin block/tx decode + §4 attribution (the adapter), a sqlite
// projection of the fold state, and a P2P sync loop.
#include "sm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "indexer.h"
#include "pow.h"

int chain_selftest(void);                 // test_chain.c
int mempool_selftest(void);               // test_chain.c (relay mempool + txcheck)
int chain_mkblocks(const char *dir);      // test_chain.c (offline `index` test fixtures)

static void hex32(const uint8_t b[32], char out[65]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[64] = 0;
}
static int eqhex(const uint8_t b[32], const char *want) {
    char got[65]; hex32(b, got); return strcmp(got, want) == 0;
}

// ── engine-link + shim conformance against the reference goldens ──────────────
static int cmd_selftest(void) {
    int fail = 0;
    #define EXPECT(cond, msg) do { if (cond) { printf("  ok   %s\n", msg); } \
        else { printf("  FAIL %s\n", msg); fail++; } } while (0)

    // 1. The fold + canonical SHA-256 digest reproduce the reference action stream
    //    (proves the engine is linked & folding byte-identically in this build).
    uint8_t in[32], st[32];
    sm_generate(42, 2000, 0, in, st, NULL, NULL, NULL);
    // Digests re-pinned 2026-07-20: 0xFF 'P' 'N' universal prefix (PepeNet).
    // Goldens = impls/c `./sm random 42 2000` (the fuzz stream embeds the
    // prefix, so any prefix skew between this link and the reference forks
    // input_digest immediately).
    EXPECT(eqhex(in, "a83f34b1c18398d2e50724b4e32de118417162a80876b84689264bcc91a49bef"),
           "sm_generate(42,2000) input_digest matches reference");
    EXPECT(eqhex(st, "94ca7666442ee768c9c9352c1b1f94a39050430fca0665b0752ae9286d9fbdfd"),
           "sm_generate(42,2000) state_digest matches reference");

    // 2. Empty-state digests (canonical + ECMH). The ECMH anchor exercises the
    //    libsecp shim (identity/hash-to-curve/add) and pins it to the §13.2 golden.
    SmState *s = sm_new(1);
    uint8_t d[32], e[32];
    sm_state_digest(s, d);
    sm_state_ecmh(s, e);
    // (Empty-state goldens are prefix-independent; these two were stale from
    // before the 2026-07-20 re-pin — refreshed to the impls/c selftest prints.)
    EXPECT(eqhex(d, "226d258381e8c6f6264d6cfefc96f111f60ef7815432aac16ba6887fbb768409"),
           "empty_state_digest matches reference");
    EXPECT(eqhex(e, "053f61e599084024c9acd6a3127057ea5de001829225590ea2b175c5506b5c55"),
           "empty_state_ecmh matches reference (libsecp shim)");
    sm_free(s);

    printf("\n-- end-to-end chain pipeline (parse → §4 attribute → fold) --\n");
    fail += chain_selftest();

    printf("\n-- relay mempool (context-free tx validation + pool) --\n");
    fail += mempool_selftest();

    printf("\n-- proof-of-work primitives (scrypt / compact / Digishield) --\n");
    { int pf = idx_pow_selftest();
      if (pf) fail += pf; else printf("  ok   RFC 7914 scrypt vector + compact round-trips + Digishield\n"); }

    printf(fail ? "\nselftest: %d FAILED\n" : "\nselftest: ALL PASSED\n", fail);
    return fail ? 1 : 0;
}

static int usage(const char *p) {
    fprintf(stderr,
      "usage: %s <command> [args]\n"
      "  selftest                 engine-link + shim conformance vs reference goldens\n"
      "  ecmh                     print the §13.2 ECMH primitive vectors (combined golden)\n"
      "  sync   <coin> <db> [peers|auto] [activation]  connect over P2P and index the chain (confirmed-only)\n"
      "  crawl  <coin> <db> [max_dials] [host:port,...]  explore the chain graph, classify peers by agent\n"
      "  serve  <coin> <db> [port] [host:port,...]  run as a pepenet chain peer (serve headers/blocks, gossip)\n"
      "  resolve <db> <name>      print the current owner (hash160) of a name\n"
      "  owned  <db> <hash160hex> list names owned by an address\n"
      "  digest <db>              print height, live §3.4 rate, and the state digest\n"
      "  refold <db>              rebuild the fold from local blocks under current rules\n"
      "  watch  <db> <addr|h160>  register a wallet address for UTXO tracking (before funding!)\n"
      "  index  <blockfile>       fold a raw block file (hex or binary) — offline\n",
      p);
    return 2;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage(argv[0]);
    const char *cmd = argv[1];
    if (!strcmp(cmd, "selftest")) return cmd_selftest();
    if (!strcmp(cmd, "ecmh"))     return ecmh_cmd();
    if (!strcmp(cmd, "mkblocks")) return argc > 2 ? chain_mkblocks(argv[2]) : usage(argv[0]);
    if (!strcmp(cmd, "sync") || !strcmp(cmd, "resolve") || !strcmp(cmd, "owned") ||
        !strcmp(cmd, "digest") || !strcmp(cmd, "index") ||
        !strcmp(cmd, "watch") || !strcmp(cmd, "refold") || !strcmp(cmd, "crawl") ||
        !strcmp(cmd, "serve") || !strcmp(cmd, "weigh"))
        return indexer_main(argc, argv);
    return usage(argv[0]);
}
