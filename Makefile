# PepeNet headless indexer (C reference)
#
# Links the protocol reference fold (protocol/impls/c/src, a pinned submodule of
# namespace-protocol) as its consensus engine — compile-in-place, so the daemon
# folds byte-for-byte identically to the executable spec. The only new
# consensus-relevant code is this repo's adapter (real Dogecoin block/tx ->
# abstract SmTx) + §4 attribution.
#
#   make            build ./indexerd (builds vendored libsecp first)
#   make test       build + run the selftest
#   make clean
#
# First checkout: git submodule update --init --recursive
#
# EC crypto is the audited vendored libsecp256k1 (verify + ECMH only — indexerd
# ships NO secret-key curve math). The self-rolled secp256k1.c from the protocol
# repo is deliberately NOT compiled here; protocol/shim/secp_shim.c re-implements
# its header on libsecp.

CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wno-unused-parameter
SMDIR   := protocol/impls/c/src
SHIM    := protocol/shim/secp_shim.c
SECPDIR := vendor/secp256k1
SECPLIB := build/secp/lib/libsecp256k1.a

# Curve-free fold + canonical SHA-256 digest (the consensus core).
ENGINE_CORE := fold decode oracle digest state lease market claim trade bitmap \
               preblock sha256 ripemd160 gen harness
ENGINE_SRCS := $(addprefix $(SMDIR)/,$(addsuffix .c,$(ENGINE_CORE)))

# Curve-dependent engine bits (ECMH published digest). attrib.c/attrib_curve.c are
# NOT linked — the daemon has its own real-tx attribution (src/attrib.c).
ENGINE_CURVE := ecmh
ENGINE_CURVE_SRCS := $(addprefix $(SMDIR)/,$(addsuffix .c,$(ENGINE_CURVE)))

# Indexer sources.
IDX_SRCS := src/main.c src/attrib.c src/adapter.c src/oracle_feed.c \
            src/db.c src/chain.c src/base58.c src/sync.c src/pow.c src/serve_store.c \
            src/txcheck.c src/mempool.c $(SHIM) src/test_chain.c

SQLITE_CFLAGS := $(shell pkg-config --cflags sqlite3 2>/dev/null)
SQLITE_LIBS   := $(shell pkg-config --libs sqlite3 2>/dev/null || echo -lsqlite3)

# Order matters: both the protocol repo and libsecp ship a header literally named
# "secp256k1.h". Engine files include theirs *quoted* (own-dir-first, = SMDIR), so
# putting the libsecp include dir ahead only affects ANGLE includes — secp_shim.c's
# `#include <secp256k1.h>` then unambiguously gets the vendored library.
INCLUDES := -Isrc -I$(SECPDIR)/include -I$(SMDIR)
LIBS     := $(SECPLIB) $(SQLITE_LIBS) -lpthread

ALL_SRCS := $(ENGINE_SRCS) $(ENGINE_CURVE_SRCS) $(IDX_SRCS)

all: indexerd

# Vendored libsecp256k1, built once via its own CMake (static, minimal modules).
$(SECPLIB): $(SECPDIR)/CMakeLists.txt
	cmake -S $(SECPDIR) -B build/secp -DCMAKE_BUILD_TYPE=Release \
	      -DBUILD_SHARED_LIBS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF \
	      -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
	      -DSECP256K1_BUILD_CTIME_TESTS=OFF -DSECP256K1_BUILD_EXAMPLES=OFF \
	      -DSECP256K1_INSTALL=OFF -DSECP256K1_ENABLE_MODULE_ECDH=ON \
	      -DSECP256K1_ENABLE_MODULE_RECOVERY=OFF -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=OFF \
	      -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=OFF -DSECP256K1_ENABLE_MODULE_MUSIG=OFF \
	      -DSECP256K1_ENABLE_MODULE_ELLSWIFT=OFF >/dev/null
	cmake --build build/secp -j >/dev/null

indexerd: $(ALL_SRCS) $(wildcard src/*.h) $(wildcard $(SMDIR)/*.h) $(SECPLIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) -o $@ $(ALL_SRCS) $(LIBS)

test: indexerd
	./indexerd selftest

clean:
	rm -rf indexerd indexerd.san build

.PHONY: all test clean

# ── extra test suites (storage / sync / codec) ────────────────────────────────
# Appended targets; `test` above is untouched and still runs ./indexerd selftest.
# Each suite links the same objects as indexerd with src/main.c swapped out for
# the suite's own main (test_chain.c stays in — sync.c's selftest path needs it).
TEST_SRCS := $(filter-out src/main.c,$(ALL_SRCS))

test_db: $(TEST_SRCS) src/test_db.c $(SECPLIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) -o $@ $(TEST_SRCS) src/test_db.c $(LIBS)

test_sync: $(TEST_SRCS) src/test_sync.c $(SECPLIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) -o $@ $(TEST_SRCS) src/test_sync.c $(LIBS)

test_codec: $(TEST_SRCS) src/test_codec.c $(SECPLIB)
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) -o $@ $(TEST_SRCS) src/test_codec.c $(LIBS)

# test_serve covers src/serve_store.c — the peer-facing getheaders/getblocks/
# getdata cache + the blockstage mailbox — which no other suite touches. It
# needs only serve_store.c and sqlite, so it links its own tiny composition
# rather than the full indexer object set.
test_serve: src/test_serve.c src/serve_store.c src/serve_store.h
	$(CC) $(CFLAGS) $(INCLUDES) $(SQLITE_CFLAGS) -o $@ src/test_serve.c src/serve_store.c $(SQLITE_LIBS)

# `make check` = the four suites. Run `make test` for the shipped selftest.
# Every suite runs even if an earlier one fails; the target fails if any did.
check: test_db test_sync test_codec test_serve
	@rc=0; for t in ./test_db ./test_sync ./test_codec ./test_serve; do \
	  echo "=== $$t ==="; $$t || rc=1; done; \
	if [ $$rc -eq 0 ]; then echo "check: ALL PASSED"; else echo "check: FAILED"; fi; exit $$rc

check-clean:
	rm -f test_db test_sync test_codec test_serve

.PHONY: check check-clean
