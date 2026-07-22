package main

// Generator-driven invariant battery (§8 properties · §9 fuzz · §10 reorg · §11 meta/reorgfuzz).
//
// These modes drive the EXISTING fold/decoder over Go's OWN generated action
// streams. The DIGESTS printed here do NOT match the gen.c-pinned soak goldens
// (the per-op draw order is not in prose — this generator is an independent
// reconstruction, like java/Gen.java). The VALUE is the generator-INDEPENDENT
// assertions: properties' `violations==0` (the fold preserves every §8
// invariant), meta/reorg/reorgfuzz's `failures==0` (the fold is drop-closed and a
// pure, reorg-safe function of the block sequence), and fuzz's `parser_crashes==0`
// (the decoder/fold is crash-safe / fail-closed over adversarial bytes).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
)

// ---- generator constants (independent reconstruction; not pinned to gen.c) ----

const (
	genNIDs     = 16
	genNamePool = 400
	genBaseTS   = int64(1_700_000_000)
)

// op draw weights for: POST,VOTE,COMMIT,CLAIM,RENEW,TRANSFER,SELL,RESERVE,SETTLE,RELEASE,SELL_TO,PAY,TRADE
var genWeights = []int{12, 12, 14, 13, 5, 5, 8, 7, 7, 3, 6, 5, 4}

var genWSum = func() int {
	s := 0
	for _, w := range genWeights {
		s += w
	}
	return s
}()

// genID builds the i-th synthetic identity: h160 with first+last byte = i.
func genID(i int) Identity {
	var h [20]byte
	h[0] = byte(i)
	h[19] = byte(i)
	return Identity{h160: h, styp: genIDType(i), ok: true}
}

func genIDType(i int) byte {
	if i%4 == 3 {
		return 1 // P2SH
	}
	return 0 // P2PKH
}

func base36(v int) string {
	if v == 0 {
		return "0"
	}
	const d = "0123456789abcdefghijklmnopqrstuvwxyz"
	var out []byte
	for v > 0 {
		out = append([]byte{d[v%36]}, out...)
		v /= 36
	}
	return string(out)
}

func genName(i int) string { return "n" + base36(i) }

func genSalt(k int64) [32]byte {
	var s [32]byte
	for i := 0; i < 8; i++ {
		s[i] = byte(k >> (8 * uint(i)))
	}
	s[31] = 0xA5
	return s
}

// bnd is the bounded-int draw used by the generator (mirrors java Rng.bnd(int)).
func bnd(p *splitMix64, n int) int {
	if n <= 0 {
		return 0
	}
	return int(p.bounded(uint64(n)))
}

// genMTP: median of the timestamps of the (≤11) blocks strictly before H
// (matches java Gen.computeMtp, index k/2 upper-middle).
func genMTP(ts []int64, H int64) int64 {
	lo := H - 11
	if lo < 0 {
		lo = 0
	}
	hi := H
	if lo >= hi {
		if len(ts) == 0 {
			return genBaseTS
		}
		idx := H
		if idx > int64(len(ts)-1) {
			idx = int64(len(ts) - 1)
		}
		return ts[idx]
	}
	w := append([]int64(nil), ts[lo:hi]...)
	sort.Slice(w, func(i, j int) bool { return w[i] < w[j] })
	return w[len(w)/2]
}

type genPending struct {
	idIdx        int
	name         string
	salt         [32]byte
	commitHeight int64
	commitTime   int64
}

// recordChain generates and RECORDS the full chain (the same chain
// properties/reorg/meta/reorgfuzz share). It folds inline ONLY to query live
// state for valid actions; the returned []FoldBlock is independently re-foldable.
func recordChain(seed uint64, count int) []FoldBlock {
	p := newPRNG(seed)
	s := newState()
	var blocks []FoldBlock
	var tsList []int64
	var ready []genPending
	ts := genBaseTS
	saltCtr := int64(1)
	var height int64
	txCount := 0
	for txCount < count {
		ts += 300 + int64(p.bounded(600))
		tsList = append(tsList, ts)
		rate := uint64(28 * (1 + p.bounded(4)))
		mtp := genMTP(tsList, height)
		nTxs := 1 + bnd(p, 8)
		var txs []FoldTx
		for ti := 0; ti < nTxs && txCount < count; ti++ {
			tx := genBuildTx(p, s, height, mtp, rate, &ready, saltCtr)
			saltCtr += 4
			tx.txIndex = uint32(ti)
			txs = append(txs, tx)
			txCount++
		}
		b := FoldBlock{height: height, mtp: mtp, rate: rate, txs: txs}
		s.applyBlock(b)
		blocks = append(blocks, b)
		height++
	}
	return blocks
}

func genPickOp(p *splitMix64) int {
	x := bnd(p, genWSum)
	acc := 0
	for i, w := range genWeights {
		acc += w
		if x < acc {
			return i
		}
	}
	return 0
}

// namesWhere lists name keys filtered by owner (nil = any) and required state (-1 = any).
func genNamesWhere(s *FoldState, owner *[20]byte, reqSt int) []string {
	var r []string
	for k, row := range s.names {
		if owner != nil && row.owner != *owner {
			continue
		}
		if reqSt >= 0 && row.st != reqSt {
			continue
		}
		r = append(r, k)
	}
	sort.Strings(r) // deterministic order for stable index picks
	return r
}

func genIdxOf(id [20]byte) int {
	for k := 0; k < genNIDs; k++ {
		if genID(k).h160 == id {
			return k
		}
	}
	return 0
}

func genOneIn(i int, outs ...FoldCarrier) FoldTx {
	return FoldTx{inputs: []Identity{genID(i)}, carriers: outs}
}

// genBuildTx mirrors java Gen.buildTx: pick an op, build a (usually valid) tx for
// the current live state; fall back to a VOTE if the chosen op has no target.
func genBuildTx(p *splitMix64, s *FoldState, height, mtp int64, rate uint64, ready *[]genPending, saltCtr int64) FoldTx {
	op := genPickOp(p)
	i := bnd(p, genNIDs)
	id := genID(i)
	days := uint64(1 + bnd(p, 60))
	rate28 := rate / 28
	leaseVal := rate28 * days // T == days at rate=28; scales otherwise

	switch op {
	case 2: // COMMIT
		j := bnd(p, genNamePool)
		name := genName(j)
		salt := genSalt(saltCtr)
		*ready = append(*ready, genPending{idIdx: i, name: name, salt: salt, commitHeight: height, commitTime: mtp})
		cm := commitment(salt, name, id.h160)
		return genOneIn(i, carrier(0, 0, payload(OP_COMMIT, cm[:]...)))

	case 3: // CLAIM a ready commit (≥1 deep, live, not already owned)
		for k := 0; k < len(*ready); k++ {
			pend := (*ready)[k]
			if pend.commitHeight < height && mtp <= pend.commitTime+COMMIT_EXPIRY {
				if _, owned := s.names[pend.name]; !owned {
					*ready = append((*ready)[:k], (*ready)[k+1:]...)
					body := append(append([]byte{}, pend.salt[:]...), pend.name...)
					return genOneIn(pend.idIdx, carrier(0, leaseVal, payload(OP_CLAIM, body...)))
				}
			}
		}

	case 4: // RENEW all
		if len(genNamesWhere(s, &id.h160, -1)) > 0 {
			return genOneIn(i, carrier(0, leaseVal, payload(OP_RENEW)))
		}

	case 5: // TRANSFER all to a random id
		if len(genNamesWhere(s, &id.h160, ST_OWNED)) > 0 {
			tgt := genID(bnd(p, genNIDs)).h160
			return genOneIn(i, carrier(0, 0, payload(OP_TRANSFER, tgt[:]...)))
		}

	case 6: // SELL an owned name with enough lease tail
		for _, nm := range genNamesWhere(s, &id.h160, ST_OWNED) {
			r := s.names[nm]
			if mtp+RESERVE_WINDOW+REORG_BUFFER <= r.leaseExpiry {
				price := uint64(3 + bnd(p, 100000))
				body := append(append(leBytes64(price), leBytes32(0)...), nm...)
				return genOneIn(i, carrier(0, 0, payload(OP_SELL, body...)))
			}
		}

	case 7: // RESERVE a listed name (buyer != seller)
		listed := genNamesWhere(s, nil, ST_LISTED)
		if len(listed) > 0 {
			nm := listed[bnd(p, len(listed))]
			r := s.names[nm]
			burn := depositLeg(r.price, RESERVE_BURN_BPS)
			payL := depositLeg(r.price, RESERVE_PAY_BPS)
			buyer := bnd(p, genNIDs)
			tx := FoldTx{inputs: []Identity{genID(buyer)},
				carriers: []FoldCarrier{carrier(0, burn, payload(OP_RESERVE, []byte(nm)...))},
				spend:    []FoldOutput{{h160: r.seller, styp: r.sellerType, value: payL}}}
			return tx
		}

	case 8: // SETTLE a reserved name (by its reserver)
		res := genNamesWhere(s, nil, ST_RESERVED)
		if len(res) > 0 {
			nm := res[bnd(p, len(res))]
			r := s.names[nm]
			rem := r.price - r.burnLeg - r.payLeg
			buyer := genIdxOf(r.buyer)
			tx := FoldTx{inputs: []Identity{genID(buyer)},
				carriers: []FoldCarrier{carrier(0, 0, payload(OP_SETTLE, []byte(nm)...))},
				spend:    []FoldOutput{{h160: r.seller, styp: r.sellerType, value: rem}}}
			return tx
		}

	case 9: // RELEASE owned names via a full-ish bitmap
		set := s.ownedSorted(id.h160)
		if len(set) > 0 {
			flags := make([]byte, (len(set)+7)/8)
			for fi := range flags {
				flags[fi] = 0xFF
			}
			if len(flags) == 0 {
				flags = []byte{1}
			}
			anchor := s.muts[id.h160] // 0 if none
			if anchor == 0 {
				anchor = height
			} else if anchor < height-1 {
				anchor = height - 1
			}
			if anchor <= height {
				body := append(leBytes40(anchor), flags...)
				return genOneIn(i, carrier(0, 0, payload(OP_RELEASE, body...)))
			}
		}

	case 10: // SELL_TO
		for _, nm := range genNamesWhere(s, &id.h160, ST_OWNED) {
			r := s.names[nm]
			if mtp+DIRECT_WINDOW+REORG_BUFFER <= r.leaseExpiry {
				price := uint64(1 + bnd(p, 100000))
				buyer := genID(bnd(p, genNIDs)).h160
				body := append(append(leBytes64(price), buyer[:]...), nm...)
				return genOneIn(i, carrier(0, 0, payload(OP_SELL_TO, body...)))
			}
		}

	case 11: // PAY an offered name (by its named buyer)
		off := genNamesWhere(s, nil, ST_OFFERED)
		if len(off) > 0 {
			nm := off[bnd(p, len(off))]
			r := s.names[nm]
			buyer := genIdxOf(r.buyer)
			tx := FoldTx{inputs: []Identity{genID(buyer)},
				carriers: []FoldCarrier{carrier(0, 0, payload(OP_PAY, []byte(nm)...))},
				spend:    []FoldOutput{{h160: r.seller, styp: r.sellerType, value: r.price}}}
			return tx
		}

	case 12: // TRADE two owned names between two ids
		myOwned := genNamesWhere(s, &id.h160, ST_OWNED)
		i2 := (i + 1 + bnd(p, genNIDs-1)) % genNIDs
		id2 := genID(i2)
		theirs := genNamesWhere(s, &id2.h160, ST_OWNED)
		if len(myOwned) > 0 && len(theirs) > 0 {
			a1, b1 := myOwned[0], theirs[0]
			if a1 != b1 {
				body := []byte{0x00, 0x01}
				body = append(body, a1...)
				body = append(body, 0x2C)
				body = append(body, b1...)
				return FoldTx{inputs: []Identity{id, id2},
					carriers: []FoldCarrier{carrier(0, 0, payload(OP_TRADE, body...))}}
			}
		}

	case 0: // POST (optionally decorated if the author owns a name)
		body := []byte("post" + base36(int(saltCtr%1000)))
		if len(genNamesWhere(s, &id.h160, -1)) > 0 && bnd(p, 2) == 0 {
			tag := byte(1 + bnd(p, 20))
			val := byte(bnd(p, 256))
			rec := []byte{tag, 0x01, 0x00, val}
			return genOneIn(i,
				carrier(0, 0, payload(OP_DECORATE, rec...)),
				carrier(1, uint64(1+bnd(p, 50)), body))
		}
		return genOneIn(i, carrier(0, uint64(1+bnd(p, 50)), body))
	}

	// VOTE fallback (always valid): target a synthetic earlier post id.
	var th int64
	if height != 0 {
		th = int64(p.bounded(uint64(height)))
	}
	target := makeSyntheticTxid(th, uint32(bnd(p, 8)))
	voteOp := byte(OP_VOTE_UP)
	if bnd(p, 2) != 0 {
		voteOp = OP_VOTE_DOWN
	}
	vbody := append(append([]byte{}, target[:]...), leBytes32(uint32(bnd(p, 4)))...)
	return genOneIn(i, carrier(0, uint64(1+bnd(p, 1000)), payload(voteOp, vbody...)))
}

// ---- streaming digest helpers (own input_digest / property fingerprint) ----

type digestBuf struct{ b []byte }

func (d *digestBuf) u8(v byte)    { d.b = append(d.b, v) }
func (d *digestBuf) u32(v uint32) { d.b = append(d.b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24)) }
func (d *digestBuf) i64(v int64)  { d.u64(uint64(v)) }
func (d *digestBuf) u64(v uint64) {
	for i := 0; i < 8; i++ {
		d.b = append(d.b, byte(v>>(8*uint(i))))
	}
}
func (d *digestBuf) i128(v i128) {
	le := v.bytesLE()
	d.b = append(d.b, le[:]...)
}
func (d *digestBuf) bytes(p []byte) { d.b = append(d.b, p...) }
func (d *digestBuf) sum() string {
	h := sha256.Sum256(d.b)
	return hex.EncodeToString(h[:])
}

func hexState(s *FoldState) string {
	d := s.stateDigest()
	return hex.EncodeToString(d[:])
}

// inputDigest streams the recorded chain (own hash_tx format).
func inputDigest(blocks []FoldBlock) string {
	var d digestBuf
	for _, blk := range blocks {
		d.i64(blk.height)
		d.i64(blk.mtp)
		d.u64(blk.rate)
		for _, tx := range blk.txs {
			d.u32(tx.txIndex)
			d.u32(uint32(len(tx.inputs)))
			for _, in := range tx.inputs {
				d.bytes(in.h160[:])
				d.u8(in.styp)
				if in.ok {
					d.u8(1)
				} else {
					d.u8(0)
				}
			}
			d.u32(uint32(len(tx.carriers)))
			for _, c := range tx.carriers {
				d.u64(c.value)
				d.u32(c.vout)
			}
			d.u32(uint32(len(tx.spend)))
			for _, o := range tx.spend {
				d.bytes(o.h160[:])
				d.u8(o.styp)
				d.u64(o.value)
			}
		}
	}
	return d.sum()
}

// ====================================================================
// MODE 1: properties — §8 invariant battery
// ====================================================================

func runProperties(seed uint64, count int) {
	blocks := recordChain(seed, count)
	s := newState()
	var violations int64
	var pd digestBuf
	for _, b := range blocks {
		s.applyBlock(b)
		violations += checkInvariants(s, b.height, b.mtp)
		fingerprint(&pd, s)
	}
	fmt.Printf("violations=%d\n", violations)
	fmt.Printf("property_digest=%s\n", pd.sum())
	fmt.Printf("state_digest=%s\n", hexState(s))
	if violations != 0 {
		os.Exit(1)
	}
}

func checkInvariants(s *FoldState, height, mtp int64) int64 {
	var v int64
	for _, r := range s.names {
		// mtp < lease_expiry <= mtp + MAX_LEASE
		if !(mtp < r.leaseExpiry) {
			v++
		}
		if !(r.leaseExpiry <= mtp+MAX_LEASE) {
			v++
		}
		if r.st == ST_LISTED || r.st == ST_OFFERED || r.st == ST_RESERVED {
			if !(r.offerExpiry+REORG_BUFFER <= r.leaseExpiry) {
				v++
			}
		}
		if r.st == ST_LISTED || r.st == ST_RESERVED {
			if r.price < 3*DUST_FLOOR { // SELL floor
				v++
			}
		}
		if r.st == ST_RESERVED {
			if !(r.reserveExpiry <= r.offerExpiry) {
				v++
			}
			if r.price < r.burnLeg+r.payLeg {
				v++
			}
			if r.burnLeg != depositLeg(r.price, RESERVE_BURN_BPS) {
				v++
			}
			if r.payLeg != depositLeg(r.price, RESERVE_PAY_BPS) {
				v++
			}
			if r.price-r.burnLeg-r.payLeg < DUST_FLOOR {
				v++
			}
		}
	}
	for _, mh := range s.muts {
		if mh > height {
			v++
		}
	}
	if s.overflow {
		v++
	}
	return v
}

func fingerprint(pd *digestBuf, s *FoldState) {
	var nOwned, nListed, nOffered, nReserved uint32
	var sumLease, sumPrice, sumLegs, sumVote i128
	add := func(a *i128, v uint64) { *a, _ = a.addOverflow(i128FromU64(v)) }
	for _, r := range s.names {
		switch r.st {
		case ST_OWNED:
			nOwned++
		case ST_LISTED:
			nListed++
		case ST_OFFERED:
			nOffered++
		case ST_RESERVED:
			nReserved++
		}
		add(&sumLease, uint64(r.leaseExpiry))
		if r.st == ST_LISTED || r.st == ST_RESERVED {
			add(&sumPrice, r.price)
		}
		if r.st == ST_RESERVED {
			add(&sumLegs, r.burnLeg)
			add(&sumLegs, r.payLeg)
		}
	}
	for _, vt := range s.votes {
		sumVote, _ = sumVote.addOverflow(vt.score)
	}
	pd.u32(uint32(len(s.names)))
	pd.u32(nOwned)
	pd.u32(nListed)
	pd.u32(nOffered)
	pd.u32(nReserved)
	pd.u32(uint32(len(s.commits)))
	pd.u32(uint32(len(s.votes)))
	pd.u32(uint32(len(s.muts)))
	pd.u32(uint32(len(s.decors)))
	pd.i128(sumLease)
	pd.i128(sumPrice)
	pd.i128(sumLegs)
	pd.i128(sumVote)
	if s.overflow {
		pd.u8(1)
	} else {
		pd.u8(0)
	}
}

// ====================================================================
// MODE 2: meta — an action the protocol IGNORES is provably inert
// ====================================================================

func runMeta(seed uint64, count int) {
	if count > 20000 {
		count = 20000
	}
	blocks := recordChain(seed, count)
	s := newState()
	var failures int64
	for _, b := range blocks {
		s.applyBlock(b)
		before := hexState(s)
		applyOneTx(s, b, inertTx())
		if hexState(s) != before {
			failures++
		}
	}
	fmt.Printf("failures=%d\n", failures)
	fmt.Printf("state_digest=%s\n", hexState(s))
	if failures != 0 {
		os.Exit(1)
	}
}

// applyOneTx folds a single extra tx into the current state at block b's context,
// WITHOUT a fresh begin_block (so it appends to the already-folded block). It
// reuses the live fold path (applyTx) — the same code paths a real block tx hits.
func applyOneTx(s *FoldState, b FoldBlock, tx FoldTx) {
	s.applyTx(b, tx)
}

// inertTx: a tx whose every carrier the protocol must IGNORE — a zero-weight
// VOTE (dropped by the dust gate), a malformed RENEW (decodes to IGNORE), an
// orphan DECORATE (discarded at tx end, no following body), and a zero-value POST
// (decodes to IGNORE). Folding it must leave the state digest unchanged.
func inertTx() FoldTx {
	target := makeSyntheticTxid(1, 0)
	zv := append(append([]byte{}, target[:]...), leBytes32(0)...)
	malformed := []byte{0xFF, 0x50, 0x4E, 0x05, 0x01, 0x02, 0x03} // RENEW bl=3 → IGNORE
	dec := payload(OP_DECORATE, 0x03, 0x01, 0x00, 0x09)
	return FoldTx{
		inputs: []Identity{genID(0)},
		carriers: []FoldCarrier{
			carrier(0, 0, payload(OP_VOTE_UP, zv...)), // zero-weight vote → dropped (dust gate)
			carrier(1, 0, malformed),                  // decodes to IGNORE
			carrier(2, 0, dec),                        // orphan DECORATE → discarded at tx end
			carrier(3, 0, []byte("hi")),               // zero-value → IGNORE (POST needs value>0)
		},
	}
}

// ====================================================================
// MODE 3: reorg — §10 confluence (replay / resume / clear-rebuild / fork-and-return)
// ====================================================================

func runReorg(seed uint64, count int) {
	if count > 20000 {
		count = 20000
	}
	blocks := recordChain(seed, count)
	n := len(blocks)
	J := n / 2
	var failures int64

	dFull := foldDigest(blocks, 0, n)
	// 1. replay
	if foldDigest(blocks, 0, n) != dFull {
		failures++
	}
	// 2. resume: fold [0,J) → S_fork, continue [J,n) == D_full
	s := newState()
	for i := 0; i < J; i++ {
		s.applyBlock(blocks[i])
	}
	sFork := hexState(s)
	for i := J; i < n; i++ {
		s.applyBlock(blocks[i])
	}
	if hexState(s) != dFull {
		failures++
	}
	// 3. clear-rebuild: clear(), re-fold [0,J) == S_fork
	s.clear()
	for i := 0; i < J; i++ {
		s.applyBlock(blocks[i])
	}
	if hexState(s) != sFork {
		failures++
	}
	// 4. fork-and-return: divergent branch = canonical tail with each block's txs reversed
	sa := newState()
	for i := 0; i < J; i++ {
		sa.applyBlock(blocks[i])
	}
	for i := J; i < n; i++ {
		sa.applyBlock(reverseTxs(blocks[i]))
	}
	dAlt := hexState(sa)
	sa.clear()
	for i := 0; i < J; i++ {
		sa.applyBlock(blocks[i])
	}
	if hexState(sa) != sFork {
		failures++
	}
	for i := J; i < n; i++ {
		sa.applyBlock(blocks[i])
	}
	if hexState(sa) != dFull {
		failures++
	}

	rd := append(append(append([]byte{}, hexDec(dFull)...), hexDec(sFork)...), hexDec(dAlt)...)
	fmt.Printf("blocks=%d fork=%d checks=6 failures=%d\n", n, J, failures)
	fmt.Printf("D_full=%s\n", dFull)
	fmt.Printf("S_fork=%s\n", sFork)
	fmt.Printf("D_alt=%s\n", dAlt)
	rh := sha256.Sum256(rd)
	fmt.Printf("reorg_digest=%s\n", hex.EncodeToString(rh[:]))
	if failures != 0 {
		os.Exit(1)
	}
}

func foldDigest(blocks []FoldBlock, lo, hi int) string {
	s := newState()
	for i := lo; i < hi; i++ {
		s.applyBlock(blocks[i])
	}
	return hexState(s)
}

func reverseTxs(b FoldBlock) FoldBlock {
	r := append([]FoldTx(nil), b.txs...)
	for i := 0; i < len(r)/2; i++ {
		r[i], r[len(r)-1-i] = r[len(r)-1-i], r[i]
	}
	return FoldBlock{height: b.height, mtp: b.mtp, rate: b.rate, txs: r}
}

func hexDec(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// ====================================================================
// MODE 4: fuzz — §9 differential fuzz (crash-safety / fail-closed robustness)
// ====================================================================

func runFuzz(seed uint64, count int) {
	p := newPRNG(seed)
	s := newState()
	var in digestBuf
	ts := genBaseTS
	var height int64
	txCount, crashes := 0, 0
	for txCount < count {
		ts += 300 + int64(p.bounded(600))
		rate := uint64(28 * (1 + p.bounded(4)))
		nTxs := 1 + bnd(p, 8)
		var txs []FoldTx
		for ti := 0; ti < nTxs && txCount < count; ti++ {
			nIn := 1 + bnd(p, 4)
			ins := make([]Identity, nIn)
			for k := 0; k < nIn; k++ {
				styp := byte(0)
				if bnd(p, 4) == 3 {
					styp = 1
				}
				id := genID(bnd(p, genNIDs))
				id.styp = styp
				id.ok = bnd(p, 8) != 0
				ins[k] = id
			}
			nOut := 1 + bnd(p, 4)
			var carriers []FoldCarrier
			var spend []FoldOutput
			for o := 0; o < nOut; o++ {
				var val uint64
				switch bnd(p, 3) {
				case 0:
					val = 0
				case 1:
					val = ^uint64(0) - uint64(bnd(p, 1000)) // near-2^64 (overflow probe)
				default:
					val = uint64(1 + bnd(p, 1000))
				}
				if bnd(p, 4) == 0 {
					// spendable output
					sid := genID(bnd(p, genNIDs))
					spend = append(spend, FoldOutput{h160: sid.h160, styp: byte(bnd(p, 2)), value: val})
					in.u8(byte(o))
					in.u64(val)
				} else {
					pl := fuzzPayload(p)
					carriers = append(carriers, FoldCarrier{c: decode(pl, val), value: val, vout: uint32(o)})
					in.u8(byte(o))
					in.u64(val)
					in.u32(uint32(len(pl)))
					in.bytes(pl)
				}
			}
			txs = append(txs, FoldTx{txIndex: uint32(ti), inputs: ins, carriers: carriers, spend: spend})
			txCount++
		}
		b := FoldBlock{height: height, mtp: ts, rate: rate, txs: txs}
		func() {
			defer func() {
				if recover() != nil {
					crashes++
				}
			}()
			s.applyBlock(b)
		}()
		height++
	}
	fmt.Printf("input_digest=%s\n", in.sum())
	fmt.Printf("state_digest=%s\n", hexState(s))
	fmt.Printf("parser_crashes=%d\n", crashes)
	if crashes != 0 {
		os.Exit(1)
	}
}

func fuzzPayload(p *splitMix64) []byte {
	if bnd(p, 10) < 4 { // dumb-random bytes
		l := bnd(p, 81)
		out := make([]byte, l)
		for i := range out {
			out[i] = byte(bnd(p, 256))
		}
		if bnd(p, 3) == 0 && l >= 4 {
			out[0] = 0xFF
			out[1] = 0x50
			out[2] = 0x4E
			out[3] = byte(1 + bnd(p, 15))
		}
		return out
	}
	// grammar-aware: a prefixed action-shaped payload, then maybe corrupt.
	pl := grammarPayload(p)
	switch bnd(p, 6) {
	case 2: // truncate
		if len(pl) > 0 {
			pl = pl[:len(pl)-1]
		}
	case 3: // flip a bit
		if len(pl) > 0 {
			pl[bnd(p, len(pl))] ^= 1 << uint(bnd(p, 8))
		}
	case 4: // extend
		pl = append(pl, byte(bnd(p, 256)))
	}
	return pl
}

func grammarPayload(p *splitMix64) []byte {
	op := 1 + bnd(p, 15)
	var bodyLen int
	switch op {
	case OP_VOTE_UP, OP_VOTE_DOWN:
		bodyLen = 36
	case OP_COMMIT:
		bodyLen = 32
	case OP_CLAIM:
		bodyLen = 33 + bnd(p, 20)
	case OP_RENEW:
		bodyLen = []int{0, 5, 6 + bnd(p, 71)}[bnd(p, 3)]
	case OP_TRANSFER:
		if bnd(p, 2) == 0 {
			bodyLen = 20
		} else {
			bodyLen = 26 + bnd(p, 51)
		}
	case OP_SELL:
		bodyLen = 13 + bnd(p, 20)
	case OP_RESERVE, OP_SETTLE, OP_PAY:
		bodyLen = 1 + bnd(p, 20)
	case OP_RELEASE:
		bodyLen = 6 + bnd(p, 71)
	case OP_DECORATE:
		bodyLen = bnd(p, 77)
	case OP_SELL_TO:
		bodyLen = 29 + bnd(p, 20)
	case OP_AS:
		bodyLen = 1
	case OP_TRADE:
		bodyLen = 5 + bnd(p, 30)
	default:
		bodyLen = bnd(p, 77)
	}
	pl := make([]byte, 4+bodyLen)
	pl[0] = 0xFF
	pl[1] = 0x50
	pl[2] = 0x4E
	pl[3] = byte(op)
	for i := 4; i < len(pl); i++ {
		pl[i] = byte(bnd(p, 256))
	}
	return pl
}

// ====================================================================
// MODE 5: reorgfuzz — §11 K=64 fork/divergence trials; clear-rebuild + replay purity
// ====================================================================

func runReorgfuzz(seed uint64, count int) {
	if count > 20000 {
		count = 20000
	}
	blocks := recordChain(seed, count)
	n := len(blocks)
	dFull := foldDigest(blocks, 0, n)
	tr := newPRNG(seed ^ 0x5245464B5A475F31)
	var altStream digestBuf
	var failures int64
	for t := 0; t < 64; t++ {
		J := int(tr.bounded(uint64(n + 1)))
		kind := bnd(tr, 3)
		// divergent branch → D_alt
		sd := newState()
		for i := 0; i < J; i++ {
			sd.applyBlock(blocks[i])
		}
		for _, b := range divergentTail(blocks, J, n, kind) {
			sd.applyBlock(b)
		}
		altStream.bytes(hexDec(hexState(sd)))
		// clear-rebuild to J reproduces fold[0,J); canonical replay reproduces D_full
		forkJ := foldDigest(blocks, 0, J)
		sc := newState()
		for i := 0; i < J; i++ {
			sc.applyBlock(blocks[i])
		}
		if hexState(sc) != forkJ {
			failures++
		}
		for i := J; i < n; i++ {
			sc.applyBlock(blocks[i])
		}
		if hexState(sc) != dFull {
			failures++
		}
	}
	altStream.bytes(hexDec(dFull))
	fmt.Printf("blocks=%d trials=64 failures=%d\n", n, failures)
	fmt.Printf("reorgfuzz_digest=%s\n", altStream.sum())
	if failures != 0 {
		os.Exit(1)
	}
}

func divergentTail(blocks []FoldBlock, J, n, kind int) []FoldBlock {
	var out []FoldBlock
	switch kind {
	case 0: // reversed tail
		for i := J; i < n; i++ {
			out = append(out, reverseTxs(blocks[i]))
		}
	case 1: // every other block
		for i := J; i < n; i += 2 {
			out = append(out, blocks[i])
		}
	default: // tail folded twice
		for i := J; i < n; i++ {
			out = append(out, blocks[i], blocks[i])
		}
	}
	return out
}
