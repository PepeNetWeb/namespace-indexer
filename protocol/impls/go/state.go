package main

// Fold state. All collections are keyed deterministically; digest.go emits them
// in the conformance-pinned sort order (never by Go map iteration).

type NameRow struct {
	owner [20]byte
	st    int // ST_OWNED / ST_LISTED / ST_OFFERED / ST_RESERVED

	leaseExpiry int64

	// market fields — always digested; zeroed when not active for the current st.
	seller       [20]byte
	sellerType   byte
	price        uint64
	offerExpiry  int64
	buyer        [20]byte // directed-offer buyer OR open-reserve reserver
	burnLeg      uint64
	payLeg       uint64
	reserveExpiry int64
}

// resetMarket physically zeroes all market fields (used on close/revert and OWNED).
func (r *NameRow) resetMarket() {
	r.seller = [20]byte{}
	r.sellerType = 0
	r.price = 0
	r.offerExpiry = 0
	r.buyer = [20]byte{}
	r.burnLeg = 0
	r.payLeg = 0
	r.reserveExpiry = 0
}

type CommitRow struct {
	commitment [32]byte
	height     int64
	txIndex    uint32
	commitTime int64
}

type VoteRow struct {
	target [32]byte
	vout   uint32
	score  i128
}

type DecorRow struct {
	txid [32]byte
	vout uint32
	rec  []byte // FULL on-wire record [tag:1][len:2 LE][value]
	seq  int    // insertion order within post (for stable sort)
}

type FoldState struct {
	names   map[string]*NameRow // key = raw name bytes
	commits []CommitRow
	votes   map[string]*VoteRow // key = string(target)+"|"+vout
	muts    map[[20]byte]int64
	decors  []DecorRow

	overflow bool

	curHeight int64

	// per-block claim displacement scratch (reset each block; NOT digested).
	scratch map[string]claimScratch
}

type claimScratch struct {
	ch    int64
	ti    uint32
	owner [20]byte
}

func newState() *FoldState {
	return &FoldState{
		names: map[string]*NameRow{},
		votes: map[string]*VoteRow{},
		muts:  map[[20]byte]int64{},
	}
}

func (s *FoldState) clear() {
	*s = *newState()
}

func (s *FoldState) bumpMut(owner [20]byte, h int64) {
	if cur, ok := s.muts[owner]; !ok || h > cur {
		s.muts[owner] = h
	}
}

// ownsAny reports whether owner has at least one name row (any live state).
func (s *FoldState) ownsAny(owner [20]byte) bool {
	for _, r := range s.names {
		if r.owner == owner {
			return true
		}
	}
	return false
}

func voteKey(target [32]byte, vout uint32) string {
	b := make([]byte, 36)
	copy(b, target[:])
	b[32] = byte(vout)
	b[33] = byte(vout >> 8)
	b[34] = byte(vout >> 16)
	b[35] = byte(vout >> 24)
	return string(b)
}

// makeSyntheticTxid: txid = u64_le(height) ‖ u32_le(txindex) ‖ 20 zero bytes (conformance §3).
func makeSyntheticTxid(height int64, txindex uint32) [32]byte {
	var t [32]byte
	h := uint64(height)
	for i := 0; i < 8; i++ {
		t[i] = byte(h >> (8 * uint(i)))
	}
	t[8] = byte(txindex)
	t[9] = byte(txindex >> 8)
	t[10] = byte(txindex >> 16)
	t[11] = byte(txindex >> 24)
	return t
}
