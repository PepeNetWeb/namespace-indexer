package main

import "unicode/utf8"

// Wire decoder: payload bytes (+ output value) → ACTION | POST | IGNORE.
// Strict, fail-closed (protocol-spec.md §0/§1/§2, SPEC-conformance.md §9).
// A malformed payload NEVER panics and NEVER errors to the caller — it decodes
// to IGNORE. Every slice read is bounds-guarded.

type carrierKind int

const (
	IGNORE carrierKind = iota
	POST
	ACTION
)

// Decoded carrier handed to the fold.
type Carrier struct {
	kind   carrierKind
	opcode byte
	// POST: body bytes (capped at 80, stored verbatim)
	postBytes []byte

	// Per-opcode parsed fields (only those relevant to opcode are set):
	txid   [32]byte // VOTE target
	vout   uint32   // VOTE target vout
	commit [32]byte // COMMIT commitment
	salt   [32]byte // CLAIM salt
	name   []byte   // CLAIM/SELL/RESERVE/SETTLE/PAY/SELL_TO name
	price  uint64   // SELL/SELL_TO
	window uint32   // SELL
	target [20]byte // TRANSFER target
	buyer  [20]byte // SELL_TO buyer
	anchor int64    // RENEW/TRANSFER/RELEASE 5-byte height anchor (-1 if absent)
	flags  []byte   // RENEW/TRANSFER/RELEASE bitmap (nil if absent / all-form)
	hasAnchor bool

	decRaw []byte // DECORATE raw TLV body

	asIndex int    // AS index
	idxA    int    // TRADE
	idxB    int    // TRADE
	nameA   []byte // TRADE
	nameB   []byte // TRADE
}

// validName enforces §3.1: charset [a-z0-9-] (a DNS label), length 1..32, byte-for-byte, no folding.
// Re-pin 2026-07-07: '.'/'_' dropped, '-' added (supersedes the 2026-07-02 dot rule). No structural
// rules — '-a', 'a-', 'xn--x' are all valid names; uppercase stays invalid.
func validName(b []byte) bool {
	if len(b) < 1 || len(b) > 32 {
		return false
	}
	for _, c := range b {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func leU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func leU64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(b[i]) << (8 * uint(i))
	}
	return v
}
func leU40(b []byte) int64 { // 5-byte little-endian height anchor
	var v int64
	for i := 0; i < 5; i++ {
		v |= int64(b[i]) << (8 * uint(i))
	}
	return v
}

// decode is the pure, fail-closed payload classifier.
func decode(payload []byte, value uint64) Carrier {
	ig := Carrier{kind: IGNORE}

	// ACTION prefix: len>=4 and payload[0..2]==FF 50 4E.
	if len(payload) >= 4 && payload[0] == 0xFF && payload[1] == 0x50 && payload[2] == 0x4E {
		return decodeAction(payload)
	}

	// POST: not an action prefix, value>0, len>=1, whole payload strict UTF-8.
	if value > 0 && len(payload) >= 1 && strictUTF8(payload) {
		pb := payload
		if len(pb) > 80 { // stored post bytes capped at 80 (conformance §9)
			pb = pb[:80]
		}
		cp := make([]byte, len(pb))
		copy(cp, pb)
		return Carrier{kind: POST, postBytes: cp}
	}
	return ig
}

// strictUTF8 validates RFC-3629: rejects overlong, surrogates U+D800..U+DFFF,
// and >U+10FFFF. We rely on utf8.Valid which implements exactly RFC-3629.
func strictUTF8(b []byte) bool { return utf8.Valid(b) }

func decodeAction(payload []byte) Carrier {
	ig := Carrier{kind: IGNORE}
	op := payload[3]
	body := payload[4:]
	bl := len(body)
	c := Carrier{kind: ACTION, opcode: op, anchor: -1, asIndex: -1, idxA: -1, idxB: -1}

	switch op {
	case OP_VOTE_UP, OP_VOTE_DOWN:
		if bl != 36 {
			return ig
		}
		copy(c.txid[:], body[0:32])
		c.vout = leU32(body[32:36])
		return c

	case OP_COMMIT:
		if bl != 32 {
			return ig
		}
		copy(c.commit[:], body[0:32])
		return c

	case OP_CLAIM:
		if bl < 33 || bl > 64 { // salt32 + name1..32
			return ig
		}
		copy(c.salt[:], body[0:32])
		nm := body[32:]
		if !validName(nm) {
			return ig
		}
		c.name = cloneBytes(nm)
		return c

	case OP_RENEW:
		// 0 = all; 5 = all-safe (anchor5); [6,76] = selective (anchor5 + flags1..71)
		switch {
		case bl == 0:
			return c
		case bl == 5:
			c.hasAnchor = true
			c.anchor = leU40(body[0:5])
			return c
		case bl >= 6 && bl <= 76:
			c.hasAnchor = true
			c.anchor = leU40(body[0:5])
			c.flags = cloneBytes(body[5:]) // 1..71 bytes
			return c
		default:
			return ig
		}

	case OP_TRANSFER:
		// 20 = all; [26,76] = selective (target20 + anchor5 + flags1..51)
		switch {
		case bl == 20:
			copy(c.target[:], body[0:20])
			return c
		case bl >= 26 && bl <= 76:
			copy(c.target[:], body[0:20])
			c.hasAnchor = true
			c.anchor = leU40(body[20:25])
			c.flags = cloneBytes(body[25:]) // 1..51
			return c
		default:
			return ig
		}

	case OP_SELL:
		if bl < 13 || bl > 44 { // price8 + window4 + name1..32
			return ig
		}
		c.price = leU64(body[0:8])
		c.window = leU32(body[8:12])
		nm := body[12:]
		if !validName(nm) {
			return ig
		}
		c.name = cloneBytes(nm)
		return c

	case OP_RESERVE, OP_SETTLE, OP_PAY:
		if bl < 1 || bl > 32 { // name1..32
			return ig
		}
		if !validName(body) {
			return ig
		}
		c.name = cloneBytes(body)
		return c

	case OP_RELEASE:
		if bl < 6 || bl > 76 {
			return ig
		}
		c.hasAnchor = true
		c.anchor = leU40(body[0:5])
		c.flags = cloneBytes(body[5:]) // 1..71
		return c

	case OP_DECORATE:
		if bl < 0 || bl > 80 { // SM_DEC_MAX raw TLV bytes (C reference decode.c; blen ≤ 80)
			return ig
		}
		c.decRaw = cloneBytes(body) // fold parses TLV
		return c

	case OP_SELL_TO:
		if bl < 29 || bl > 60 { // price8 + buyer20 + name1..32
			return ig
		}
		c.price = leU64(body[0:8])
		copy(c.buyer[:], body[8:28])
		nm := body[28:]
		if !validName(nm) {
			return ig
		}
		c.name = cloneBytes(nm)
		return c

	case OP_AS:
		if bl != 1 {
			return ig
		}
		c.asIndex = int(body[0])
		return c

	case OP_TRADE:
		if bl < 5 {
			return ig
		}
		c.idxA = int(body[0])
		c.idxB = int(body[1])
		rest := body[2:]
		// exactly one 0x2C, both sides valid §3.1
		comma := -1
		count := 0
		for i, b := range rest {
			if b == 0x2C {
				count++
				comma = i
			}
		}
		if count != 1 {
			return ig
		}
		na := rest[:comma]
		nb := rest[comma+1:]
		if !validName(na) || !validName(nb) {
			return ig
		}
		c.nameA = cloneBytes(na)
		c.nameB = cloneBytes(nb)
		return c

	default:
		// opcode 0x00 or 0x10..0xFF: not a recognized action. 0xFF lead never
		// valid UTF-8 → IGNORE (never a post).
		return ig
	}
}

func cloneBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
