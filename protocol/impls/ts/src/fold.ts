// The deterministic fold state machine (protocol-spec.md §3/§6) + canonical state digest
// (SPEC-conformance.md §4). This is the consensus heart. It consumes an ABSTRACT tx model with
// already-resolved identities (the §6 fold "is fed an already-resolved identity"; the real §4
// byte-logic lives in attribution.ts). Carrier bytes are interpreted via decode.ts.
//
// VALUE-PATH POLICY (TS specific, brief + conformance §2): every koinu/price/weight/time/lease
// quantity is `bigint`. `number` appears only for vout, tx_index, array indices, counts, single
// bytes (opcode/flags/AS index/tag/TLV len), and UTF-8 code points — all genuinely ≤32-bit, exact
// in a double. Block height is carried as `bigint` (it lands in i64 digest fields). A stray
// `number` on the value path makes JS THROW on a BigInt+number mix — fail-loud, never silent round.
import type { Bytes } from "./bytes.ts";
import {
  concat, u8, u32le, u64le, i64le, i128le, leBytes, cmpBytes, eqBytes, hex,
} from "./bytes.ts";
import { sha256 } from "./sha256.ts";
import { ecmhIdentity, ecmhHash, ecmhAdd } from "./secp256k1.ts";
import { decodePayload } from "./decode.ts";
import type { Action } from "./decode.ts";
import {
  OP, ST, DUST_FLOOR, SELL_PRICE_FLOOR, LEASE_QUANTUM, BILLING_UNIT, MAX_LEASE,
  COMMIT_EXPIRY, RESERVE_WINDOW, DIRECT_WINDOW, REORG_BUFFER, RESERVE_BURN_BPS,
  RESERVE_PAY_BPS, BPS_DENOM, MAX_ANCHOR_AGE, DEFAULT_ACTIVATION_HEIGHT,
} from "./constants.ts";

// ─── Abstract tx model (already-resolved identities) ─────────────────────────────────────────
// id = 20-byte hash160 or null (⊥, §4-unattributable). type 0=P2PKH 1=P2SH. sighashAll = Rule 3.
export type FoldInput = { id: Bytes | null; type: number; sighashAll: boolean };
export type FoldCarrier = { payload: Bytes; value: bigint; vout: number };
export type FoldOutput = { type: number; hash: Bytes; value: bigint }; // spendable (payment) output
export type FoldTx = { inputs: FoldInput[]; carriers: FoldCarrier[]; outputs: FoldOutput[] };

// resolved acting identity {id,type} or null. Rule 3: §4 fails if not exactly SIGHASH_ALL.
type Actor = { id: Bytes; type: number } | null;
function resolve(input: FoldInput | undefined): Actor {
  if (!input || input.id === null || !input.sighashAll) return null;
  return { id: input.id, type: input.type };
}

// ─── names row (all market fields ALWAYS present; zeroed when inactive — conformance §4) ──────
const Z20 = new Uint8Array(20);
type NameRow = {
  name: Bytes;
  owner: Bytes; // 20
  st: number; // OWNED/LISTED/OFFERED/RESERVED
  leaseExpiry: bigint;
  seller: Bytes; // 20
  sellerType: number;
  price: bigint;
  offerExpiry: bigint;
  buyer: Bytes; // 20 — SELL_TO buyer (OFFERED) or reserver (RESERVED)
  burnLeg: bigint;
  payLeg: bigint;
  reserveExpiry: bigint;
};
type Commit = { commitment: Bytes; commitHeight: bigint; txIndex: number; commitTime: bigint };
type Decor = { txid: Bytes; vout: number; rec: Bytes };

const PEND_DECOR_MAX = 64; // §1 pending-record cap (SM_MAX_PEND_DECOR, pinned all 7 impls)

const nk = (name: Bytes): string => hex(name); // names are [a-z0-9-] so raw bytes are the canon key
const ik = (id: Bytes): string => hex(id);

function zeroMarket(r: NameRow): void {
  r.seller = Z20; r.sellerType = 0; r.price = 0n; r.offerExpiry = 0n;
  r.buyer = Z20; r.burnLeg = 0n; r.payLeg = 0n; r.reserveExpiry = 0n;
}

export class Fold {
  names = new Map<string, NameRow>();
  ownerNames = new Map<string, Set<string>>(); // ownerHex → set of nameKeys (live reverse index)
  commits: Commit[] = [];
  votes = new Map<string, { target: Bytes; vout: number; score: bigint }>();
  muts = new Map<string, { owner: Bytes; height: bigint }>();
  decors: Decor[] = [];
  overflow = 0;

  blockTimestamps: bigint[] = []; // height → timestamp (for reference; MTP injected per block)
  activationHeight: bigint;

  curHeight = 0n;
  curMTP = 0n;
  curRate = 1n;
  // per-block claim scratch (NOT digested): nameKey → backing commit tuple + provisional owner
  claimScratch = new Map<string, { ch: bigint; ti: number; owner: Bytes }>();

  constructor(activationHeight: bigint = DEFAULT_ACTIVATION_HEIGHT) {
    this.activationHeight = activationHeight;
  }

  clear(): void {
    this.names.clear(); this.ownerNames.clear(); this.commits = [];
    this.votes.clear(); this.muts.clear(); this.decors = []; this.overflow = 0;
    this.claimScratch.clear();
  }

  // ─── ownership index helpers ────────────────────────────────────────────────────────────────
  private _ownerSet(idHex: string): Set<string> {
    let s = this.ownerNames.get(idHex);
    if (!s) { s = new Set(); this.ownerNames.set(idHex, s); }
    return s;
  }
  private _add(row: NameRow): void {
    this.names.set(nk(row.name), row);
    this._ownerSet(ik(row.owner)).add(nk(row.name));
  }
  private _remove(key: string): void {
    const row = this.names.get(key);
    if (!row) return;
    this._ownerSet(ik(row.owner)).delete(key);
    this.names.delete(key);
  }
  private _chown(key: string, newOwner: Bytes): void {
    const row = this.names.get(key);
    if (!row) return;
    this._ownerSet(ik(row.owner)).delete(key);
    row.owner = newOwner;
    this._ownerSet(ik(newOwner)).add(key);
  }
  private _bump(id: Bytes): void {
    // mut height stamped to the connecting/confirm height (curHeight) — monotonic high-water mark.
    this.muts.set(ik(id), { owner: id, height: this.curHeight });
  }
  private _ownsAName(id: Bytes): boolean {
    const s = this.ownerNames.get(ik(id));
    return !!s && s.size > 0;
  }
  private _ownedListSorted(id: Bytes): NameRow[] {
    const s = this.ownerNames.get(ik(id));
    if (!s) return [];
    const rows: NameRow[] = [];
    for (const key of s) { const r = this.names.get(key); if (r) rows.push(r); }
    rows.sort((a, b) => cmpBytes(a.name, b.name)); // ascending bytewise (§3.5)
    return rows;
  }

  // ─── per-block driver ───────────────────────────────────────────────────────────────────────
  beginBlock(height: bigint, mtp: bigint, rate: bigint): void {
    this.curHeight = height;
    this.curMTP = mtp;
    this.curRate = rate;
    this.claimScratch.clear();
    this.preBlock();
  }

  // §6 time-triggered transitions, BEFORE the block's txs, in reserve→offer→lease type order,
  // then COMMIT_EXPIRY pruning. Bounds are EXCLUSIVE (owned iff MTP < lease_expiry); the commit
  // window is INCLUSIVE (pruned only once MTP > commit_time + COMMIT_EXPIRY).
  private preBlock(): void {
    const mtp = this.curMTP;
    // 1. reserve_expiry: RESERVED → LISTED  (revert reserve; name was always seller's; no bump)
    for (const r of [...this.names.values()]) {
      if (r.st === ST.RESERVED && mtp >= r.reserveExpiry) {
        r.st = ST.LISTED;
        r.buyer = Z20; r.burnLeg = 0n; r.payLeg = 0n; r.reserveExpiry = 0n; // reset reserve fields
      }
    }
    // 2. offer_expiry: LISTED or OFFERED → OWNED  (close; no bump)
    for (const r of [...this.names.values()]) {
      if ((r.st === ST.LISTED || r.st === ST.OFFERED) && mtp >= r.offerExpiry) {
        r.st = ST.OWNED;
        zeroMarket(r);
      }
    }
    // 3. lease_expiry: lapse to pool (remove from set; stamp owner's mut to connecting height H)
    for (const [key, r] of [...this.names.entries()]) {
      if (mtp >= r.leaseExpiry) {
        const owner = r.owner;
        this._remove(key);
        this._bump(owner); // a lapse is a time-triggered set mutation (§3.5/conformance §3)
      }
    }
    // COMMIT_EXPIRY pruning (independent; inclusive window)
    this.commits = this.commits.filter((c) => !(mtp > c.commitTime + COMMIT_EXPIRY));
  }

  // ─── tx processing (§6 inner loop) ───────────────────────────────────────────────────────────
  applyTx(tx: FoldTx, txIndex: number): void {
    let actor: Actor = resolve(tx.inputs[0]); // default acting identity = vin[0] (Rule 1)
    let pending: Bytes[] = []; // pending DECORATE records buffer
    const consumed = new Set<number>(); // spendable outputs consumed by market ops (per-tx)

    for (const o of tx.carriers) {
      const dec = decodePayload(o.payload, o.value);
      if (dec.kind === "IGNORE") continue; // ⊥ / malformed / non-UTF8 zero-value → ignore
      if (dec.kind === "POST") {
        this.handlePost(actor, txIndex, o.vout, pending);
        pending = [];
        continue;
      }
      const act = dec.action;
      // §3.0 forward-only gate: gated opcodes (0x03..0x0F) below activation are dropped.
      if (act.op >= OP.COMMIT && this.curHeight < this.activationHeight) continue;

      if (act.op === OP.AS) {
        pending = []; // AS flushes the pending DECORATE buffer (orphan, §3.10)
        const k = (act as { index: number }).index;
        actor = resolve(tx.inputs[k]); // ⊥ if OOB or fails §4/SIGHASH_ALL → segment drops
        continue;
      }

      // TRADE is attributed to its OWN named inputs vin[idxA]/vin[idxB], NOT the acting identity
      // (§3.10/§6): it dispatches regardless of whether the acting identity verified, and never
      // consults `actor`, so it MUST run before the acting-identity drop gate below. (Requiring a
      // verified `actor` here would drop trades the spec settles — the M9 fork.)
      if (act.op === OP.TRADE) { this.doTrade(act, tx); continue; }

      // run §4 verification on the acting identity (memoized trivially here)
      if (actor === null) continue; // ⊥ actor → drop this action

      this.dispatch(act, actor, tx, o, txIndex, consumed, pending);
    }
    // end of tx: any pending DECORATE records with no following body are orphaned & discarded (§1)
  }

  private handlePost(actor: Actor, txIndex: number, vout: number, pending: Bytes[]): void {
    // author = §4(actor) or ANONYMOUS. Bind buffered decorations iff author owns ≥1 name (§1).
    if (actor !== null && pending.length > 0 && this._ownsAName(actor.id)) {
      const txid = this.syntheticTxid(txIndex);
      for (const rec of pending) this.decors.push({ txid, vout, rec });
    }
    // buffer is cleared by the caller after every body (bound or not)
  }

  private syntheticTxid(txIndex: number): Bytes {
    // conformance §3: u64_le(height) ‖ u32_le(txindex) ‖ 20 zero bytes = 32 bytes
    return concat(u64le(this.curHeight), u32le(txIndex), Z20);
  }

  private dispatch(
    act: Action, actor: { id: Bytes; type: number }, tx: FoldTx, o: FoldCarrier,
    txIndex: number, consumed: Set<number>, pending: Bytes[],
  ): void {
    switch (act.op) {
      case OP.VOTE_UP:
      case OP.VOTE_DOWN: {
        if (o.value < DUST_FLOOR) return; // zero/under-floor weight carries no signal → drop
        const key = hex(act.target) + ":" + act.vout;
        let v = this.votes.get(key);
        if (!v) { v = { target: act.target.slice(), vout: act.vout, score: 0n }; this.votes.set(key, v); }
        v.score += act.op === OP.VOTE_UP ? o.value : -o.value;
        // i128 fail-loud overflow guard (bigint never wraps; flag if out of signed-128 range)
        const LIM = 1n << 127n;
        if (v.score >= LIM || v.score < -LIM) this.overflow = 1;
        return;
      }
      case OP.COMMIT: {
        this.commits.push({
          commitment: act.commitment.slice(), commitHeight: this.curHeight,
          txIndex, commitTime: this.curMTP,
        });
        return;
      }
      case OP.CLAIM:
        return this.doClaim(act, actor, o);
      case OP.RENEW:
        return this.doRenew(act, actor, o);
      case OP.TRANSFER:
        return this.doTransfer(act, actor);
      case OP.RELEASE:
        return this.doRelease(act, actor);
      case OP.SELL:
        return this.doSell(act, actor);
      case OP.SELL_TO:
        return this.doSellTo(act, actor);
      case OP.RESERVE:
        return this.doReserve(act, actor, tx, o, consumed);
      case OP.SETTLE:
        return this.doSettle(act, actor, tx, consumed);
      case OP.PAY:
        return this.doPay(act, actor, tx, consumed);
      // OP.TRADE is intercepted in applyTx (before the acting-identity gate) — it never reaches here.
      case OP.DECORATE:
        return this.doDecorate(act, pending);
    }
  }

  // ─── CLAIM (§3.2) ─────────────────────────────────────────────────────────────────────────
  private leaseDaysTotal(burn: bigint): bigint {
    // T = ⌊burn · LEASE_QUANTUM / (rate · BILLING_UNIT)⌋  (numerator ≥128-bit; bigint = exact)
    if (this.curRate <= 0n) return 0n;
    return (burn * LEASE_QUANTUM) / (this.curRate * BILLING_UNIT);
  }
  private findBackingCommit(salt: Bytes, name: Bytes, author: Bytes): { ch: bigint; ti: number } | null {
    const target = sha256(concat(salt, name, author)); // commitment = SHA256(salt‖name‖author_h160)
    let best: { ch: bigint; ti: number } | null = null;
    for (const c of this.commits) {
      if (!eqBytes(c.commitment, target)) continue;
      if (c.commitHeight >= this.curHeight) continue; // MUST be a STRICTLY earlier block (§3.2)
      // commit still live (pre-block pruned expired ones, inclusive window) → eligible
      if (best === null || c.commitHeight < best.ch || (c.commitHeight === best.ch && c.txIndex < best.ti)) {
        best = { ch: c.commitHeight, ti: c.txIndex };
      }
    }
    return best;
  }
  private doClaim(act: Extract<Action, { op: typeof OP.CLAIM }>, actor: { id: Bytes; type: number }, o: FoldCarrier): void {
    const key = nk(act.name);
    const backing = this.findBackingCommit(act.salt, act.name, actor.id);
    if (backing === null) return; // no live ≥1-deep matching commit → drop (no FCFS fallback)
    const T = this.leaseDaysTotal(o.value);
    if (T < 1n) return; // CLAIM MUST cover ≥1 day (§3.2/§3.5 fail-closed)
    const add = T < 365n ? T : 365n; // fresh name: headroom = MAX_LEASE/BILLING_UNIT = 365 days
    const newExpiry = this.curMTP + add * BILLING_UNIT;

    const existing = this.names.get(key);
    if (existing) {
      // name already present. Same-block displacement (conformance §3 + §3.2 tuple + §7 vec 42):
      // displace iff the existing is still THIS owner's fresh OWNED mint AND this claim's backing
      // (commit_height, commit_tx_index) is strictly smaller. NOTE (see SPEC-RATIONALE.md): conformance §3
      // prose says "commit_height strictly smaller" only; §3.2 + §7 require the full (ch,ti) tuple.
      const sc = this.claimScratch.get(key);
      if (sc && existing.st === ST.OWNED && eqBytes(existing.owner, sc.owner) &&
          (backing.ch < sc.ch || (backing.ch === sc.ch && backing.ti < sc.ti))) {
        this._chown(key, actor.id);
        existing.leaseExpiry = newExpiry;
        zeroMarket(existing);
        this.claimScratch.set(key, { ch: backing.ch, ti: backing.ti, owner: actor.id });
        this._bump(actor.id);
      }
      return; // else: already owned → drop
    }
    // fresh mint
    const row: NameRow = {
      name: act.name.slice(), owner: actor.id, st: ST.OWNED, leaseExpiry: newExpiry,
      seller: Z20, sellerType: 0, price: 0n, offerExpiry: 0n, buyer: Z20,
      burnLeg: 0n, payLeg: 0n, reserveExpiry: 0n,
    };
    this._add(row);
    this.claimScratch.set(key, { ch: backing.ch, ti: backing.ti, owner: actor.id });
    this._bump(actor.id);
  }

  // ─── water-fill (§3.5) shared by RENEW (and the trivial single-name CLAIM above) ─────────────
  private waterfill(rows: NameRow[], T: bigint): Map<string, bigint> {
    const now = this.curMTP;
    const items = rows.map((r) => {
      const remaining = r.leaseExpiry - now; // owned ⇒ > 0
      let h = (MAX_LEASE - remaining) / BILLING_UNIT; // headroom in days
      if (h < 0n) h = 0n;
      return { key: nk(r.name), name: r.name, h };
    });
    const out = new Map<string, bigint>();
    let totalH = 0n;
    for (const it of items) totalH += it.h;
    if (T >= totalH) {
      for (const it of items) out.set(it.key, it.h); // every name caps; surplus forfeited (§3.5)
      return out;
    }
    // T < totalH: find max λ with Σ min(hᵢ,λ) ≤ T  (λ ∈ [0, maxH ≤ 365])
    let maxH = 0n;
    for (const it of items) if (it.h > maxH) maxH = it.h;
    let lo = 0n, hi = maxH;
    while (lo < hi) {
      const mid = (lo + hi + 1n) / 2n;
      let s = 0n;
      for (const it of items) s += it.h < mid ? it.h : mid;
      if (s <= T) lo = mid; else hi = mid - 1n;
    }
    const lambda = lo;
    let used = 0n;
    for (const it of items) { const a = it.h < lambda ? it.h : lambda; out.set(it.key, a); used += a; }
    let r = T - used; // remainder < (#headroom names), each gets +1
    if (r > 0n) {
      const headroom = items.filter((it) => it.h > lambda).sort((a, b) => cmpBytes(a.name, b.name));
      for (const it of headroom) {
        if (r <= 0n) break;
        out.set(it.key, (out.get(it.key) as bigint) + 1n);
        r -= 1n;
      }
    }
    return out;
  }

  // ─── anchor guard (§3.5) ─────────────────────────────────────────────────────────────────────
  private anchorOk(actor: Bytes, H: bigint): boolean {
    if (H > this.curHeight) return false; // fail-closed upper bound (never relaxed)
    if (this.curHeight - H > MAX_ANCHOR_AGE) return false; // too stale
    const m = this.muts.get(ik(actor));
    const lastMut = m ? m.height : 0n; // no entry ⇒ never mutated ⇒ treat as 0 (passes)
    if (lastMut > H) return false; // set mutated since H → reject-and-resend
    return true;
  }

  // bitmap select over a sorted owned list, LSB-first; bits ≥ K ignored (§3.5)
  private bitmapSelect(owned: NameRow[], flags: Bytes): NameRow[] {
    const K = owned.length;
    const sel: NameRow[] = [];
    for (let i = 0; i < K; i++) {
      const bit = (flags[i >> 3] >> (i & 7)) & 1;
      if (bit) sel.push(owned[i]);
    }
    return sel;
  }

  // ─── RENEW (§3.5) ─────────────────────────────────────────────────────────────────────────
  private doRenew(act: Extract<Action, { op: typeof OP.RENEW }>, actor: { id: Bytes; type: number }, o: FoldCarrier): void {
    const owned = this._ownedListSorted(actor.id);
    let targeted: NameRow[];
    if (act.mode === "all") {
      targeted = owned; // renew-all: no anchor, whole live set
    } else if (act.mode === "all-safe") {
      if (!this.anchorOk(actor.id, act.anchor)) return;
      targeted = owned;
    } else {
      if (!this.anchorOk(actor.id, act.anchor)) return;
      targeted = this.bitmapSelect(owned, act.flags);
    }
    if (targeted.length === 0) return; // nothing to renew
    const T = this.leaseDaysTotal(o.value);
    if (T < 1n) return; // fail-closed at T=0 (§3.5 step 1)  [RENEW renews even LOCKED names — no skip]
    const adds = this.waterfill(targeted, T);
    for (const r of targeted) {
      const a = adds.get(nk(r.name)) ?? 0n;
      r.leaseExpiry += a * BILLING_UNIT;
    }
    // RENEW does NOT bump last_set_mutation_height (no set/ordering change, §3.5)
  }

  // ─── TRANSFER (§3.5/§3.6) ────────────────────────────────────────────────────────────────────
  private doTransfer(act: Extract<Action, { op: typeof OP.TRANSFER }>, actor: { id: Bytes; type: number }): void {
    const owned = this._ownedListSorted(actor.id);
    let targeted: NameRow[];
    if (act.mode === "all") {
      targeted = owned; // transfer-all: no anchor
    } else {
      if (!this.anchorOk(actor.id, act.anchor)) return;
      targeted = this.bitmapSelect(owned, act.flags);
    }
    let moved = false;
    for (const r of targeted) {
      if (r.st !== ST.OWNED) continue; // locked (LISTED/OFFERED/RESERVED) → SKIP, not fatal (§3.5)
      if (eqBytes(r.owner, act.target)) continue; // self-transfer no-op
      this._chown(nk(r.name), act.target.slice());
      // lease conveys (lease_expiry unchanged)
      moved = true;
    }
    if (moved) { this._bump(actor.id); this._bump(act.target); } // bump BOTH parties (§3.5)
  }

  // ─── RELEASE (§3.6) ───────────────────────────────────────────────────────────────────────
  private doRelease(act: Extract<Action, { op: typeof OP.RELEASE }>, actor: { id: Bytes; type: number }): void {
    if (!this.anchorOk(actor.id, act.anchor)) return;
    const owned = this._ownedListSorted(actor.id);
    const targeted = this.bitmapSelect(owned, act.flags);
    let released = false;
    for (const r of targeted) {
      if (r.st !== ST.OWNED) continue; // locked → SKIP (§3.5)
      this._remove(nk(r.name)); // return to pool immediately (immediately reclaimable)
      released = true;
    }
    if (released) this._bump(actor.id); // bump only if ≥1 actually released (§3.5)
  }

  // ─── SELL (§3.7) ─────────────────────────────────────────────────────────────────────────
  private doSell(act: Extract<Action, { op: typeof OP.SELL }>, actor: { id: Bytes; type: number }): void {
    const row = this.names.get(nk(act.name));
    if (!row || !eqBytes(row.owner, actor.id) || row.st !== ST.OWNED) return; // own + unlocked + unlisted
    if (act.price < SELL_PRICE_FLOOR) return; // price ≥ 3·DUST_FLOOR (fold-safety floor)
    let window = act.window;
    if (window === 0n) window = RESERVE_WINDOW; // window==0 defaults to RESERVE_WINDOW
    if (window < RESERVE_WINDOW) return; // below floor (and nonzero) → out of range → ignored
    // upper bound in ADD-FORM (never the underflowing subtraction): now+window+REORG ≤ lease_expiry
    if (this.curMTP + window + REORG_BUFFER > row.leaseExpiry) return;
    row.st = ST.LISTED;
    row.seller = actor.id; row.sellerType = actor.type;
    row.price = act.price; row.offerExpiry = this.curMTP + window;
    // SELL does NOT bump mutation height (§3.5)
  }

  // ─── SELL_TO (§3.7 directed) ─────────────────────────────────────────────────────────────────
  private doSellTo(act: Extract<Action, { op: typeof OP.SELL_TO }>, actor: { id: Bytes; type: number }): void {
    const row = this.names.get(nk(act.name));
    if (!row || !eqBytes(row.owner, actor.id) || row.st !== ST.OWNED) return;
    if (act.price < DUST_FLOOR) return; // SELL_TO floor is DUST_FLOOR (not 3×)
    // lease tail ≥ DIRECT_WINDOW + REORG_BUFFER (add-form)
    if (this.curMTP + DIRECT_WINDOW + REORG_BUFFER > row.leaseExpiry) return;
    row.st = ST.OFFERED;
    row.seller = actor.id; row.sellerType = actor.type;
    row.price = act.price; row.offerExpiry = this.curMTP + DIRECT_WINDOW;
    row.buyer = act.buyer.slice(); // the named buyer (may be P2SH)
    // SELL_TO does NOT bump (§3.5)
  }

  // exact-value output match: lowest unconsumed output equal to (seller_type, seller, owed). §3.5
  private matchOutput(tx: FoldTx, consumed: Set<number>, sType: number, sHash: Bytes, owed: bigint): boolean {
    for (let i = 0; i < tx.outputs.length; i++) {
      if (consumed.has(i)) continue;
      const out = tx.outputs[i];
      if (out.type === sType && out.value === owed && eqBytes(out.hash, sHash)) {
        consumed.add(i);
        return true;
      }
    }
    return false;
  }

  // ─── RESERVE (§3.7) ───────────────────────────────────────────────────────────────────────
  private depositLegs(price: bigint): { burnLeg: bigint; payLeg: bigint } {
    // max(DUST_FLOOR, ⌊price·bps/10000⌋); price·bps ≥128-bit (bigint exact). §3.7/§2
    const burn = (price * RESERVE_BURN_BPS) / BPS_DENOM;
    const pay = (price * RESERVE_PAY_BPS) / BPS_DENOM;
    return {
      burnLeg: burn > DUST_FLOOR ? burn : DUST_FLOOR,
      payLeg: pay > DUST_FLOOR ? pay : DUST_FLOOR,
    };
  }
  private doReserve(act: Extract<Action, { op: typeof OP.RESERVE }>, actor: { id: Bytes; type: number }, tx: FoldTx, o: FoldCarrier, consumed: Set<number>): void {
    const row = this.names.get(nk(act.name));
    if (!row || row.st !== ST.LISTED) return; // must be an OPEN listing (first reserve wins option)
    if (this.curMTP >= row.offerExpiry) return; // listing live (exclusive bound)
    const { burnLeg, payLeg } = this.depositLegs(row.price);
    if (o.value < burnLeg) return; // RESERVE OP_RETURN value ≥ burn_leg (≥, not exact — vec 46)
    if (!this.matchOutput(tx, consumed, row.sellerType, row.seller, payLeg)) return; // pay-leg output
    row.st = ST.RESERVED;
    row.buyer = actor.id; // the reserver (exclusive buyer)
    row.burnLeg = burnLeg; row.payLeg = payLeg;
    const rw = this.curMTP + RESERVE_WINDOW;
    row.reserveExpiry = rw < row.offerExpiry ? rw : row.offerExpiry; // clamp to offer_expiry (§3.7)
    // RESERVE does NOT bump (name stays seller's, §3.5)
  }

  // ─── SETTLE (§3.7) ────────────────────────────────────────────────────────────────────────
  private doSettle(act: Extract<Action, { op: typeof OP.SETTLE }>, actor: { id: Bytes; type: number }, tx: FoldTx, consumed: Set<number>): void {
    const row = this.names.get(nk(act.name));
    if (!row || row.st !== ST.RESERVED) return;
    if (!eqBytes(actor.id, row.buyer)) return; // only the exclusive reserver may SETTLE
    if (this.curMTP >= row.reserveExpiry) return; // MTP < reserve_expiry
    const remainder = row.price - row.burnLeg - row.payLeg; // ≥ DUST_FLOOR by price floor
    if (!this.matchOutput(tx, consumed, row.sellerType, row.seller, remainder)) return;
    const seller = row.seller;
    this._chown(nk(act.name), actor.id); // name → buyer; lease conveys
    row.st = ST.OWNED;
    zeroMarket(row);
    this._bump(actor.id); this._bump(seller); // bump BOTH (buyer gains, seller loses)
  }

  // ─── PAY (§3.7 directed) ─────────────────────────────────────────────────────────────────────
  private doPay(act: Extract<Action, { op: typeof OP.PAY }>, actor: { id: Bytes; type: number }, tx: FoldTx, consumed: Set<number>): void {
    const row = this.names.get(nk(act.name));
    if (!row || row.st !== ST.OFFERED) return;
    if (!eqBytes(actor.id, row.buyer)) return; // only the named buyer's vin[0] may PAY
    if (this.curMTP >= row.offerExpiry) return; // MTP < offer_expiry
    if (!this.matchOutput(tx, consumed, row.sellerType, row.seller, row.price)) return; // full price
    const seller = row.seller;
    this._chown(nk(act.name), actor.id); // name → buyer; lease conveys
    row.st = ST.OWNED;
    zeroMarket(row);
    this._bump(actor.id); this._bump(seller); // bump BOTH
  }

  // ─── TRADE (§3.10) ────────────────────────────────────────────────────────────────────────
  private doTrade(act: Extract<Action, { op: typeof OP.TRADE }>, tx: FoldTx): void {
    if (act.idxA === act.idxB) return; // idxA==idxB → drop
    if (eqBytes(act.nameA, act.nameB)) return; // nameA==nameB → drop
    const A = resolve(tx.inputs[act.idxA]); // §4 + SIGHASH_ALL on both parties
    const B = resolve(tx.inputs[act.idxB]);
    if (A === null || B === null) return; // index OOB or party fails §4/SIGHASH_ALL → drop
    const ra = this.names.get(nk(act.nameA));
    const rb = this.names.get(nk(act.nameB));
    // live-ownership anti-rug re-check at confirm: each party still owns its pledged name, UNLOCKED.
    if (!ra || ra.st !== ST.OWNED || !eqBytes(ra.owner, A.id)) return;
    if (!rb || rb.st !== ST.OWNED || !eqBytes(rb.owner, B.id)) return;
    this._chown(nk(act.nameA), B.id); // nameA → vin[idxB]
    this._chown(nk(act.nameB), A.id); // nameB → vin[idxA]; leases convey
    this._bump(A.id); this._bump(B.id); // bump BOTH parties' mutation heights (§3.10)
  }

  // ─── DECORATE (§1) ────────────────────────────────────────────────────────────────────────
  private doDecorate(act: Extract<Action, { op: typeof OP.DECORATE }>, pending: Bytes[]): void {
    // parse TLV records left→right, fail-closed: a len overrun OR a trailing remnant < 3-byte
    // header drops the malformed tail; every fully-parsed record before it is kept & buffered.
    const body = act.body;
    let i = 0;
    while (i < body.length) {
      if (i + 3 > body.length) break; // remnant shorter than [tag:1][len:2] header → stop
      const len = body[i + 1] | (body[i + 2] << 8); // len:2 LE
      const end = i + 3 + len;
      if (end > body.length) break; // value overruns → stop (drop tail)
      // §1 pending-record cap: buffer only the first PEND_DECOR_MAX records; drop further, keep parsing.
      if (pending.length < PEND_DECOR_MAX) pending.push(body.subarray(i, end).slice()); // FULL record [tag][len:2][value] verbatim
      i = end;
    }
  }

  // ─── canonical state digest (SPEC-conformance.md §4) ─────────────────────────────────────────
  serialize(): Bytes {
    const parts: Bytes[] = [];
    parts.push(new TextEncoder().encode("SMv1"));

    // names — rows sorted ascending by raw name bytes
    const nameRows = [...this.names.values()].sort((a, b) => cmpBytes(a.name, b.name));
    parts.push(u32le(nameRows.length));
    for (const r of nameRows) {
      parts.push(u8(r.name.length));
      parts.push(r.name);
      parts.push(pad20(r.owner));
      parts.push(u8(r.st));
      parts.push(i64le(r.leaseExpiry));
      parts.push(pad20(r.seller));
      parts.push(u8(r.sellerType));
      parts.push(u64le(r.price));
      parts.push(i64le(r.offerExpiry));
      parts.push(pad20(r.buyer));
      parts.push(u64le(r.burnLeg));
      parts.push(u64le(r.payLeg));
      parts.push(i64le(r.reserveExpiry));
    }

    // commits — sorted by commitment bytes (then height,tx_index,time for total order; LOG: spec
    // pins only "by commitment bytes", so identical commitments need a documented tiebreak)
    const commitRows = this.commits.slice().sort((a, b) => {
      const c = cmpBytes(a.commitment, b.commitment);
      if (c !== 0) return c;
      if (a.commitHeight !== b.commitHeight) return a.commitHeight < b.commitHeight ? -1 : 1;
      if (a.txIndex !== b.txIndex) return a.txIndex - b.txIndex;
      return a.commitTime < b.commitTime ? -1 : a.commitTime > b.commitTime ? 1 : 0;
    });
    parts.push(u32le(commitRows.length));
    for (const c of commitRows) {
      parts.push(pad(c.commitment, 32));
      parts.push(i64le(c.commitHeight));
      parts.push(u32le(c.txIndex));
      parts.push(i64le(c.commitTime));
    }

    // votes — sorted by (target[32], vout)
    const voteRows = [...this.votes.values()].sort((a, b) => {
      const c = cmpBytes(a.target, b.target);
      return c !== 0 ? c : a.vout - b.vout;
    });
    parts.push(u32le(voteRows.length));
    for (const v of voteRows) {
      parts.push(pad(v.target, 32));
      parts.push(u32le(v.vout));
      parts.push(i128le(v.score));
    }

    // muts — sorted by owner bytes
    const mutRows = [...this.muts.values()].sort((a, b) => cmpBytes(a.owner, b.owner));
    parts.push(u32le(mutRows.length));
    for (const m of mutRows) {
      parts.push(pad20(m.owner));
      parts.push(i64le(m.height));
    }

    // decors — sorted by (txid[32], vout) STABLE (insertion order within a post)
    const idx = this.decors.map((d, i) => ({ d, i }));
    idx.sort((x, y) => {
      const c = cmpBytes(x.d.txid, y.d.txid);
      if (c !== 0) return c;
      if (x.d.vout !== y.d.vout) return x.d.vout - y.d.vout;
      return x.i - y.i; // stable: preserve insertion order within equal (txid,vout)
    });
    parts.push(u32le(idx.length));
    for (const { d } of idx) {
      parts.push(pad(d.txid, 32));
      parts.push(u32le(d.vout));
      parts.push(u8(d.rec.length & 0xff));
      parts.push(d.rec);
    }

    parts.push(u8(this.overflow));
    return concat(...parts);
  }

  digest(): Bytes {
    return sha256(this.serialize());
  }

  // ─── incremental ECMH state digest (SPEC-conformance.md §13.2) ───────────────────────────────
  // The order-independent / invertible twin of digest(): a per-table elliptic-curve multiset hash
  // over the SAME per-row encoding serialize() uses (so the two induce the identical equality
  // relation), folded into one combined SHA-256. Mirrors impls/c/src/ecmh.c sm_state_ecmh.
  stateEcmh(): Bytes {
    // P(row) = ECMH_H2C("ECMHv1" ‖ tag ‖ row_bytes); A_T = Σ P(row); start from ∞.
    const REC = new TextEncoder().encode("ECMHv1");
    const fold = (tag: number, rows: Bytes[]): Bytes => {
      let acc = ecmhIdentity();
      for (const rb of rows) acc = ecmhAdd(acc, ecmhHash(concat(REC, u8(tag), rb)).pt);
      return acc;
    };

    const an = fold(0x01, [...this.names.values()].map((r) => concat(
      u8(r.name.length), r.name, pad20(r.owner), u8(r.st), i64le(r.leaseExpiry),
      pad20(r.seller), u8(r.sellerType), u64le(r.price), i64le(r.offerExpiry),
      pad20(r.buyer), u64le(r.burnLeg), u64le(r.payLeg), i64le(r.reserveExpiry),
    )));
    const ac = fold(0x02, this.commits.map((c) => concat(
      pad(c.commitment, 32), i64le(c.commitHeight), u32le(c.txIndex), i64le(c.commitTime),
    )));
    const av = fold(0x03, [...this.votes.values()].map((v) => concat(
      pad(v.target, 32), u32le(v.vout), i128le(v.score),
    )));
    const am = fold(0x04, [...this.muts.values()].map((m) => concat(
      pad20(m.owner), i64le(m.height),
    )));
    const ad = fold(0x05, this.decors.map((d) => concat(
      pad(d.txid, 32), u32le(d.vout), u8(d.rec.length & 0xff), d.rec,
    )));

    // combined = SHA256("ECMHtop1" ‖ A_names ‖ A_commits ‖ A_votes ‖ A_muts ‖ A_decors ‖ overflow).
    return sha256(concat(
      new TextEncoder().encode("ECMHtop1"), an, ac, av, am, ad, u8(this.overflow),
    ));
  }
}

function pad(b: Bytes, n: number): Bytes {
  if (b.length === n) return b;
  const out = new Uint8Array(n);
  out.set(b.subarray(0, n), 0);
  return out;
}
function pad20(b: Bytes): Bytes {
  return pad(b, 20);
}
