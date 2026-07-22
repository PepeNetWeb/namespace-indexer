// MY OWN internally-consistent seed-driven generator (NOT the doc's). The exact draw-order that the
// frozen seed goldens depend on is defined by impls/c/src/gen.c — FORBIDDEN for this exercise — so
// this generator uses my own draw order and WILL NOT reproduce the doc's frozen `state_digest` /
// `input_digest` goldens (SPEC-conformance.md §6/§9). That is expected and stated plainly; I do not
// fake a match. Its value: exercise the fold deterministically at scale and prove same-seed →
// same-digest internally (a real cross-run determinism check).
import { SplitMix64 } from "./prng.ts";
import { Fold } from "./fold.ts";
import type { FoldTx } from "./fold.ts";
import { sha256 } from "./sha256.ts";
import { concat, u8, u32le, u64le, hex, type Bytes } from "./bytes.ts";
import * as B from "./builders.ts";
import { N_IDS, BASE_TS } from "./constants.ts";

// op weights (conformance §5) — used as relative frequencies under MY OWN draw order.
const WEIGHTS = [12, 12, 14, 13, 5, 5, 8, 7, 7, 3, 6, 5, 4]; // POST,VOTE,COMMIT,CLAIM,RENEW,...
const W_SUM = WEIGHTS.reduce((a, b) => a + b, 0);

type PendingCommit = { salt: Bytes; name: string; author: number };

function nameOf(i: number): string {
  return "n" + i.toString(36); // base36 digits 0-9a-z (matches §5 name_of style)
}

export function runGenerator(seed: bigint, blocks: number): { inputDigest: string; stateDigest: string } {
  const r = new SplitMix64(seed);
  const f = new Fold(0n);
  let ts = BASE_TS;
  let input = new Uint8Array(0); // streaming input digest accumulator (running sha256)
  const recentCommits: PendingCommit[] = []; // commits to claim next block
  let nameCounter = 0;

  for (let h = 1; h <= blocks; h++) {
    ts += BigInt(300 + r.boundedN(600));
    const rate = 28n * (1n + r.bounded(4));
    const mtp = ts; // simplified: use the per-block ts as MTP (own model; not the §2 median)
    f.beginBlock(BigInt(h), mtp, rate);

    // claim any pending commits from prior blocks (so names actually mint)
    const toClaim = recentCommits.splice(0, recentCommits.length);
    let txIndex = 0;
    for (const pc of toClaim) {
      if (r.boundedN(4) === 0) continue; // sometimes let a commit lapse
      const id = B.genId(pc.author);
      const tx = B.tx([B.input(id, B.genType(pc.author))], [B.claim(pc.salt, pc.name, 1n + r.bounded(120))]);
      input = sha256(concat(input, hashTx(tx, txIndex)));
      f.applyTx(tx, txIndex++);
    }

    const nTx = 1 + r.boundedN(8);
    for (let t = 0; t < nTx; t++) {
      const tx = buildTx(r, f, recentCommits, () => nameOf(nameCounter++));
      if (tx) {
        input = sha256(concat(input, hashTx(tx, txIndex)));
        f.applyTx(tx, txIndex++);
      }
    }
  }
  return { inputDigest: hex(input), stateDigest: hex(f.digest()) };
}

function buildTx(r: SplitMix64, f: Fold, commits: PendingCommit[], freshName: () => string): FoldTx | null {
  const idn = r.boundedN(N_IDS);
  const id = B.genId(idn);
  const inp = B.input(id, B.genType(idn));
  // pick an op by weight
  let x = r.boundedN(W_SUM);
  let op = 0;
  for (; op < WEIGHTS.length; op++) { if (x < WEIGHTS[op]) break; x -= WEIGHTS[op]; }

  switch (op) {
    case 0: // POST
      return B.tx([inp], [B.postCarrier("post-" + r.boundedN(1000), 1n)]);
    case 1: { // VOTE
      const target = new Uint8Array(32);
      target[0] = r.boundedN(256);
      const up = r.boundedN(2) === 0;
      const w = 1n + r.bounded(1000);
      return B.tx([inp], [up ? B.voteUp(target, 0, w) : B.voteDown(target, 0, w)]);
    }
    case 2: { // COMMIT (queue a claim for next block)
      const name = freshName();
      const salt = new Uint8Array(32);
      salt[0] = r.boundedN(256); salt[1] = r.boundedN(256);
      commits.push({ salt, name, author: idn });
      return B.tx([inp], [B.commit(B.commitmentOf(salt, name, id))]);
    }
    case 4: // RENEW all
      return B.tx([inp], [B.renewAll(1n + r.bounded(120))]);
    case 5: { // TRANSFER all → random other id
      const tgt = B.genId(r.boundedN(N_IDS));
      return B.tx([inp], [B.transferAll(tgt)]);
    }
    case 6: { // SELL a name the id owns (if any)
      const owned = ownedOf(f, id);
      if (owned.length === 0) return B.tx([inp], [B.postCarrier("noop", 1n)]);
      const name = owned[r.boundedN(owned.length)];
      return B.tx([inp], [B.sell(3n + r.bounded(100000), 18000n + r.bounded(50000), name)]);
    }
    default: // CLAIM/RESERVE/SETTLE/RELEASE/SELL_TO/PAY/TRADE: emit a harmless VOTE to keep flowing
      return B.tx([inp], [B.voteUp(new Uint8Array(32), 0, 1n + r.bounded(10))]);
  }
}

function ownedOf(f: Fold, id: Bytes): string[] {
  const dec = new TextDecoder();
  const out: string[] = [];
  for (const r of f.names.values()) if (hex(r.owner) === hex(id) && r.st === 0) out.push(dec.decode(r.name));
  return out;
}

function hashTx(tx: FoldTx, txIndex: number): Bytes {
  // fixed serialization for the input digest (MY layout, not §9's hash_tx)
  const parts: Bytes[] = [u32le(txIndex), u8(tx.inputs.length)];
  for (const i of tx.inputs) parts.push(concat(i.id ?? new Uint8Array(20), u8(i.type), u8(i.sighashAll ? 1 : 0)));
  parts.push(u8(tx.carriers.length));
  for (const c of tx.carriers) parts.push(concat(u32le(c.payload.length), c.payload, u64le(c.value), u32le(c.vout)));
  parts.push(u8(tx.outputs.length));
  for (const o of tx.outputs) parts.push(concat(u8(o.type), o.hash, u64le(o.value)));
  return concat(...parts);
}
