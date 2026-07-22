// Wire decoder (protocol-spec.md §1/§2/§3; SPEC-conformance.md §9). Strict, fail-closed: turns a
// carrier payload + its output value into ACTION | POST | IGNORE. Any field/length mismatch, bad
// prefix, or invalid name ⇒ IGNORE. Indexers MUST agree byte-for-byte (§0).
//
// All value-bearing fields (price, window, vote target is just bytes) are read straight to bigint.
import type { Bytes } from "./bytes.ts";
import { rdLE, rdU32 } from "./bytes.ts";
import { validUtf8 } from "./utf8.ts";
import { OP, OP_MIN, OP_MAX, PREFIX0, PREFIX1, PREFIX2 } from "./constants.ts";

export type DecodeKind = "ACTION" | "POST" | "IGNORE";

export type Action =
  | { op: typeof OP.VOTE_UP | typeof OP.VOTE_DOWN; target: Bytes; vout: number }
  | { op: typeof OP.COMMIT; commitment: Bytes }
  | { op: typeof OP.CLAIM; salt: Bytes; name: Bytes }
  | { op: typeof OP.RENEW; mode: "all" | "all-safe" | "selective"; anchor: bigint; flags: Bytes }
  | { op: typeof OP.TRANSFER; mode: "all" | "selective"; target: Bytes; anchor: bigint; flags: Bytes }
  | { op: typeof OP.SELL; price: bigint; window: bigint; name: Bytes }
  | { op: typeof OP.RESERVE | typeof OP.SETTLE | typeof OP.PAY; name: Bytes }
  | { op: typeof OP.RELEASE; anchor: bigint; flags: Bytes }
  | { op: typeof OP.DECORATE; body: Bytes }
  | { op: typeof OP.SELL_TO; price: bigint; buyer: Bytes; name: Bytes }
  | { op: typeof OP.AS; index: number }
  | { op: typeof OP.TRADE; idxA: number; idxB: number; nameA: Bytes; nameB: Bytes };

export type DecodeResult =
  | { kind: "ACTION"; action: Action }
  | { kind: "POST" }
  | { kind: "IGNORE" };

const IGNORE: DecodeResult = { kind: "IGNORE" };
const POST: DecodeResult = { kind: "POST" };

// §3.1 name validation: charset [a-z0-9-] (a DNS label), length 1..32. NOTE (see SPEC-RATIONALE.md):
// the prose also says "the canonical key is the lowercase form", but the charset admits only
// lowercase, and §9 says a non-name byte ⇒ IGNORE — so we REJECT uppercase rather than lowercase it.
// Re-pin 2026-07-07: '.'/'_' dropped, '-' added (supersedes the 2026-07-02 dot rule); no structural
// rules — '-a', 'a-', 'xn--x' are all valid names.
export function isNameByte(c: number): boolean {
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x2d;
}
export function validName(b: Bytes): boolean {
  if (b.length < 1 || b.length > 32) return false;
  for (let i = 0; i < b.length; i++) if (!isNameByte(b[i])) return false;
  return true;
}

// §1: a carrier's scriptPubKey MUST be exactly `OP_RETURN <one minimal push of P≤80 bytes>`.
// Multi-push / non-minimal push / trailing opcode ⇒ not a carrier (⊥). Returns the payload bytes,
// or null for ⊥. (The fold treats null as "ignore".) OP_RETURN = 0x6a.
export function singleMinimalPush(spk: Bytes): Bytes | null {
  if (spk.length < 1 || spk[0] !== 0x6a) return null; // not OP_RETURN
  let i = 1;
  if (i >= spk.length) {
    // bare OP_RETURN, empty payload — len 0. §1 requires one push; treat empty as ⊥ (no push).
    return null;
  }
  const op = spk[i];
  let pushLen: number;
  let dataStart: number;
  if (op >= 0x01 && op <= 0x4b) {
    pushLen = op; dataStart = i + 1;
  } else if (op === 0x4c) {
    // OP_PUSHDATA1
    if (i + 2 > spk.length) return null;
    pushLen = spk[i + 1]; dataStart = i + 2;
    if (pushLen < 0x4c) return null; // non-minimal: <76 must use direct push
  } else if (op === 0x4d) {
    // OP_PUSHDATA2
    if (i + 3 > spk.length) return null;
    pushLen = spk[i + 1] | (spk[i + 2] << 8); dataStart = i + 3;
    if (pushLen <= 0xff) return null; // non-minimal: ≤255 must use PUSHDATA1
  } else {
    return null; // OP_0, OP_1..OP_16, or any non-push opcode as first item ⇒ not a single data push
  }
  if (pushLen > 80) return null; // P ≤ 80 (§0)
  const dataEnd = dataStart + pushLen;
  if (dataEnd !== spk.length) return null; // trailing bytes/opcodes ⇒ ⊥ (must be EXACTLY one push)
  return spk.subarray(dataStart, dataEnd);
}

// §9 decoder: payload bytes + output value ⇒ ACTION | POST | IGNORE.
export function decodePayload(payload: Bytes, value: bigint): DecodeResult {
  const len = payload.length;
  // action-prefix iff len≥4 and FF 50 4E and opcode in 0x01..0x0F (§6 pseudocode).
  if (
    len >= 4 &&
    payload[0] === PREFIX0 &&
    payload[1] === PREFIX1 &&
    payload[2] === PREFIX2 &&
    payload[3] >= OP_MIN &&
    payload[3] <= OP_MAX
  ) {
    const act = decodeAction(payload);
    return act ? { kind: "ACTION", action: act } : IGNORE; // malformed action ⇒ IGNORE, never POST
  }
  // POST iff (not an action prefix) and value>0 and len≥1 and whole-payload strict UTF-8 (§1/§9).
  if (value > 0n && len >= 1 && validUtf8(payload)) return POST;
  return IGNORE;
}

function decodeAction(payload: Bytes): Action | null {
  const op = payload[3];
  const b = payload.subarray(4); // body
  const bl = b.length;
  switch (op) {
    case OP.VOTE_UP:
    case OP.VOTE_DOWN: {
      if (bl !== 36) return null;
      return { op, target: b.subarray(0, 32), vout: rdU32(b, 32) };
    }
    case OP.COMMIT: {
      if (bl !== 32) return null;
      return { op: OP.COMMIT, commitment: b.subarray(0, 32) };
    }
    case OP.CLAIM: {
      if (bl < 33 || bl > 64) return null; // salt32 + name1..32
      const name = b.subarray(32);
      if (!validName(name)) return null;
      return { op: OP.CLAIM, salt: b.subarray(0, 32), name };
    }
    case OP.RENEW: {
      if (bl === 0) return { op: OP.RENEW, mode: "all", anchor: 0n, flags: new Uint8Array(0) };
      if (bl === 5) return { op: OP.RENEW, mode: "all-safe", anchor: rdLE(b, 0, 5), flags: new Uint8Array(0) };
      if (bl >= 6 && bl <= 76)
        return { op: OP.RENEW, mode: "selective", anchor: rdLE(b, 0, 5), flags: b.subarray(5) };
      return null; // bl ∈ {1,2,3,4} or >76 invalid
    }
    case OP.TRANSFER: {
      if (bl === 20)
        return { op: OP.TRANSFER, mode: "all", target: b.subarray(0, 20), anchor: 0n, flags: new Uint8Array(0) };
      if (bl >= 26 && bl <= 76)
        return {
          op: OP.TRANSFER, mode: "selective", target: b.subarray(0, 20),
          anchor: rdLE(b, 20, 5), flags: b.subarray(25),
        };
      return null; // bl ∈ [21,25], <20, >76 invalid
    }
    case OP.SELL: {
      if (bl < 13 || bl > 44) return null; // price8 + window4 + name1..32
      const name = b.subarray(12);
      if (!validName(name)) return null;
      return { op: OP.SELL, price: rdLE(b, 0, 8), window: rdLE(b, 8, 4), name };
    }
    case OP.RESERVE:
    case OP.SETTLE:
    case OP.PAY: {
      if (bl < 1 || bl > 32) return null; // name1..32
      const name = b.subarray(0);
      if (!validName(name)) return null;
      return { op, name };
    }
    case OP.RELEASE: {
      if (bl < 6 || bl > 76) return null; // anchor5 + flags1..71
      return { op: OP.RELEASE, anchor: rdLE(b, 0, 5), flags: b.subarray(5) };
    }
    case OP.DECORATE: {
      if (bl > 80) return null; // bl 0..80 = SM_DEC_MAX raw TLV (fold parses); matches C reference
      return { op: OP.DECORATE, body: b.subarray(0) };
    }
    case OP.SELL_TO: {
      if (bl < 29 || bl > 60) return null; // price8 + buyer20 + name1..32
      const name = b.subarray(28);
      if (!validName(name)) return null;
      return { op: OP.SELL_TO, price: rdLE(b, 0, 8), buyer: b.subarray(8, 28), name };
    }
    case OP.AS: {
      if (bl !== 1) return null;
      return { op: OP.AS, index: b[0] };
    }
    case OP.TRADE: {
      if (bl < 5) return null; // idxA1 + idxB1 + nameA,nameB (≥ "a,b")
      const idxA = b[0];
      const idxB = b[1];
      const rest = b.subarray(2);
      // split on the SINGLE 0x2C comma; comma ∉ name charset so the separator is unambiguous (§3.10)
      let commaPos = -1;
      let commaCount = 0;
      for (let i = 0; i < rest.length; i++) {
        if (rest[i] === 0x2c) {
          commaCount++;
          commaPos = i;
        }
      }
      if (commaCount !== 1) return null; // exactly one comma
      const nameA = rest.subarray(0, commaPos);
      const nameB = rest.subarray(commaPos + 1);
      if (!validName(nameA) || !validName(nameB)) return null;
      return { op: OP.TRADE, idxA, idxB, nameA, nameB };
    }
    default:
      return null;
  }
}
