"""Strict, fail-closed wire decoder (protocol-spec.md §0/§1/§2, SPEC-conformance.md §9).

Turns an OP_RETURN payload into ACTION | POST | IGNORE. Any malformed field or
length mismatch => IGNORE (fail closed). A malformed input never raises.

Decode operates on the *payload* = the bytes of the single minimal push (§1).
`single_minimal_push` extracts that from a raw scriptPubKey for completeness.
"""
from const import (PREFIX, OP_VOTE_UP, OP_VOTE_DOWN, OP_COMMIT, OP_CLAIM,
                   OP_RENEW, OP_TRANSFER, OP_SELL, OP_RESERVE, OP_SETTLE,
                   OP_RELEASE, OP_DECORATE, OP_SELL_TO, OP_PAY, OP_AS, OP_TRADE)

IGNORE = "IGNORE"
POST = "POST"
ACTION = "ACTION"

_NAME_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789-")


def valid_name(b):
    """§3.1: charset [a-z0-9-] (a DNS label), length 1..32, byte-for-byte (no case fold).
    Re-pin 2026-07-07: '.'/'_' dropped, '-' added (supersedes the 2026-07-02 dot rule).
    No structural rules — '-a', 'a-', 'xn--x' are valid names; uppercase stays invalid."""
    if not (1 <= len(b) <= 32):
        return False
    for ch in b:
        if ch not in _NAME_BYTES:
            return False
    return True


def valid_utf8(b):
    """§1 strict RFC-3629: reject overlong, surrogates, > U+10FFFF.
    CPython's strict utf-8 decoder enforces exactly this (see SPEC-RATIONALE.md)."""
    if len(b) < 1:
        return False
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def single_minimal_push(spk):
    """Extract the lone minimal data push from `OP_RETURN <push>` (§1).
    Returns payload bytes, or None if the script is not exactly OP_RETURN + one
    minimal push (multi-push / non-minimal / trailing opcode => None)."""
    if len(spk) < 1 or spk[0] != 0x6A:  # OP_RETURN
        return None
    i = 1
    n = len(spk)
    if i >= n:
        return None  # bare OP_RETURN, no push -> not a carrier
    op = spk[i]
    i += 1
    if op == 0x00:  # OP_0 pushes empty; minimal for empty data
        data = b""
    elif 1 <= op <= 75:
        if op == 0:
            return None
        data = spk[i:i + op]
        if len(data) != op:
            return None
        # minimal: a 1-byte value in 1..16 or 0x81 should use OP_N, but for
        # OP_RETURN payloads we treat any direct 1..75 push as the carrier; the
        # spec's "minimal push" only forbids over-long length prefixes here.
        i += op
    elif op == 0x4C:  # OP_PUSHDATA1
        if i >= n:
            return None
        ln = spk[i]
        i += 1
        if ln < 76:  # non-minimal: must use direct push
            return None
        data = spk[i:i + ln]
        if len(data) != ln:
            return None
        i += ln
    elif op == 0x4D:  # OP_PUSHDATA2
        if i + 2 > n:
            return None
        ln = int.from_bytes(spk[i:i + 2], "little")
        i += 2
        if ln < 256:
            return None
        data = spk[i:i + ln]
        if len(data) != ln:
            return None
        i += ln
    else:
        return None
    if i != n:
        return None  # trailing bytes / extra opcode
    if len(data) > 80:
        return None
    return data


def _u32(b):
    return int.from_bytes(b, "little")


def _u64(b):
    return int.from_bytes(b, "little")


def decode_payload(payload, value):
    """Return (kind, info).
    kind == ACTION  -> info is a dict {op, ...fields}
    kind == POST    -> info is the payload bytes
    kind == IGNORE  -> info is None
    Never raises (fail closed)."""
    try:
        return _decode(payload, value)
    except Exception:
        return (IGNORE, None)


def _decode(payload, value):
    n = len(payload)
    # ACTION prefix test: len>=4, payload[0:3]==FF 50 4E
    if n >= 4 and payload[0:3] == PREFIX:
        op = payload[3]
        b = payload[4:]
        bl = n - 4
        info = _decode_action(op, b, bl)
        if info is None:
            return (IGNORE, None)   # malformed action: 0xFF lead is never UTF-8
        info["op"] = op
        return (ACTION, info)
    # POST: not an action prefix, value>0, len>=1, whole payload strict UTF-8
    if value > 0 and n >= 1 and valid_utf8(payload):
        return (POST, payload)
    return (IGNORE, None)


def _decode_action(op, b, bl):
    """Return a field dict on success, else None. (caller maps None -> IGNORE)"""
    if op in (OP_VOTE_UP, OP_VOTE_DOWN):
        if bl != 36:
            return None
        return {"target": b[0:32], "vout": _u32(b[32:36])}

    if op == OP_COMMIT:
        if bl != 32:
            return None
        return {"commitment": b[0:32]}

    if op == OP_CLAIM:
        if not (33 <= bl <= 64):   # salt32 + name1..32
            return None
        salt = b[0:32]
        name = b[32:]
        if not valid_name(name):
            return None
        return {"salt": salt, "name": name}

    if op == OP_RENEW:
        if bl == 0:
            return {"mode": "all"}
        if bl == 5:
            return {"mode": "all_safe", "anchor": _u32_5(b[0:5])}
        if 6 <= bl <= 76:
            return {"mode": "selective", "anchor": _u32_5(b[0:5]),
                    "flags": b[5:]}
        return None

    if op == OP_TRANSFER:
        if bl == 20:
            return {"mode": "all", "target": b[0:20]}
        if 26 <= bl <= 76:
            return {"mode": "selective", "target": b[0:20],
                    "anchor": _u32_5(b[20:25]), "flags": b[25:]}
        return None

    if op == OP_SELL:
        if not (13 <= bl <= 44):   # price8 + window4 + name1..32
            return None
        price = _u64(b[0:8])
        window = _u32(b[8:12])
        name = b[12:]
        if not valid_name(name):
            return None
        return {"price": price, "window": window, "name": name}

    if op in (OP_RESERVE, OP_SETTLE, OP_PAY):
        if not (1 <= bl <= 32):    # name1..32
            return None
        name = b[0:bl]
        if not valid_name(name):
            return None
        return {"name": name}

    if op == OP_RELEASE:
        if not (6 <= bl <= 76):
            return None
        return {"anchor": _u32_5(b[0:5]), "flags": b[5:]}

    if op == OP_DECORATE:
        if not (0 <= bl <= 80):    # SM_DEC_MAX raw TLV bytes (C reference guard; blen ≤ 80)
            return None
        return {"raw": bytes(b)}   # fold parses TLV records

    if op == OP_SELL_TO:
        if not (29 <= bl <= 60):   # price8 + buyer20 + name1..32
            return None
        price = _u64(b[0:8])
        buyer = b[8:28]
        name = b[28:]
        if not valid_name(name):
            return None
        return {"price": price, "buyer": buyer, "name": name}

    if op == OP_AS:
        if bl != 1:
            return None
        return {"index": b[0]}

    if op == OP_TRADE:
        if bl < 5:
            return None
        idxA = b[0]
        idxB = b[1]
        rest = b[2:]
        if rest.count(0x2C) != 1:
            return None
        i = rest.index(0x2C)
        nameA = rest[0:i]
        nameB = rest[i + 1:]
        if not valid_name(nameA) or not valid_name(nameB):
            return None
        return {"idxA": idxA, "idxB": idxB, "nameA": nameA, "nameB": nameB}

    return None  # unknown opcode (0x00 or 0x10+)


def _u32_5(b):
    """5-byte little-endian height anchor (§0)."""
    return int.from_bytes(b, "little")
