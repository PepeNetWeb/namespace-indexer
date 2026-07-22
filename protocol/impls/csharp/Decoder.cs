using System;

namespace Shibpost;

public enum DecodeKind { Ignore, Post, Action }

/// <summary>Result of the strict, fail-closed wire decode (§9). Never throws.</summary>
public readonly struct Decoded
{
    public readonly DecodeKind Kind;
    public readonly byte Opcode;     // meaningful only when Kind==Action
    public readonly byte[] Body;     // payload[4:] for Action; whole payload for Post; empty for Ignore

    private Decoded(DecodeKind kind, byte opcode, byte[] body) { Kind = kind; Opcode = opcode; Body = body; }

    public static readonly Decoded Ignore = new(DecodeKind.Ignore, 0, Array.Empty<byte>());
    public static Decoded Post(byte[] payload) => new(DecodeKind.Post, 0, payload);
    public static Decoded Action(byte opcode, byte[] body) => new(DecodeKind.Action, opcode, body);
}

public static class Decoder
{
    /// <summary>
    /// sm_decode_payload (SPEC-conformance §9). The carrier MUST already be the
    /// single minimal push (§1); the caller (fold) supplies that payload + the
    /// carrier output value. A 0xFF lead is never valid UTF-8, so a malformed
    /// action is IGNORE, never a POST.
    /// </summary>
    public static Decoded Decode(byte[] payload, ulong value)
    {
        if (payload.Length >= 4 && payload[0] == K.PFX0 && payload[1] == K.PFX1 && payload[2] == K.PFX2)
        {
            byte op = payload[3];
            int bl = payload.Length - 4;
            byte[] body = new byte[bl];
            Array.Copy(payload, 4, body, 0, bl);
            return ValidateAction(op, body) ? Decoded.Action(op, body) : Decoded.Ignore;
        }

        // POST iff (not an action prefix) and value > 0 and len >= 1 and whole payload strict UTF-8.
        if (value > 0 && payload.Length >= 1 && ValidUtf8(payload))
            return Decoded.Post(payload);

        return Decoded.Ignore;
    }

    private static bool ValidateAction(byte op, byte[] b)
    {
        int bl = b.Length;
        switch (op)
        {
            case K.OP_VOTE_UP:
            case K.OP_VOTE_DOWN:
                return bl == 36;                                  // txid32 + vout4
            case K.OP_COMMIT:
                return bl == 32;
            case K.OP_CLAIM:
                return bl >= 33 && bl <= 64 && ValidName(b, 32, bl - 32);  // salt32 + name1..32
            case K.OP_RENEW:
                return bl == 0 || bl == 5 || (bl >= 6 && bl <= 76);        // {0,5}∪[6,76]
            case K.OP_TRANSFER:
                return bl == 20 || (bl >= 26 && bl <= 76);                 // 20 ∪ [26,76]
            case K.OP_SELL:
                return bl >= 13 && bl <= 44 && ValidName(b, 12, bl - 12);  // price8+window4+name1..32
            case K.OP_RESERVE:
            case K.OP_SETTLE:
            case K.OP_PAY:
                return bl >= 1 && bl <= 32 && ValidName(b, 0, bl);         // name 1..32
            case K.OP_RELEASE:
                return bl >= 6 && bl <= 76;                                // anchor5 + flags1..71
            case K.OP_DECORATE:
                return bl >= 0 && bl <= 80;                                // raw TLV (SM_DEC_MAX=80); fold parses
            case K.OP_SELL_TO:
                return bl >= 29 && bl <= 60 && ValidName(b, 28, bl - 28);  // price8+buyer20+name1..32
            case K.OP_AS:
                return bl == 1;
            case K.OP_TRADE:
                return ValidateTrade(b);
            default:
                return false; // opcode outside 0x01..0x0F
        }
    }

    /// <summary>TRADE: bl≥5, exactly one 0x2C, both sides §3.1-valid (1..32). (§9/§3.10)</summary>
    private static bool ValidateTrade(byte[] b)
    {
        if (b.Length < 5) return false;
        // [idxA:1][idxB:1] then nameA,nameB
        int commaCount = 0, commaPos = -1;
        for (int i = 2; i < b.Length; i++)
            if (b[i] == 0x2C) { commaCount++; commaPos = i; }
        if (commaCount != 1) return false;
        int aStart = 2, aLen = commaPos - aStart;
        int bStart = commaPos + 1, bLen = b.Length - bStart;
        return ValidName(b, aStart, aLen) && ValidName(b, bStart, bLen);
    }

    /// <summary>Name validation §3.1: charset [a-z0-9-] (a DNS label), length 1..32, byte-exact,
    /// NO case-folding. Re-pin 2026-07-07: '.'/'_' dropped, '-' added (supersedes the 2026-07-02
    /// dot rule). No structural rules — '-a', 'a-', 'xn--x' are valid names; uppercase invalid.</summary>
    public static bool ValidName(byte[] b, int off, int len)
    {
        if (len < 1 || len > 32) return false;
        if (off < 0 || off + len > b.Length) return false;
        for (int i = 0; i < len; i++)
        {
            byte c = b[off + i];
            bool ok = (c >= (byte)'a' && c <= (byte)'z') ||
                      (c >= (byte)'0' && c <= (byte)'9') ||
                      (c == (byte)'-');
            if (!ok) return false;
        }
        return true;
    }

    /// <summary>
    /// Strict RFC-3629 UTF-8 (§1/§9 sm_valid_utf8). Hand-rolled rather than
    /// trusting BCL fallback nuances: reject overlong, surrogates U+D800..U+DFFF,
    /// and > U+10FFFF. Empty is rejected by the caller's len>=1 gate.
    /// </summary>
    public static bool ValidUtf8(byte[] b)
    {
        int i = 0, n = b.Length;
        while (i < n)
        {
            byte c = b[i];
            if (c <= 0x7F) { i++; continue; }
            if (c >= 0xC2 && c <= 0xDF)
            {
                if (i + 1 >= n || !Cont(b[i + 1])) return false;
                i += 2; continue;
            }
            if (c == 0xE0)
            {
                if (i + 2 >= n || b[i + 1] < 0xA0 || b[i + 1] > 0xBF || !Cont(b[i + 2])) return false;
                i += 3; continue;
            }
            if (c >= 0xE1 && c <= 0xEC)
            {
                if (i + 2 >= n || !Cont(b[i + 1]) || !Cont(b[i + 2])) return false;
                i += 3; continue;
            }
            if (c == 0xED) // exclude surrogates D800..DFFF: second byte 0x80..0x9F
            {
                if (i + 2 >= n || b[i + 1] < 0x80 || b[i + 1] > 0x9F || !Cont(b[i + 2])) return false;
                i += 3; continue;
            }
            if (c >= 0xEE && c <= 0xEF)
            {
                if (i + 2 >= n || !Cont(b[i + 1]) || !Cont(b[i + 2])) return false;
                i += 3; continue;
            }
            if (c == 0xF0) // overlong guard: second byte 0x90..0xBF
            {
                if (i + 3 >= n || b[i + 1] < 0x90 || b[i + 1] > 0xBF || !Cont(b[i + 2]) || !Cont(b[i + 3])) return false;
                i += 4; continue;
            }
            if (c >= 0xF1 && c <= 0xF3)
            {
                if (i + 3 >= n || !Cont(b[i + 1]) || !Cont(b[i + 2]) || !Cont(b[i + 3])) return false;
                i += 4; continue;
            }
            if (c == 0xF4) // cap at U+10FFFF: second byte 0x80..0x8F
            {
                if (i + 3 >= n || b[i + 1] < 0x80 || b[i + 1] > 0x8F || !Cont(b[i + 2]) || !Cont(b[i + 3])) return false;
                i += 4; continue;
            }
            return false; // 0xC0,0xC1, 0xF5..0xFF, lone continuation
        }
        return true;
    }

    private static bool Cont(byte x) => x >= 0x80 && x <= 0xBF;
}
