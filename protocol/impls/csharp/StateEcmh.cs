using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Shibpost;

/// <summary>
/// §13.2 ECMH state digest — the incremental twin of Digest.Compute. Five per-table
/// Elliptic-Curve Multiset Hash sub-accumulators over the SAME canonical per-row
/// encoding Digest uses (so the two digests induce the identical equality relation),
/// combined into one 32-byte value. A point-sum is order-independent and invertible.
/// Mirrors impls/c/src/ecmh.c (sm_state_ecmh). Reuses the ECMH primitive in
/// Secp256k1.cs and the per-row field layout from Digest.cs (no count prefix, no
/// "SMv1"/overflow framing — just the per-row field bytes).
/// </summary>
public static class StateEcmh
{
    // domain tags — second-preimage separation between tables (match ecmh.c).
    private const byte TagName = 0x01, TagCommit = 0x02, TagVote = 0x03, TagMut = 0x04, TagDecor = 0x05;
    private static readonly byte[] RecTag = { (byte)'E', (byte)'C', (byte)'M', (byte)'H', (byte)'v', (byte)'1' };

    public static byte[] Compute(Fold f)
    {
        byte[] an = Secp256k1.EcmhIdentity(), ac = Secp256k1.EcmhIdentity(), av = Secp256k1.EcmhIdentity();
        byte[] am = Secp256k1.EcmhIdentity(), ad = Secp256k1.EcmhIdentity();

        foreach (var r in f.Names.Values)
        {
            var b = new Row();
            b.U8((byte)r.Name.Length); b.Bytes(r.Name);
            b.Fixed(r.Owner, 20);                       // owner_type NOT encoded (matches Digest)
            b.U8(r.St); b.I64(r.LeaseExpiry);
            b.Fixed(r.Seller, 20); b.U8(r.SellerType);
            b.U64(r.Price); b.I64(r.OfferExpiry);
            b.Fixed(r.Buyer, 20);
            b.U64(r.BurnLeg); b.U64(r.PayLeg); b.I64(r.ReserveExpiry);
            FoldRow(an, TagName, b);
        }
        foreach (var c in f.Commits)
        {
            var b = new Row();
            b.Fixed(c.Commitment, 32); b.I64(c.CommitHeight);
            b.U32(c.TxIndex); b.I64(c.CommitTime);
            FoldRow(ac, TagCommit, b);
        }
        foreach (var kv in f.VoteScore)
        {
            var (target, vout) = f.VoteKeyInfo[kv.Key];
            var b = new Row();
            b.Fixed(target, 32); b.U32(vout); b.I128(kv.Value);
            FoldRow(av, TagVote, b);
        }
        foreach (var kv in f.Muts)
        {
            var b = new Row();
            b.Fixed(f.MutOwnerBytes[kv.Key], 20); b.I64(kv.Value);
            FoldRow(am, TagMut, b);
        }
        foreach (var d in f.Decors)
        {
            var b = new Row();
            b.Fixed(d.Txid, 32); b.U32(d.Vout);
            b.U8((byte)d.Rec.Length); b.Bytes(d.Rec);
            FoldRow(ad, TagDecor, b);
        }

        // combined = SHA256("ECMHtop1" ‖ the five sub-accumulators ‖ overflow flag).
        var top = new Row();
        top.Ascii("ECMHtop1");
        top.Raw(an); top.Raw(ac); top.Raw(av); top.Raw(am); top.Raw(ad);
        top.U8((byte)(f.OverflowFlag != 0 ? 1 : 0));
        return Hashing.Sha256(top.ToArray());
    }

    public static string ComputeHex(Fold f) => Hashing.Hex(Compute(f));

    // acc ← acc + H2C("ECMHv1" ‖ tag ‖ row_bytes).
    private static void FoldRow(byte[] acc, byte tag, Row r)
    {
        byte[] rb = r.ToArray();
        byte[] pre = new byte[6 + 1 + rb.Length];
        Buffer.BlockCopy(RecTag, 0, pre, 0, 6);
        pre[6] = tag;
        Buffer.BlockCopy(rb, 0, pre, 7, rb.Length);
        Secp256k1.EcmhHash(pre, out byte[] pt);
        Secp256k1.EcmhAdd(acc, pt);
    }

    // per-row byte buffer — byte-identical field encoding to Digest.cs's Buf.
    private sealed class Row
    {
        private byte[] _b = new byte[64];
        private int _len;
        private void Ensure(int n) { if (_len + n > _b.Length) Array.Resize(ref _b, Math.Max(_b.Length * 2, _len + n)); }
        public void U8(byte v) { Ensure(1); _b[_len++] = v; }
        public void Bytes(byte[] v) { Ensure(v.Length); Buffer.BlockCopy(v, 0, _b, _len, v.Length); _len += v.Length; }
        public void Raw(byte[] v) => Bytes(v);
        public void Fixed(byte[] v, int n)
        {
            Ensure(n);
            int copy = Math.Min(n, v.Length);
            Buffer.BlockCopy(v, 0, _b, _len, copy);
            for (int i = copy; i < n; i++) _b[_len + i] = 0;
            _len += n;
        }
        public void Ascii(string s) { Ensure(s.Length); foreach (char c in s) _b[_len++] = (byte)c; }
        public void U32(uint v) { Ensure(4); BinaryPrimitives.WriteUInt32LittleEndian(_b.AsSpan(_len, 4), v); _len += 4; }
        public void U64(ulong v) { Ensure(8); BinaryPrimitives.WriteUInt64LittleEndian(_b.AsSpan(_len, 8), v); _len += 8; }
        public void I64(long v) { Ensure(8); BinaryPrimitives.WriteInt64LittleEndian(_b.AsSpan(_len, 8), v); _len += 8; }
        public void I128(Int128 v)
        {
            UInt128 u = unchecked((UInt128)v);
            U64((ulong)(u & (UInt128)ulong.MaxValue));
            U64((ulong)(u >> 64));
        }
        public byte[] ToArray() { byte[] r = new byte[_len]; Buffer.BlockCopy(_b, 0, r, 0, _len); return r; }
    }
}
