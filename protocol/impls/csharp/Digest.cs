using System;
using System.Collections.Generic;
using System.Buffers.Binary;

namespace Shibpost;

/// <summary>
/// Canonical SHA-256 state digest (SPEC-conformance §4). All multi-byte integers
/// little-endian; signed two's-complement LE; i128 = 16 bytes LE. Sorts are
/// explicit and unsigned-bytewise; Dictionary/HashSet enumeration never feeds the
/// digest (brief). Written with BinaryPrimitives (host-endian-independent).
/// </summary>
public static class Digest
{
    public static byte[] Compute(Fold f)
    {
        var buf = new Buf();
        buf.Ascii("SMv1");

        // ---- names: sorted ascending by raw name bytes ----
        var names = new List<NameRow>(f.Names.Values);
        names.Sort((a, b) => ByteArrayComparer.Instance.Compare(a.Name, b.Name));
        buf.U32((uint)names.Count);
        foreach (var r in names)
        {
            buf.U8((byte)r.Name.Length);
            buf.Bytes(r.Name);
            buf.Fixed(r.Owner, 20);
            buf.U8(r.St);
            buf.I64(r.LeaseExpiry);
            buf.Fixed(r.Seller, 20);
            buf.U8(r.SellerType);
            buf.U64(r.Price);
            buf.I64(r.OfferExpiry);
            buf.Fixed(r.Buyer, 20);
            buf.U64(r.BurnLeg);
            buf.U64(r.PayLeg);
            buf.I64(r.ReserveExpiry);
        }

        // ---- commits: sorted by (commitment[32], commit_height, tx_index) — total order ----
        var commits = new List<CommitRow>(f.Commits);
        commits.Sort((a, b) =>
        {
            int c = ByteArrayComparer.Instance.Compare(a.Commitment, b.Commitment);
            if (c != 0) return c;
            c = a.CommitHeight.CompareTo(b.CommitHeight);
            if (c != 0) return c;
            return a.TxIndex.CompareTo(b.TxIndex);
        });
        buf.U32((uint)commits.Count);
        foreach (var c in commits)
        {
            buf.Fixed(c.Commitment, 32);
            buf.I64(c.CommitHeight);
            buf.U32(c.TxIndex);
            buf.I64(c.CommitTime);
        }

        // ---- votes: sorted by (target[32], vout) ----
        var votes = new List<(byte[] target, uint vout, Int128 score)>();
        foreach (var kv in f.VoteScore)
        {
            var (target, vout) = f.VoteKeyInfo[kv.Key];
            votes.Add((target, vout, kv.Value));
        }
        votes.Sort((a, b) =>
        {
            int c = ByteArrayComparer.Instance.Compare(a.target, b.target);
            if (c != 0) return c;
            return a.vout.CompareTo(b.vout);
        });
        buf.U32((uint)votes.Count);
        foreach (var v in votes)
        {
            buf.Fixed(v.target, 32);
            buf.U32(v.vout);
            buf.I128(v.score);
        }

        // ---- muts: sorted by owner bytes ----
        var muts = new List<(byte[] owner, long h)>();
        foreach (var kv in f.Muts)
            muts.Add((f.MutOwnerBytes[kv.Key], kv.Value));
        muts.Sort((a, b) => ByteArrayComparer.Instance.Compare(a.owner, b.owner));
        buf.U32((uint)muts.Count);
        foreach (var m in muts)
        {
            buf.Fixed(m.owner, 20);
            buf.I64(m.h);
        }

        // ---- decors: sorted by (txid[32], vout) STABLE (insertion order within a post) ----
        var decorsIdx = new List<(DecorRow row, int orig)>();
        for (int i = 0; i < f.Decors.Count; i++) decorsIdx.Add((f.Decors[i], i));
        decorsIdx.Sort((a, b) =>
        {
            int c = ByteArrayComparer.Instance.Compare(a.row.Txid, b.row.Txid);
            if (c != 0) return c;
            c = a.row.Vout.CompareTo(b.row.Vout);
            if (c != 0) return c;
            return a.orig.CompareTo(b.orig); // stable tiebreak = insertion order
        });
        buf.U32((uint)decorsIdx.Count);
        foreach (var (row, _) in decorsIdx)
        {
            buf.Fixed(row.Txid, 32);
            buf.U32(row.Vout);
            buf.U8((byte)row.Rec.Length);
            buf.Bytes(row.Rec);
        }

        buf.U8(f.OverflowFlag);

        return Hashing.Sha256(buf.ToSpan());
    }

    public static string ComputeHex(Fold f) => Hashing.Hex(Compute(f));

    private sealed class Buf
    {
        private byte[] _b = new byte[256];
        private int _len;

        private void Ensure(int n) { if (_len + n > _b.Length) Array.Resize(ref _b, Math.Max(_b.Length * 2, _len + n)); }
        public void U8(byte v) { Ensure(1); _b[_len++] = v; }
        public void Bytes(byte[] v) { Ensure(v.Length); Buffer.BlockCopy(v, 0, _b, _len, v.Length); _len += v.Length; }
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
            // 16 bytes LE two's complement: reinterpret bit pattern via UInt128.
            UInt128 u = unchecked((UInt128)v);
            ulong lo = (ulong)(u & (UInt128)ulong.MaxValue);
            ulong hi = (ulong)(u >> 64);
            U64(lo); U64(hi);
        }
        public ReadOnlySpan<byte> ToSpan() => _b.AsSpan(0, _len);
    }
}
