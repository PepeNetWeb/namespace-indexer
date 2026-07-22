//! Strict, fail-closed wire decoder (§0/§1/§2 + conformance §9).
//! A malformed action NEVER panics — it returns Ignore. ACTION | POST | IGNORE.

use crate::types::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    VoteUp { target: [u8; 32], vout: u32 },
    VoteDown { target: [u8; 32], vout: u32 },
    Commit { commitment: [u8; 32] },
    Claim { salt: [u8; 32], name: Vec<u8> },
    Renew { mode: RenewMode },
    Transfer { target: Hash160, sel: Option<BitmapSel> },
    Sell { price: u64, window: u32, name: Vec<u8> },
    Reserve { name: Vec<u8> },
    Settle { name: Vec<u8> },
    Release { anchor: i64, flags: Vec<u8> },
    Decorate { raw: Vec<u8> },
    SellTo { price: u64, buyer: Hash160, name: Vec<u8> },
    Pay { name: Vec<u8> },
    As { index: u8 },
    Trade { idx_a: u8, idx_b: u8, name_a: Vec<u8>, name_b: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewMode {
    All,                              // bl == 0
    AllSafe { anchor: i64 },          // bl == 5
    Selective { anchor: i64, flags: Vec<u8> }, // bl 6..=76
}

/// A bitmap selection (anchor + flag bytes), used by TRANSFER selective.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitmapSel {
    pub anchor: i64,
    pub flags: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    Action(Action),
    Post(Vec<u8>),
    Ignore,
}

#[inline]
fn rd_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
#[inline]
fn rd_u64_le(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}
/// 5-byte little-endian height anchor → i64 (fits comfortably).
#[inline]
fn rd_h5_le(b: &[u8]) -> i64 {
    (b[0] as i64)
        | ((b[1] as i64) << 8)
        | ((b[2] as i64) << 16)
        | ((b[3] as i64) << 24)
        | ((b[4] as i64) << 32)
}

/// Top-level demux. `value` is the OP_RETURN output value (for the post burn gate).
pub fn decode_payload(payload: &[u8], value: u64) -> Decoded {
    // ACTION prefix test: len>=4 and FF 50 4E + opcode.
    if payload.len() >= 4 && payload[0] == 0xFF && payload[1] == 0x50 && payload[2] == 0x4E {
        return match decode_action(payload[3], &payload[4..]) {
            Some(a) => Decoded::Action(a),
            None => Decoded::Ignore, // 0xFF lead is never valid UTF-8 ⇒ never a post
        };
    }
    // POST: not action prefix, value>0, len>=1, whole payload strict UTF-8.
    if value > 0 && !payload.is_empty() && valid_utf8(payload) {
        return Decoded::Post(payload.to_vec());
    }
    Decoded::Ignore
}

fn decode_action(opcode: u8, b: &[u8]) -> Option<Action> {
    let bl = b.len();
    match opcode {
        OP_VOTE_UP | OP_VOTE_DOWN => {
            if bl != 36 {
                return None;
            }
            let mut target = [0u8; 32];
            target.copy_from_slice(&b[..32]);
            let vout = rd_u32_le(&b[32..36]);
            Some(if opcode == OP_VOTE_UP {
                Action::VoteUp { target, vout }
            } else {
                Action::VoteDown { target, vout }
            })
        }
        OP_COMMIT => {
            if bl != 32 {
                return None;
            }
            let mut c = [0u8; 32];
            c.copy_from_slice(&b[..32]);
            Some(Action::Commit { commitment: c })
        }
        OP_CLAIM => {
            // salt32 + name1..32  → bl 33..=64
            if bl < 33 || bl > 64 {
                return None;
            }
            let name = &b[32..];
            if !valid_name(name) {
                return None;
            }
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&b[..32]);
            Some(Action::Claim { salt, name: name.to_vec() })
        }
        OP_RENEW => match bl {
            0 => Some(Action::Renew { mode: RenewMode::All }),
            5 => Some(Action::Renew {
                mode: RenewMode::AllSafe { anchor: rd_h5_le(&b[..5]) },
            }),
            6..=76 => Some(Action::Renew {
                mode: RenewMode::Selective {
                    anchor: rd_h5_le(&b[..5]),
                    flags: b[5..].to_vec(),
                },
            }),
            _ => None, // bl 1..4 invalid
        },
        OP_TRANSFER => {
            // all: bl==20 ; selective: 20+anchor5+flags1..51 → bl 26..=76
            if bl == 20 {
                let mut t = [0u8; 20];
                t.copy_from_slice(&b[..20]);
                Some(Action::Transfer { target: t, sel: None })
            } else if (26..=76).contains(&bl) {
                let mut t = [0u8; 20];
                t.copy_from_slice(&b[..20]);
                let anchor = rd_h5_le(&b[20..25]);
                let flags = b[25..].to_vec();
                Some(Action::Transfer {
                    target: t,
                    sel: Some(BitmapSel { anchor, flags }),
                })
            } else {
                None
            }
        }
        OP_SELL => {
            // price8 + window4 + name1..32 → bl 13..=44
            if bl < 13 || bl > 44 {
                return None;
            }
            let name = &b[12..];
            if !valid_name(name) {
                return None;
            }
            let price = rd_u64_le(&b[..8]);
            let window = rd_u32_le(&b[8..12]);
            Some(Action::Sell { price, window, name: name.to_vec() })
        }
        OP_RESERVE | OP_SETTLE | OP_PAY => {
            // name1..32 → bl 1..=32
            if bl < 1 || bl > 32 {
                return None;
            }
            if !valid_name(b) {
                return None;
            }
            let name = b.to_vec();
            Some(match opcode {
                OP_RESERVE => Action::Reserve { name },
                OP_SETTLE => Action::Settle { name },
                _ => Action::Pay { name },
            })
        }
        OP_RELEASE => {
            // anchor5 + flags1..71 → bl 6..=76
            if bl < 6 || bl > 76 {
                return None;
            }
            let anchor = rd_h5_le(&b[..5]);
            Some(Action::Release { anchor, flags: b[5..].to_vec() })
        }
        OP_DECORATE => {
            // bl 0..=80 raw TLV (SM_DEC_MAX); the fold parses records (fail-closed there).
            if bl > 80 {
                return None;
            }
            Some(Action::Decorate { raw: b.to_vec() })
        }
        OP_SELL_TO => {
            // price8 + buyer20 + name1..32 → bl 29..=60
            if bl < 29 || bl > 60 {
                return None;
            }
            let name = &b[28..];
            if !valid_name(name) {
                return None;
            }
            let price = rd_u64_le(&b[..8]);
            let mut buyer = [0u8; 20];
            buyer.copy_from_slice(&b[8..28]);
            Some(Action::SellTo { price, buyer, name: name.to_vec() })
        }
        OP_AS => {
            if bl != 1 {
                return None;
            }
            Some(Action::As { index: b[0] })
        }
        OP_TRADE => {
            // idxA1 + idxB1 + nameA,nameB ; exactly one 0x2C
            if bl < 5 {
                return None;
            }
            let idx_a = b[0];
            let idx_b = b[1];
            let names = &b[2..];
            // exactly one comma
            let commas = names.iter().filter(|&&c| c == b',').count();
            if commas != 1 {
                return None;
            }
            let pos = names.iter().position(|&c| c == b',').unwrap();
            let name_a = &names[..pos];
            let name_b = &names[pos + 1..];
            if !valid_name(name_a) || !valid_name(name_b) {
                return None;
            }
            Some(Action::Trade {
                idx_a,
                idx_b,
                name_a: name_a.to_vec(),
                name_b: name_b.to_vec(),
            })
        }
        _ => None, // unknown opcode (incl. 0x00, 0x10..) → not an action
    }
}

/// Strict RFC-3629 UTF-8: reject overlong, surrogates U+D800..U+DFFF, > U+10FFFF.
pub fn valid_utf8(b: &[u8]) -> bool {
    let mut i = 0;
    let n = b.len();
    while i < n {
        let c = b[i];
        if c < 0x80 {
            i += 1;
        } else if c >> 5 == 0b110 {
            // 2-byte: U+0080..U+07FF
            if i + 1 >= n || (b[i + 1] & 0xC0) != 0x80 {
                return false;
            }
            let cp = ((c as u32 & 0x1F) << 6) | (b[i + 1] as u32 & 0x3F);
            if cp < 0x80 {
                return false; // overlong
            }
            i += 2;
        } else if c >> 4 == 0b1110 {
            // 3-byte: U+0800..U+FFFF, excluding surrogates
            if i + 2 >= n || (b[i + 1] & 0xC0) != 0x80 || (b[i + 2] & 0xC0) != 0x80 {
                return false;
            }
            let cp = ((c as u32 & 0x0F) << 12)
                | ((b[i + 1] as u32 & 0x3F) << 6)
                | (b[i + 2] as u32 & 0x3F);
            if cp < 0x800 {
                return false; // overlong
            }
            if (0xD800..=0xDFFF).contains(&cp) {
                return false; // surrogate
            }
            i += 3;
        } else if c >> 3 == 0b11110 {
            // 4-byte: U+10000..U+10FFFF
            if i + 3 >= n
                || (b[i + 1] & 0xC0) != 0x80
                || (b[i + 2] & 0xC0) != 0x80
                || (b[i + 3] & 0xC0) != 0x80
            {
                return false;
            }
            let cp = ((c as u32 & 0x07) << 18)
                | ((b[i + 1] as u32 & 0x3F) << 12)
                | ((b[i + 2] as u32 & 0x3F) << 6)
                | (b[i + 3] as u32 & 0x3F);
            if cp < 0x10000 || cp > 0x10FFFF {
                return false; // overlong or out of range
            }
            i += 4;
        } else {
            return false; // 0xFF, 0x80-continuation lead, 0xF8+, etc.
        }
    }
    true
}
