use super::encode::{Decodable, Encodable, Error};
use hashes::{hash_newtype, sha256, sha256d, sha256t, Hash};
use std::io;

macro_rules! impl_hashencode {
    ($hashtype:ident) => {
        impl Encodable for $hashtype {
            fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
                self.0.consensus_encode(s)
            }
        }

        impl Decodable for $hashtype {
            fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
                use $crate::hashes::Hash;
                Ok(Self::from_inner(
                    <<$hashtype as $crate::hashes::Hash>::Inner>::consensus_decode(d)?,
                ))
            }
        }
    };
}

/// The SHA-256 midstate value for the TapLeaf hash.
pub const MIDSTATE_TAPLEAF: [u8; 32] = [
    156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15, 80, 137, 211, 243, 147, 108,
    71, 99, 110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
];
// 9ce0e4e67c116c3938b3caf2c30f5089d3f3936c47636e607db33eeaddc6f0c9

/// The SHA-256 midstate value for the TapBranch hash.
pub const MIDSTATE_TAPBRANCH: [u8; 32] = [
    35, 168, 101, 169, 184, 164, 13, 167, 151, 124, 30, 4, 196, 158, 36, 111, 181, 190, 19, 118,
    157, 36, 201, 183, 181, 131, 181, 212, 168, 210, 38, 210,
];
// 23a865a9b8a40da7977c1e04c49e246fb5be13769d24c9b7b583b5d4a8d226d2

/// The SHA-256 midstate value for the TapTweak hash.
pub const MIDSTATE_TAPTWEAK: [u8; 32] = [
    209, 41, 162, 243, 112, 28, 101, 93, 101, 131, 182, 195, 185, 65, 151, 39, 149, 244, 226, 50,
    148, 253, 84, 244, 162, 174, 141, 133, 71, 202, 89, 11,
];
// d129a2f3701c655d6583b6c3b941972795f4e23294fd54f4a2ae8d8547ca590b

/// The SHA-256 midstate value for the TapSigHash hash.
pub const MIDSTATE_TAPSIGHASH: [u8; 32] = [
    245, 4, 164, 37, 215, 248, 120, 59, 19, 99, 134, 138, 227, 229, 86, 88, 110, 238, 148, 93, 188,
    120, 136, 221, 2, 166, 226, 195, 24, 115, 254, 159,
];
// f504a425d7f8783b1363868ae3e556586eee945dbc7888dd02a6e2c31873fe9f

/// Internal macro to speficy the different taproot tagged hashes.
macro_rules! sha256t_hash_newtype {
    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr) => {
        sha256t_hash_newtype!(
            $newtype,
            $tag,
            $midstate,
            $midstate_len,
            $docs,
            $reverse,
            stringify!($newtype)
        );
    };

    ($newtype:ident, $tag:ident, $midstate:ident, $midstate_len:expr, $docs:meta, $reverse: expr, $sname:expr) => {
        #[doc = "The tag used for ["]
        #[doc = $sname]
        #[doc = "]"]
        pub struct $tag;

        impl sha256t::Tag for $tag {
            fn engine() -> sha256::HashEngine {
                let midstate = sha256::Midstate::from_inner($midstate);
                sha256::HashEngine::from_midstate(midstate, $midstate_len)
            }
        }

        hash_newtype!($newtype, sha256t::Hash<$tag>, 32, $docs, $reverse);
    };
}

// Currently all taproot hashes are defined as being displayed backwards,
// but that can be specified individually per hash.
sha256t_hash_newtype!(
    TapLeafHash,
    TapLeafTag,
    MIDSTATE_TAPLEAF,
    64,
    doc = "Taproot-tagged hash for tapscript Merkle tree leafs",
    true
);
sha256t_hash_newtype!(
    TapBranchHash,
    TapBranchTag,
    MIDSTATE_TAPBRANCH,
    64,
    doc = "Taproot-tagged hash for tapscript Merkle tree branches",
    true
);
sha256t_hash_newtype!(
    TapTweakHash,
    TapTweakTag,
    MIDSTATE_TAPTWEAK,
    64,
    doc = "Taproot-tagged hash for public key tweaks",
    true
);
sha256t_hash_newtype!(
    TapSighashHash,
    TapSighashTag,
    MIDSTATE_TAPSIGHASH,
    64,
    doc = "Taproot-tagged hash for the taproot signature hash",
    true
);

hash_newtype!(
    ScriptId,
    sha256d::Hash,
    32,
    doc = "A bitcoin transaction hash/transaction ID."
);
hash_newtype!(
    ScriptMerkleNode,
    sha256d::Hash,
    32,
    doc = "A hash of the Merkle tree branch or root for transactions"
);

impl_hashencode!(ScriptId);
impl_hashencode!(ScriptMerkleNode);
