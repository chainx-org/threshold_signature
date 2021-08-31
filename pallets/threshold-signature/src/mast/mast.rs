#![allow(dead_code)]
use super::error::Result;
use super::{
    key::PrivateKey, pmt::PartialMerkleTree, serialize, ScriptId, ScriptMerkleNode, TapBranchHash,
    TapLeafHash, TapTweakHash, VarInt,
};
use bech32::{self, u5, CheckBase32, Variant};
use hashes::{
    hex::{FromHex, ToHex},
    Hash,
};
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::String};

pub type XOnly = PrivateKey;

/// Data structure that represents a partial mast tree
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Mast {
    /// All leaf nodes of the mast tree
    pub scripts: Vec<XOnly>,
}

impl Mast {
    /// calculate merkle root
    pub fn calc_root(&self) -> Result<ScriptMerkleNode> {
        let script_ids = self
            .scripts
            .iter()
            .map(|s| tagged_leaf(s))
            .collect::<Result<Vec<_>>>()?;

        let mut matches = vec![true];
        matches.extend(&vec![false; self.scripts.len() - 1]);
        let pmt = PartialMerkleTree::from_script_ids(&script_ids, &matches)?;
        let mut matches_vec: Vec<ScriptId> = vec![];
        let mut indexes_vec: Vec<u32> = vec![];
        pmt.extract_matches(&mut matches_vec, &mut indexes_vec)
    }

    /// generate merkle proof
    pub fn generate_merkle_proof(&self, script: &XOnly) -> Result<Vec<ScriptMerkleNode>> {
        assert!(self
            .scripts
            .iter()
            .any(|s| s.serialize() == script.serialize()));
        let mut matches = vec![];
        for s in self.scripts.iter() {
            if s.serialize() == script.serialize() {
                matches.push(true)
            } else {
                matches.push(false)
            }
        }
        let script_ids = self
            .scripts
            .iter()
            .map(|s| tagged_leaf(s))
            .collect::<Result<Vec<_>>>()?;
        Ok(PartialMerkleTree::from_script_ids(&script_ids, &matches)?.collected_hashes())
    }

    /// generate threshold signature address
    pub fn generate_address(&self, inner_pubkey: &XOnly) -> Result<String> {
        let root = self.calc_root()?;
        let mut x: Vec<u8> = vec![];
        x.extend(&inner_pubkey.serialize());
        x.extend(&root.to_vec());
        let program = TapTweakHash::hash(&x).to_vec();
        // todo!(May need to add btc testnet prefix or other prefix.)
        // https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#Test_vectors_for_Bech32m
        let mut data = vec![u5::try_from_u8(1).expect("It will definitely be converted to u5")];
        data.extend(program.check_base32()?);
        Ok(bech32::encode("bc", data, Variant::Bech32m)?)
    }
}

/// Calculate the leaf nodes from the script
///
/// tagged_hash("TapLeaf", bytes([leaf_version]) + ser_script(script))
pub fn tagged_leaf(script: &XOnly) -> Result<ScriptId> {
    let mut x: Vec<u8> = vec![];
    x.extend(hex::decode("c0")?.iter());
    let script_hash = script.serialize();
    let ser_len = serialize(&VarInt(script_hash.len() as u64));
    x.extend(&ser_len);
    x.extend(&script_hash);
    Ok(ScriptId::from_hex(&TapLeafHash::hash(&x).to_hex())?)
}

/// Calculate branch nodes from left and right children
///
/// tagged_hash("TapBranch", left + right)). The left and right nodes are lexicographic order
pub fn tagged_branch(
    script_left: ScriptMerkleNode,
    script_right: ScriptMerkleNode,
) -> Result<ScriptMerkleNode> {
    // If the hash of the left and right leaves is the same, it means that the total number of leaves is odd
    //
    // In this case, the parent hash is computed without copying
    // Note: `TapLeafHash` will replace the `TapBranchHash`
    if script_left != script_right {
        let mut x: Vec<u8> = vec![];
        let (script_left, script_right) = lexicographical_compare(script_left, script_right);
        x.extend(script_left.to_vec().iter());
        x.extend(script_right.to_vec().iter());

        Ok(ScriptMerkleNode::from_hex(
            &TapBranchHash::hash(&x).to_hex(),
        )?)
    } else {
        Ok(script_left)
    }
}

/// Lexicographic order of left and right nodes
fn lexicographical_compare(
    script_left: ScriptMerkleNode,
    script_right: ScriptMerkleNode,
) -> (ScriptMerkleNode, ScriptMerkleNode) {
    if script_right.to_vec() < script_left.to_vec() {
        (script_right, script_left)
    } else {
        (script_left, script_right)
    }
}
