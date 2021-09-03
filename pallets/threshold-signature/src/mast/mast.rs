#![allow(dead_code)]
#![allow(clippy::module_inception)]

use core::ops::AddAssign;

use super::error::MastError;
use super::XOnly;
use super::{
    error::Result, pmt::PartialMerkleTree, serialize, ScriptId, ScriptMerkleNode, TapBranchHash,
    TapLeafHash, TapTweakHash, VarInt,
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};
use bech32::{self, u5, ToBase32, Variant};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use frame_support::sp_tracing::debug;
use hashes::{
    hex::{FromHex, ToHex},
    Hash,
};
use schnorrkel::PublicKey;

use sp_core::sp_std::ops::Deref;

/// Data structure that represents a partial mast tree
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Mast {
    /// All leaf nodes of the mast tree
    pub scripts: Vec<XOnly>,
}

impl Mast {
    /// Create a mast instance
    pub fn new(scripts: Vec<XOnly>) -> Self {
        Mast { scripts }
    }

    /// calculate merkle root
    pub fn calc_root(&self) -> Result<ScriptMerkleNode> {
        let script_ids = self
            .scripts
            .iter()
            .map(|s| tagged_leaf(s))
            .collect::<Result<Vec<_>>>()?;

        let mut matches = vec![true];

        if self.scripts.len() < 2 {
            return Err(MastError::MastBuildError);
        }
        matches.extend(&vec![false; self.scripts.len() - 1]);
        let pmt = PartialMerkleTree::from_script_ids(&script_ids, &matches)?;
        let mut matches_vec: Vec<ScriptId> = vec![];
        let mut indexes_vec: Vec<u32> = vec![];
        pmt.extract_matches(&mut matches_vec, &mut indexes_vec)
    }

    /// generate merkle proof
    pub fn generate_merkle_proof(&self, script: &XOnly) -> Result<Vec<ScriptMerkleNode>> {
        let proof = {
            assert!(self.scripts.iter().any(|s| *s == *script));
            let mut matches = vec![];
            for s in self.scripts.iter() {
                if *s == *script {
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
        };

        if let Err(e) = proof {
            debug!("Mast genegerate address meet err: {:?}", e);
            Err(MastError::MastGenProofError)
        } else {
            proof
        }
    }

    /// generate threshold signature address
    pub fn generate_address(&self, inner_pubkey: &XOnly) -> Result<String> {
        let addr = {
            let root = self.calc_root()?;
            let program = tweak_pubkey(inner_pubkey, &root)?;
            try_to_bench32m(&program)
        };

        if let Err(e) = addr {
            debug!("Mast genegerate address meet err: {:?}", e);
            Err(MastError::MastGenAddrError)
        } else {
            addr
        }
    }
}

/// Calculate the leaf nodes from the script
///
/// tagged_hash("TapLeaf", bytes([leaf_version]) + ser_script(script))
pub fn tagged_leaf(script: &XOnly) -> Result<ScriptId> {
    let mut x: Vec<u8> = vec![];
    x.extend(hex::decode("c0")?.iter());
    let ser_len = serialize(&VarInt(32u64))?;
    x.extend(&ser_len);
    x.extend(script.deref());
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

/// Compute tweak public key
pub fn tweak_pubkey(inner_pubkey: &[u8; 32], root: &ScriptMerkleNode) -> Result<Vec<u8>> {
    // P + hash_tweak(P||root)G
    let mut x: Vec<u8> = vec![];
    x.extend(inner_pubkey);
    x.extend(&root.to_vec());
    let tweak_key = TapTweakHash::hash(&x);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&tweak_key[..]);

    let scalar = Scalar::from_bytes_mod_order(bytes);
    let base_point = RISTRETTO_BASEPOINT_POINT;

    let mut point = base_point * scalar;

    let inner_pubkey = PublicKey::from_bytes(inner_pubkey)?;
    point.add_assign(inner_pubkey.as_point());
    Ok(point.compress().as_bytes().to_vec())
}

/// Convert to bench32m encode
pub fn try_to_bench32m(program: &[u8]) -> Result<String> {
    // May need to add btc testnet prefix or other prefix.
    // https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki#Test_vectors_for_Bech32m
    let mut data = vec![u5::try_from_u8(1)?];
    data.extend(program.to_base32());
    let addr = bech32::encode("bc", data, Variant::Bech32m)?;
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::{u5, ToBase32, Variant};
    use core::convert::TryFrom;
    use hashes::hex::ToHex;

    #[test]
    fn mast_generate_root_should_work() {
        let script_a = XOnly::try_from(
            hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9")
                .unwrap(),
        )
        .unwrap();
        let script_b = XOnly::try_from(
            hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
                .unwrap(),
        )
        .unwrap();
        let script_c = XOnly::try_from(
            hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
                .unwrap(),
        )
        .unwrap();
        let scripts = vec![script_a, script_b, script_c];
        let mast = Mast { scripts };
        let root = mast.calc_root().unwrap();
        println!("root is {:?}", root);

        assert_eq!(
            "4ac28f45b41d96319f16141ec8433362f35cadb1a44a0e40aea424a5ef34d828",
            root.to_hex()
        );
    }

    #[test]
    fn mast_generate_merkle_proof_should_work() {
        let script_a = XOnly::try_from(
            hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9")
                .unwrap(),
        )
        .unwrap();
        let script_b = XOnly::try_from(
            hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
                .unwrap(),
        )
        .unwrap();
        let script_c = XOnly::try_from(
            hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
                .unwrap(),
        )
        .unwrap();
        let scripts = vec![script_a, script_b, script_c];
        let mast = Mast { scripts };
        let proof = mast.generate_merkle_proof(&script_a).unwrap();
        println!(
            "proof is {:?}",
            proof.iter().map(|p| p.to_hex()).collect::<Vec<_>>()
        );

        assert_eq!(
            proof.iter().map(|p| p.to_hex()).collect::<Vec<_>>(),
            vec![
                "c51bcfc34f78ae1518b7feaed7d0702d790d946aa5732cb9ad75d22fcd3917d4",
                "f49b4c19bf53dfcdd50bc565ccca5cfc64226ef20301502f2264b25e2f0adb3a",
                "aa4bc1ce7be6887fad68d95fcf8b0d19788640ead71837ed43a2b518e673ba2f",
            ]
        )
    }

    #[test]
    fn mast_generate_address_should_work() {
        let mut data = vec![u5::try_from_u8(1).unwrap()];
        data.extend(
            hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap()
                .to_base32(),
        );
        let address = bech32::encode("bc", data, Variant::Bech32m).unwrap();
        assert_eq!(
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
            address
        )
    }

    #[test]
    fn test_bech32m_addr() {
        let internal_key = XOnly::try_from(
            hex::decode("881102cd9cf2ee389137a99a2ad88447b9e8b60c350cda71aff049233574c768")
                .unwrap(),
        )
        .unwrap();

        let script_a = XOnly::try_from(
            hex::decode("7c9a72882718402bf909b3c1693af60501c7243d79ecc8cf030fa253eb136861")
                .unwrap(),
        )
        .unwrap();
        let script_b = XOnly::try_from(
            hex::decode("b69af178463918a181a8549d2cfbe77884852ace9d8b299bddf69bedc33f6356")
                .unwrap(),
        )
        .unwrap();
        let script_c = XOnly::try_from(
            hex::decode("a20c839d955cb10e58c6cbc75812684ad3a1a8f24a503e1c07f5e4944d974d3b")
                .unwrap(),
        )
        .unwrap();
        let scripts = vec![script_a, script_b, script_c];
        let mast = Mast { scripts };

        let bech32_addr = mast.generate_address(&internal_key).unwrap();

        assert_eq!(
            "bc1pqqtqf0hs3507fnhm9e669dux9puzz4r0dt9739ts4nzat2da2pysmvuvvd",
            bech32_addr
        );
    }
}
