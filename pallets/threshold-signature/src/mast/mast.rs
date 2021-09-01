#![allow(dead_code)]
#![allow(clippy::module_inception)]
use super::{
    error::Result, key::PrivateKey, pmt::PartialMerkleTree, serialize, ScriptId, ScriptMerkleNode,
    TapBranchHash, TapLeafHash, TapTweakHash, VarInt,
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec, vec::Vec};
use bech32::{self, u5, CheckBase32, Variant};
use hashes::{
    hex::{FromHex, ToHex},
    Hash,
};

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
        // Ok(hex::encode(program))
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

#[cfg(test)]
mod mast_tests {
    use super::*;
    use bech32::{u5, ToBase32, Variant};
    use hashes::hex::ToHex;

    #[test]
    fn test_ser_compact_size_tests() {
        let r1 = serialize(&VarInt(34_u64));
        let r2 = serialize(&VarInt(253_u64));
        let r3 = serialize(&VarInt(254_u64));
        let r4 = serialize(&VarInt(255_u64));
        let r5 = serialize(&VarInt(55555_u64));
        let r6 = serialize(&VarInt(666666_u64));
        let r7 = serialize(&VarInt(999999999_u64));
        let r8 = serialize(&VarInt(10000000000000_u64));

        assert_eq!(r1.to_hex(), "22");
        assert_eq!(r2.to_hex(), "fdfd00");
        assert_eq!(r3.to_hex(), "fdfe00");
        assert_eq!(r4.to_hex(), "fdff00");
        assert_eq!(r5.to_hex(), "fd03d9");
        assert_eq!(r6.to_hex(), "fe2a2c0a00");
        assert_eq!(r7.to_hex(), "feffc99a3b");
        assert_eq!(r8.to_hex(), "ff00a0724e18090000");
    }

    #[test]
    fn mast_generate_root_should_work() {
        let script_a = XOnly::parse_slice(
            &hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9")
                .unwrap(),
        )
        .unwrap();
        let script_b = XOnly::parse_slice(
            &hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
                .unwrap(),
        )
        .unwrap();
        let script_c = XOnly::parse_slice(
            &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
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
        let script_a = XOnly::parse_slice(
            &hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9")
                .unwrap(),
        )
        .unwrap();
        let script_b = XOnly::parse_slice(
            &hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
                .unwrap(),
        )
        .unwrap();
        let script_c = XOnly::parse_slice(
            &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
                .unwrap(),
        )
        .unwrap();
        let scripts = vec![script_a.clone(), script_b, script_c];
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
        let internal_key = XOnly::parse_slice(
            &hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9")
                .unwrap(),
        )
        .unwrap();

        let script_a = XOnly::parse_slice(
            &hex::decode("D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9")
                .unwrap(),
        )
        .unwrap();
        let script_b = XOnly::parse_slice(
            &hex::decode("EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34")
                .unwrap(),
        )
        .unwrap();
        let script_c = XOnly::parse_slice(
            &hex::decode("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
                .unwrap(),
        )
        .unwrap();
        let scripts = vec![script_a, script_b, script_c];
        let mast = Mast { scripts };
        let root = mast.calc_root().unwrap();
        println!("root is {:?}", root);

        let bech32_addr = mast.generate_address(&internal_key);
        println!("bech32 addr is {:?}", bech32_addr);

        assert_eq!(
            "4ac28f45b41d96319f16141ec8433362f35cadb1a44a0e40aea424a5ef34d828",
            root.to_hex()
        );
    }
}
