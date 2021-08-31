#[cfg(test)]
mod tag_test {
    use super::super::hash_types::*;
    use hashes::{hex::ToHex, sha256, sha256t::Tag, Hash, HashEngine};

    fn tag_engine(tag_name: &str) -> sha256::HashEngine {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag_name.as_bytes());
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        engine
    }

    #[test]
    fn test_midstates() {
        // check midstate against hard-coded values
        assert_eq!(
            MIDSTATE_TAPLEAF,
            tag_engine("TapLeaf").midstate().into_inner()
        );
        assert_eq!(
            MIDSTATE_TAPBRANCH,
            tag_engine("TapBranch").midstate().into_inner()
        );
        assert_eq!(
            MIDSTATE_TAPTWEAK,
            tag_engine("TapTweak").midstate().into_inner()
        );
        assert_eq!(
            MIDSTATE_TAPSIGHASH,
            tag_engine("TapSighash").midstate().into_inner()
        );

        // test that engine creation roundtrips
        assert_eq!(
            tag_engine("TapLeaf").midstate(),
            TapLeafTag::engine().midstate()
        );
        assert_eq!(
            tag_engine("TapBranch").midstate(),
            TapBranchTag::engine().midstate()
        );
        assert_eq!(
            tag_engine("TapTweak").midstate(),
            TapTweakTag::engine().midstate()
        );
        assert_eq!(
            tag_engine("TapSighash").midstate(),
            TapSighashTag::engine().midstate()
        );

        // check that hash creation is the same as building into the same engine
        fn empty_hash(tag_name: &str) -> [u8; 32] {
            let mut e = tag_engine(tag_name);
            e.input(&[]);
            sha256::Hash::from_engine(e).into_inner()
        }
        assert_eq!(empty_hash("TapLeaf"), TapLeafHash::hash(&[]).into_inner());
        assert_eq!(
            empty_hash("TapBranch"),
            TapBranchHash::hash(&[]).into_inner()
        );
        assert_eq!(empty_hash("TapTweak"), TapTweakHash::hash(&[]).into_inner());
        assert_eq!(
            empty_hash("TapSighash"),
            TapSighashHash::hash(&[]).into_inner()
        );
    }

    #[test]
    fn test_vectors_core() {
        //! Test vectors taken from Core

        // uninitialized writers
        //   CHashWriter writer = HasherTapLeaf;
        //   writer.GetSHA256().GetHex()
        assert_eq!(
            TapLeafHash::from_engine(TapLeafTag::engine()).to_hex(),
            "cbfa0621df37662ca57697e5847b6abaf92934a1a5624916f8d177a388c21252"
        );
        assert_eq!(
            TapBranchHash::from_engine(TapBranchTag::engine()).to_hex(),
            "dffd9fbe4c21c893fa934f8774eda0e1efdc06f52ffbf5c1533c6f4dec73c353"
        );
        assert_eq!(
            TapTweakHash::from_engine(TapTweakTag::engine()).to_hex(),
            "e4156b45ff9b277dd92a042af9eed8c91f1d037f68f0d6b20001ab749422a48a"
        );
        assert_eq!(
            TapSighashHash::from_engine(TapSighashTag::engine()).to_hex(),
            "03c8b9d47cdb5f7bf924e282ce99ba8d2fe581262a04002907d8bc4a9111bcda"
        );

        // 0-byte
        //   CHashWriter writer = HasherTapLeaf;
        //   writer << std::vector<unsigned char>{};
        //   writer.GetSHA256().GetHex()
        // Note that Core writes the 0 length prefix when an empty vector is written.
        assert_eq!(
            TapLeafHash::hash(&[0]).to_hex(),
            "29589d5122ec666ab5b4695070b6debc63881a4f85d88d93ddc90078038213ed"
        );
        assert_eq!(
            TapBranchHash::hash(&[0]).to_hex(),
            "1deb45569eb6b2da88b5c2ab46d6a64ab08d58a2fdd5f75a24e6c760194b5392"
        );
        assert_eq!(
            TapTweakHash::hash(&[0]).to_hex(),
            "1eea90d42a359c89bbf702ddf6bde140349e95b9e8036ff1c37f04e6b53787cd"
        );
        assert_eq!(
            TapSighashHash::hash(&[0]).to_hex(),
            "cd10c023c300fb9a507dff136370fba1d8a0566667cfafc4099a8803e00dfdc2"
        );
    }
}
