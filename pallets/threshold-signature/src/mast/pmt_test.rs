use super::*;
use super::{
    serialize,
    deserialize,
    pmt::PartialMerkleTree,
    mast::tagged_branch,
};
use core::cmp::min;
use hashes::hex::FromHex;
use rand::{thread_rng, Rng};

#[test]
fn pmt_tests() {
    let mut rng = thread_rng();
    let script_counts = vec![3, 5];

    for num_script in script_counts {
        // Create some fake script ids
        let script_ids = (1..num_script + 1) // change to `1..=num_tx` when min Rust >= 1.26.0
            .map(|i| ScriptId::from_hex(&format!("{:064x}", i)).unwrap())
            .collect::<Vec<_>>();

        // Calculate the merkle root and height
        // let hashes = script_ids.iter().map(|t| t.as_hash());
        let mut height = 1;
        let mut ntx = num_script;
        while ntx > 1 {
            ntx = (ntx + 1) / 2;
            height += 1;
        }

        // Check with random subsets with inclusion chances 1, 1/2, 1/4, ..., 1/128
        for att in 1..2 {
            let mut matches = vec![false; num_script];
            let mut match_txid1 = vec![];
            for j in 0..num_script {
                // Generate `att / 2` random bits
                let rand_bits = match att / 2 {
                    0 => 0,
                    bits => rng.gen::<u64>() >> (64 - bits),
                };
                let include = rand_bits == 0;
                matches[j] = include;

                if include {
                    match_txid1.push(script_ids[j]);
                };
            }

            // Build the partial merkle tree
            let pmt1 = PartialMerkleTree::from_script_ids(&script_ids, &matches).unwrap();
            let serialized = serialize(&pmt1);

            // Verify PartialMerkleTree's size guarantees
            let n = min(num_script, 1 + match_txid1.len() * height);
            assert!(serialized.len() <= 13 + (290 * n + 7) / 8);

            // Deserialize into a tester copy
            let pmt2: PartialMerkleTree =
                deserialize(&serialized).expect("Could not deserialize own data");

            // Extract merkle root and matched txids from copy
            let mut match_txid2: Vec<ScriptId> = vec![];
            let mut indexes = vec![];
            let merkle_root_2 = pmt2
                .extract_matches(&mut match_txid2, &mut indexes)
                .expect("Could not extract matches");

            // Check that it has the same merkle root as the original, and a valid one
            // assert_eq!(merkle_root_1, merkle_root_2);
            assert_ne!(merkle_root_2, ScriptMerkleNode::default());

            // check that it contains the matched transactions (in the same order!)
            assert_eq!(match_txid1, match_txid2);
        }
    }
}

#[test]
fn pmt_encode_decode_should_work() {
    let txids: Vec<ScriptId> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 9, 10]
        .iter()
        .map(|i| ScriptId::from_hex(&format!("{:064x}", i)).unwrap())
        .collect();

    let matches = vec![
        false, false, false, false, false, false, false, false, false, false, false, true,
    ];
    let pmt = PartialMerkleTree::from_script_ids(&txids, &matches).unwrap();
    let serialized = serialize(&pmt);
    let pmt1 = deserialize::<PartialMerkleTree>(&serialized).unwrap();
    assert_eq!(pmt, pmt1)
}

#[test]
fn pmt_proof_generate_correct_order() {
    let txids: Vec<ScriptId> = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        .iter()
        .map(|i| ScriptId::from_hex(&format!("{:064x}", i)).unwrap())
        .collect();

    let matches = vec![
        false, false, false, false, false, false, false, false, false, false, false, true,
    ];
    let tree = PartialMerkleTree::from_script_ids(&txids, &matches).unwrap();
    let mut matches_vec = vec![];
    let mut indexes = vec![];
    let root = tree
        .extract_matches(&mut matches_vec, &mut indexes)
        .unwrap();

    let proofs = tree.collected_hashes();
    let mut root1 = proofs[0];
    for i in 1..proofs.len() {
        root1 = tagged_branch(root1, proofs[i]).unwrap();
    }
    assert_eq!(root, root1)
}
