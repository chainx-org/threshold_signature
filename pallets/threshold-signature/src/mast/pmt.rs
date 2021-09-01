// Refer from https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/merkleblock.rs
#![allow(dead_code)]
use super::{
    error::{MastError, Result},
    hash_types::*,
    mast::tagged_branch,
    *,
};
use core::result;
use hashes::Hash;

/// Data structure that represents a partial merkle tree.
///
/// It represents a subset of the script_id's of a known script, in a way that
/// allows recovery of the list of script_id's and the merkle root, in an
/// authenticated way.
///
/// The encoding works as follows: we traverse the tree in depth-first order,
/// storing a bit for each traversed node, signifying whether the node is the
/// parent of at least one matched leaf script_id (or a matched script_id itself). In
/// case we are at the leaf level, or this bit is 0, its merkle node hash is
/// stored, and its children are not explored further. Otherwise, no hash is
/// stored, but we recurse into both (or the only) child branch. During
/// decoding, the same depth-first traversal is performed, consuming bits and
/// hashes as they written during encoding.
///
/// The serialization is fixed and provides a hard guarantee about the
/// encoded size:
///
///   SIZE <= 13 + ceil(36.25*N)
///
/// Where N represents the number of leaf nodes of the partial tree. N itself
/// is bounded by:
///
///   N <= total_scripts
///   N <= 1 + matched_scripts*tree_height
///
/// The serialization format:
///  - uint32     total_scripts (4 bytes)
///  - varint     number of hashes   (1-3 bytes)
///  - uint256[]  hashes in depth-first order (<= 32*N bytes)
///  - varint     number of bytes of flag bits (1-3 bytes)
///  - byte[]     flag bits, packed per 8 in a byte, least significant bit first (<= 2*N-1 bits)
///  - varint     number of heights   (1-3 bytes)
///  - uint256[]  the height of hashes (<= 4*N bytes)
/// The size constraints follow from this.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PartialMerkleTree {
    /// The total number of scripts in the tree
    num_scripts: u32,
    /// node-is-parent-of-matched-script_id bits
    bits: Vec<bool>,
    /// Transaction ids and internal hashes
    hashes: Vec<ScriptMerkleNode>,
    /// The height of hashes
    heights: Vec<u32>,
}

impl PartialMerkleTree {
    /// Construct a partial merkle tree
    /// The `script_ids` are the script hashes of the script and the `matches` is the contains flags
    /// wherever a script_id hash should be included in the proof.
    ///
    /// Panics when `script_ids` is empty or when `matches` has a different length
    /// ```
    pub fn from_script_ids(script_ids: &[ScriptId], matches: &[bool]) -> Result<Self> {
        // We can never have zero scripts in a merkle script
        assert_ne!(script_ids.len(), 0);
        assert_eq!(script_ids.len(), matches.len());

        let mut pmt = PartialMerkleTree {
            num_scripts: script_ids.len() as u32,
            bits: Vec::with_capacity(script_ids.len()),
            hashes: vec![],
            heights: vec![],
        };
        // calculate height of tree
        let height = pmt.calc_tree_height();

        // traverse the partial tree
        if let Ok(()) = pmt.traverse_and_build(height, 0, script_ids, matches) {
            Ok(pmt)
        } else {
            Err(MastError::MastBuildError)
        }
    }

    /// Extract the matching script_id's represented by this partial merkle tree
    /// and their respective indices within the partial tree.
    /// returns the merkle root, or error in case of failure
    pub fn extract_matches(
        &self,
        matches: &mut Vec<ScriptId>,
        indexes: &mut Vec<u32>,
    ) -> Result<ScriptMerkleNode> {
        matches.clear();
        indexes.clear();
        // An empty set will not work
        if self.num_scripts == 0 {
            return Err(MastError::NoScripts);
        };
        // check for excessively high numbers of scripts
        // if self.num_scripts > MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT {
        //     return Err(TooManyTransactions);
        // }
        // there can never be more hashes provided than one for every script_id
        if self.hashes.len() as u32 > self.num_scripts {
            return Err(MastError::BadFormat(
                "Proof contains more hashes than scripts".to_owned(),
            ));
        };
        // there must be at least one bit per node in the partial tree, and at least one node per hash
        if self.bits.len() < self.hashes.len() {
            return Err(MastError::BadFormat(
                "Proof contains less bits than hashes".to_owned(),
            ));
        };

        // calculate height of tree
        let height = self.calc_tree_height();
        // traverse the partial tree
        let mut bits_used = 0u32;
        let mut hash_used = 0u32;
        let hash_merkle_root =
            self.traverse_and_extract(height, 0, &mut bits_used, &mut hash_used, matches, indexes)?;
        // Verify that all bits were consumed (except for the padding caused by
        // serializing it as a byte sequence)
        if (bits_used + 7) / 8 != (self.bits.len() as u32 + 7) / 8 {
            return Err(MastError::BadFormat("Not all bit were consumed".to_owned()));
        }
        // Verify that all hashes were consumed
        if hash_used != self.hashes.len() as u32 {
            return Err(MastError::BadFormat(
                "Not all hashes were consumed".to_owned(),
            ));
        }
        Ok(ScriptMerkleNode::from_inner(hash_merkle_root.into_inner()))
    }

    /// Helper function to efficiently calculate the number of nodes at given height
    /// in the merkle tree
    #[inline]
    fn calc_tree_width(&self, height: u32) -> u32 {
        (self.num_scripts + (1 << height) - 1) >> height
    }

    /// Helper function to efficiently calculate the height of merkle tree
    fn calc_tree_height(&self) -> u32 {
        let mut height = 0u32;
        while self.calc_tree_width(height) > 1 {
            height += 1;
        }
        height
    }

    /// Calculate the hash of a node in the merkle tree (at leaf level: the script_id's themselves)
    fn calc_hash(
        &self,
        height: u32,
        pos: u32,
        script_ids: &[ScriptId],
    ) -> Result<ScriptMerkleNode> {
        if height == 0 {
            // Hash at height 0 is the script_id itself
            Ok(ScriptMerkleNode::from_inner(
                script_ids[pos as usize].into_inner(),
            ))
        } else {
            // Calculate left hash
            let left = self.calc_hash(height - 1, pos * 2, script_ids)?;
            // Calculate right hash if not beyond the end of the array - copy left hash otherwise
            let right = if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                self.calc_hash(height - 1, pos * 2 + 1, script_ids)?
            } else {
                left
            };
            // Combine subhashes
            // PartialMerkleTree::parent_hash(left, right)
            Ok(tagged_branch(left, right)?)
        }
    }

    /// Recursive function that traverses tree nodes, storing the data as bits and hashes
    fn traverse_and_build(
        &mut self,
        height: u32,
        pos: u32,
        script_ids: &[ScriptId],
        matches: &[bool],
    ) -> Result<()> {
        // Determine whether this node is the parent of at least one matched script_id
        let mut parent_of_match = false;
        let mut p = pos << height;
        while p < (pos + 1) << height && p < self.num_scripts {
            parent_of_match |= matches[p as usize];
            p += 1;
        }
        // Store as flag bit
        self.bits.push(parent_of_match);

        if height == 0 || !parent_of_match {
            // If at height 0, or nothing interesting below, store hash and stop
            let hash = self.calc_hash(height, pos, script_ids)?;
            self.hashes.push(hash);
            self.heights.push(height);
        } else {
            // Otherwise, don't store any hash, but descend into the subtrees
            self.traverse_and_build(height - 1, pos * 2, script_ids, matches)?;
            if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                self.traverse_and_build(height - 1, pos * 2 + 1, script_ids, matches)?;
            }
        }

        Ok(())
    }

    /// Recursive function that traverses tree nodes, consuming the bits and hashes produced by
    /// TraverseAndBuild. It returns the hash of the respective node and its respective index.
    fn traverse_and_extract(
        &self,
        height: u32,
        pos: u32,
        bits_used: &mut u32,
        hash_used: &mut u32,
        matches: &mut Vec<ScriptId>,
        indexes: &mut Vec<u32>,
    ) -> Result<ScriptMerkleNode> {
        if *bits_used as usize >= self.bits.len() {
            return Err(MastError::BadFormat("Overflowed the bits array".to_owned()));
        }
        let parent_of_match = self.bits[*bits_used as usize];
        *bits_used += 1;
        if height == 0 || !parent_of_match {
            // If at height 0, or nothing interesting below, use stored hash and do not descend
            if *hash_used as usize >= self.hashes.len() {
                return Err(MastError::BadFormat("Overflowed the hash array".to_owned()));
            }
            let hash = self.hashes[*hash_used as usize];
            *hash_used += 1;
            if height == 0 && parent_of_match {
                // in case of height 0, we have a matched script_id
                matches.push(ScriptId::from_inner(hash.into_inner()));
                indexes.push(pos);
            }
            Ok(hash)
        } else {
            // otherwise, descend into the subtrees to extract matched script_ids and hashes
            let left = self.traverse_and_extract(
                height - 1,
                pos * 2,
                bits_used,
                hash_used,
                matches,
                indexes,
            )?;
            let right;
            if pos * 2 + 1 < self.calc_tree_width(height - 1) {
                right = self.traverse_and_extract(
                    height - 1,
                    pos * 2 + 1,
                    bits_used,
                    hash_used,
                    matches,
                    indexes,
                )?;
                if right == left {
                    // The left and right branches should never be identical, as the script
                    // hashes covered by them must each be unique.
                    return Err(MastError::BadFormat(
                        "Found identical script hashes".to_owned(),
                    ));
                }
            } else {
                right = left;
            }
            // and combine them before returning
            // Ok(PartialMerkleTree::parent_hash(left, right))
            Ok(tagged_branch(left, right)?)
        }
    }

    /// Helper method to produce SHA256D(left + right)
    fn parent_hash(left: ScriptMerkleNode, right: ScriptMerkleNode) -> Result<ScriptMerkleNode> {
        let mut encoder = ScriptMerkleNode::engine();
        left.consensus_encode(&mut encoder)?;
        right.consensus_encode(&mut encoder)?;
        Ok(ScriptMerkleNode::from_engine(encoder))
    }

    pub fn collected_hashes(&self) -> Vec<ScriptMerkleNode> {
        let mut zipped = self.hashes.iter().zip(&self.heights).collect::<Vec<_>>();
        zipped.sort_unstable_by_key(|(_, h)| **h);
        zipped.into_iter().map(|(a, _)| *a).collect::<Vec<_>>()
    }
}

impl Encodable for PartialMerkleTree {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> result::Result<usize, io::Error> {
        let ret =
            self.num_scripts.consensus_encode(&mut s)? + self.hashes.consensus_encode(&mut s)?;
        let mut bytes: Vec<u8> = vec![0; (self.bits.len() + 7) / 8];
        for p in 0..self.bits.len() {
            bytes[p / 8] |= (self.bits[p] as u8) << (p % 8) as u8;
        }
        Ok(ret + bytes.consensus_encode(&mut s)? + self.heights.consensus_encode(s)?)
    }
}

impl Decodable for PartialMerkleTree {
    fn consensus_decode<D: io::Read>(mut d: D) -> result::Result<Self, encode::Error> {
        let num_scripts: u32 = Decodable::consensus_decode(&mut d)?;
        let hashes: Vec<ScriptMerkleNode> = Decodable::consensus_decode(&mut d)?;

        let bytes: Vec<u8> = Decodable::consensus_decode(&mut d)?;
        let mut bits: Vec<bool> = vec![false; bytes.len() * 8];

        for (p, bit) in bits.iter_mut().enumerate() {
            *bit = (bytes[p / 8] & (1 << (p % 8) as u8)) != 0;
        }
        let heights: Vec<u32> = Decodable::consensus_decode(d)?;

        Ok(PartialMerkleTree {
            num_scripts,
            hashes,
            bits,
            heights,
        })
    }
}

#[cfg(test)]
mod pmt_tests {
    use super::*;
    use core::cmp::min;
    use encode::{deserialize, serialize};
    use hashes::hex::FromHex;
    use rand::{thread_rng, Rng};

    #[cfg(not(feature = "std"))]
    use alloc::{vec, vec::Vec};

    #[test]
    fn pmt_tests() {
        let mut rng = thread_rng();
        let script_counts = vec![3, 5];

        for num_script in script_counts {
            // Create some fake script ids
            let script_ids =
                (1..num_script + 1) // change to `1..=num_tx` when min Rust >= 1.26.0
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
        for i in proofs.iter().skip(1) {
            root1 = tagged_branch(root1, *i).unwrap();
        }
        assert_eq!(root, root1)
    }
}
