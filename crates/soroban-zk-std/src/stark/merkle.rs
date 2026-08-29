//! Soroban-optimized Merkle authentication (Issue #366, Phase 3).
//!
//! Verification streams a fixed-size [`MerklePath`] of sibling hashes and folds
//! them with the leaf via the **native SHA-256 host binding** (`env.crypto().
//! sha256`, a single CAP-0075 host call per level). No guest Wasm heap is
//! touched: the only storage is the `siblings` array, bounded by `MAX_DEPTH`.
//!
//! Gas model: each tree level costs exactly one host `sha256` call. For a tree
//! of `2^d` leaves the verifier pays `d` host calls — this is the dominant, and
//! minimal, cost of the STARK Merkle check.
//!
//! **Localized hashing gas profile.** A standard STARK Merkle check walks one
//! authentication path of length `d` (the trace-domain log-size, e.g. `d = 20`
//! for a 1M-row trace). Each `sha256` host call is a single CAP-0075 metered
//! instruction; the Wasm-side work is just 64 bytes of array copies plus one
//! `BytesN` conversion per level. Total verifier cost is therefore
//! `O(d)` host calls and `O(d·64)` bytes of linear-memory traffic — no
//! guest heap allocation, independent of trace width. Doubling the trace length
//! adds exactly one more `sha256` call per query.

use soroban_sdk::{Bytes, BytesN, Env, Vec};

use crate::stark::field::Felt;

/// Maximum tree depth supported by a [`MerklePath`] (covers `2^32` leaves).
pub const MAX_DEPTH: u32 = 32;

/// An authentication path: the sibling hashes (raw 32-byte digests) from leaf to
/// root, plus the leaf index so folding can decide left/right ordering.
pub struct MerklePath {
    pub siblings: [[u8; 32]; MAX_DEPTH as usize],
    pub depth: u32,
    pub index: u64,
}

/// SHA-256 of an arbitrary byte slice (a Merkle leaf or inner-node input).
#[inline(always)]
pub fn hash(env: &Env, data: &Bytes) -> BytesN<32> {
    BytesN::from_array(env, &env.crypto().sha256(data).to_array())
}

/// Merkle leaf for a single Goldilocks element (its 8-byte big-endian encoding).
#[inline(always)]
pub fn felt_leaf(env: &Env, f: Felt) -> BytesN<32> {
    let b = f.to_bytes();
    hash(env, &Bytes::from_slice(env, &b))
}

/// Hash two 32-byte digests into their parent node, returning raw bytes.
#[inline(always)]
fn sha_pair(l: &[u8; 32], r: &[u8; 32], env: &Env) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(l);
    buf[32..].copy_from_slice(r);
    env.crypto().sha256(&Bytes::from_array(env, &buf)).to_array()
}

#[inline(always)]
fn sha_pair_bn(env: &Env, l: &BytesN<32>, r: &BytesN<32>) -> BytesN<32> {
    let a = l.to_array();
    let b = r.to_array();
    BytesN::from_array(env, &sha_pair(&a, &b, env))
}

impl MerklePath {
    /// Recompute the root this path authenticates to, given the leaf digest.
    pub fn compute_root(&self, env: &Env, leaf: &BytesN<32>) -> BytesN<32> {
        let mut cur = leaf.to_array();
        let mut idx = self.index;
        for i in 0..self.depth as usize {
            let sib = self.siblings[i];
            let (l, r) = if idx & 1 == 0 { (cur, sib) } else { (sib, cur) };
            cur = sha_pair(&l, &r, env);
            idx >>= 1;
        }
        BytesN::from_array(env, &cur)
    }

    /// Verify that `leaf` sits at `index` in the tree with Merkle `root`.
    pub fn verify(&self, env: &Env, leaf: &BytesN<32>, root: &BytesN<32>) -> bool {
        &self.compute_root(env, leaf) == root
    }
}

/// Build the Merkle root over a list of leaf digests (prover-side helper / test
/// fixture). Uses a host-backed `Vec` of digests — no guest Wasm heap.
pub fn merkle_root(env: &Env, leaves: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for l in leaves.iter() {
        level.push_back(l);
    }
    while level.len() > 1 {
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let n = level.len();
        let mut i = 0;
        while i < n {
            next.push_back(sha_pair_bn(env, &level.get(i).unwrap(), &level.get(i + 1).unwrap()));
            i += 2;
        }
        level = next;
    }
    level.get(0).unwrap()
}

/// Open a Merkle proof for `leaves[index]` (prover-side helper / test fixture).
pub fn open(env: &Env, leaves: &Vec<BytesN<32>>, index: u32) -> MerklePath {
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for l in leaves.iter() {
        level.push_back(l);
    }
    let mut path = MerklePath {
        siblings: [[0u8; 32]; MAX_DEPTH as usize],
        depth: 0,
        index: index as u64,
    };
    let mut idx = index;
    let mut depth = 0u32;
    while level.len() > 1 {
        let sib_idx = (idx ^ 1) as usize;
        path.siblings[depth as usize] = level.get(sib_idx as u32).unwrap().to_array();
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let n = level.len();
        let mut i = 0;
        while i < n {
            next.push_back(sha_pair_bn(env, &level.get(i).unwrap(), &level.get(i + 1).unwrap()));
            i += 2;
        }
        level = next;
        idx >>= 1;
        depth += 1;
    }
    path.depth = depth;
    path
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::Env;

    fn env() -> Env {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e
    }

    #[test]
    fn valid_path_verifies_and_corrupted_fails() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..8u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let root = merkle_root(&env, &leaves);

        let idx = 3u32;
        let path = open(&env, &leaves, idx);
        let leaf = felt_leaf(&env, Felt::new(idx as u64));
        assert!(path.verify(&env, &leaf, &root), "valid path must verify");

        let bad_leaf = felt_leaf(&env, Felt::new(99));
        assert!(!path.verify(&env, &bad_leaf, &root), "corrupted leaf must fail");

        let mut bad_path = path.clone_struct();
        bad_path.siblings[0] = felt_leaf(&env, Felt::new(123)).to_array();
        assert!(!bad_path.verify(&env, &leaf, &root), "corrupted sibling must fail");
    }

    #[test]
    fn different_root_rejected() {
        let env = env();
        let mut leaves = Vec::new(&env);
        for i in 0..4u64 {
            leaves.push_back(felt_leaf(&env, Felt::new(i)));
        }
        let path = open(&env, &leaves, 0);
        let leaf = felt_leaf(&env, Felt::new(0));
        let wrong = BytesN::from_array(&env, &[0xab; 32]);
        assert!(!path.verify(&env, &leaf, &wrong));
    }
}

#[cfg(test)]
impl MerklePath {
    /// Copy a path so a test can mutate one sibling (no `Copy` on the struct).
    fn clone_struct(&self) -> MerklePath {
        MerklePath {
            siblings: self.siblings,
            depth: self.depth,
            index: self.index,
        }
    }
}
