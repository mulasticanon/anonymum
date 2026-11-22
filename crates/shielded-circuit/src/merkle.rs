//! An append-only Poseidon Merkle tree of depth [`TREE_DEPTH`], matching the
//! path check in the circuit. Each level hashes in its own domain, and an
//! empty position holds a fixed value with no known preimage.

use ark_bls12_381::Fr;

use crate::objects::TREE_DEPTH;
use crate::poseidon::{domain_tag, hash};

/// The domain label of an interior node at `level` (0 = just above leaves).
pub fn node_label(level: usize) -> String {
    format!("merkle/{level}")
}

pub fn node(level: usize, left: Fr, right: Fr) -> Fr {
    hash(&node_label(level), &[left, right])
}

/// What an unused leaf position holds.
pub fn empty_leaf() -> Fr {
    domain_tag("merkle/empty-leaf", 0)
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// `zero[l]`: the root of an empty subtree of height `l`.
    zero: Vec<Fr>,
    /// Populated nodes per level, level 0 being the leaves.
    layers: Vec<Vec<Fr>>,
    root: Fr,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TreeFull;

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    pub fn new() -> Self {
        let mut zero = Vec::with_capacity(TREE_DEPTH + 1);
        zero.push(empty_leaf());
        for level in 0..TREE_DEPTH {
            let below = zero[level];
            zero.push(node(level, below, below));
        }
        let root = zero[TREE_DEPTH];
        MerkleTree { zero, layers: vec![Vec::new(); TREE_DEPTH], root }
    }

    pub fn root(&self) -> Fr {
        self.root
    }

    pub fn len(&self) -> u64 {
        self.layers[0].len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.layers[0].is_empty()
    }

    /// Add a leaf; returns its position.
    pub fn append(&mut self, leaf: Fr) -> Result<u64, TreeFull> {
        let position = self.layers[0].len();
        if position >= 1usize << TREE_DEPTH {
            return Err(TreeFull);
        }
        self.layers[0].push(leaf);
        let (mut index, mut current) = (position, leaf);
        for level in 0..TREE_DEPTH {
            let (left, right) = if index & 1 == 0 {
                (current, self.zero[level])
            } else {
                (self.layers[level][index - 1], current)
            };
            current = node(level, left, right);
            index >>= 1;
            if level + 1 < TREE_DEPTH {
                let above = &mut self.layers[level + 1];
                if index < above.len() {
                    above[index] = current;
                } else {
                    above.push(current);
                }
            }
        }
        self.root = current;
        Ok(position as u64)
    }

    /// The sibling at each level for the leaf at `position`.
    pub fn path(&self, position: u64) -> Vec<Fr> {
        let mut index = position as usize;
        (0..TREE_DEPTH)
            .map(|level| {
                let sibling = self.layers[level].get(index ^ 1).copied().unwrap_or(self.zero[level]);
                index >>= 1;
                sibling
            })
            .collect()
    }
}

/// The root implied by `leaf` at `position` with sibling path `path`.
pub fn root_from_path(leaf: Fr, position: u64, path: &[Fr]) -> Fr {
    let mut current = leaf;
    for (level, sibling) in path.iter().enumerate() {
        current = if (position >> level) & 1 == 0 {
            node(level, current, *sibling)
        } else {
            node(level, *sibling, current)
        };
    }
    current
}
