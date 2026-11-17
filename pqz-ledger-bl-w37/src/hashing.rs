//! SHA3-256 helpers and an RFC-6962-style Merkle tree (leaf 0x00, node 0x01).
//! Hashing is the vetted `sha3` crate; only the tree wiring is ours.

use sha3::{Digest, Sha3_256};

pub type Hash = [u8; 32];

/// H(part_0 || part_1 || ...) with plain concatenation, as the paper writes `||`.
/// Callers use fixed-width fields (u64 big-endian, 32-byte hashes) so that the
/// concatenation is unambiguous; labels are the paper's domain strings.
pub fn h(parts: &[&[u8]]) -> Hash {
    let mut d = Sha3_256::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

pub fn u64b(x: u64) -> [u8; 8] {
    x.to_be_bytes()
}

pub fn hex(x: &[u8]) -> String {
    let mut s = String::with_capacity(x.len() * 2);
    for b in x {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn short(x: &Hash) -> String {
    hex(&x[..4])
}

pub fn leaf_hash(data: &[u8]) -> Hash {
    h(&[&[0x00], data])
}

pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
    h(&[&[0x01], l, r])
}

fn split_point(n: usize) -> usize {
    // largest power of two strictly smaller than n (n >= 2)
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Root over already-hashed leaves. Empty tree: H("").
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => h(&[]),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&merkle_root(&leaves[..k]), &merkle_root(&leaves[k..]))
        }
    }
}

/// Audit path for leaf `m`, from the leaf upwards (last element = top sibling).
pub fn merkle_path(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    assert!(m < n);
    if n == 1 {
        return vec![];
    }
    let k = split_point(n);
    if m < k {
        let mut p = merkle_path(&leaves[..k], m);
        p.push(merkle_root(&leaves[k..]));
        p
    } else {
        let mut p = merkle_path(&leaves[k..], m - k);
        p.push(merkle_root(&leaves[..k]));
        p
    }
}

/// Recompute the root from a leaf hash, its index `m`, tree size `n` and path.
/// Returns None when the path length does not fit (n, m).
pub fn root_from_path(leaf: &Hash, m: usize, n: usize, path: &[Hash]) -> Option<Hash> {
    if m >= n {
        return None;
    }
    if n == 1 {
        return if path.is_empty() { Some(*leaf) } else { None };
    }
    let (top, rest) = path.split_last()?;
    let k = split_point(n);
    if m < k {
        let l = root_from_path(leaf, m, k, rest)?;
        Some(node_hash(&l, top))
    } else {
        let r = root_from_path(leaf, m - k, n - k, rest)?;
        Some(node_hash(top, &r))
    }
}

pub fn verify_path(leaf: &Hash, m: usize, n: usize, path: &[Hash], root: &Hash) -> bool {
    root_from_path(leaf, m, n, path).map_or(false, |r| &r == root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&u64b(i as u64))).collect()
    }

    #[test]
    fn sha3_256_known_answer() {
        // FIPS 202 test vector: SHA3-256("abc")
        assert_eq!(
            hex(&h(&[b"abc"])),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        // split input must equal joined input
        assert_eq!(h(&[b"a", b"bc"]), h(&[b"abc"]));
    }

    #[test]
    fn paths_verify_for_all_sizes_and_indices() {
        for n in 1..=40usize {
            let l = leaves(n);
            let root = merkle_root(&l);
            for m in 0..n {
                let p = merkle_path(&l, m);
                assert!(verify_path(&l[m], m, n, &p, &root), "n={} m={}", n, m);
                // wrong leaf, wrong index, wrong size must fail
                let bad = leaf_hash(b"x");
                assert!(!verify_path(&bad, m, n, &p, &root));
                if n > 1 {
                    assert!(!verify_path(&l[m], (m + 1) % n, n, &p, &root) || l[m] == l[(m + 1) % n]);
                }
                // NOTE: a path can also verify for a different claimed size n' in some
                // shapes (e.g. 3 vs 4 leaves). The tree size must therefore come from an
                // authenticated source (G_e in the signed A_e); see audit.rs.
            }
        }
    }

    #[test]
    fn root_changes_when_any_leaf_changes_or_is_dropped() {
        let l = leaves(9);
        let r = merkle_root(&l);
        for i in 0..9 {
            let mut l2 = l.clone();
            l2[i] = leaf_hash(b"changed");
            assert_ne!(r, merkle_root(&l2));
            let mut l3 = l.clone();
            l3.remove(i);
            assert_ne!(r, merkle_root(&l3));
        }
    }
}
