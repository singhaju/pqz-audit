//! Merkle-committed key/value map: the replicated world state of the ledger.
//! Root = RFC-6962-style Merkle tree over the leaves of the key-sorted entries.
//! The root is recomputed over all entries once per block (O(|state|)); this is
//! NOT an incremental sparse Merkle tree, so per-block cost grows with state size.
//! A journal gives atomic block application (begin / commit / rollback).

use crate::hashing::*;
use std::collections::BTreeMap;

type Entry = (Vec<u8>, Hash);

pub fn leaf_of(key: &[u8], val: &[u8]) -> Hash {
    let mut b = Vec::with_capacity(8 + key.len() + val.len());
    b.extend_from_slice(&(key.len() as u32).to_be_bytes());
    b.extend_from_slice(key);
    b.extend_from_slice(&(val.len() as u32).to_be_bytes());
    b.extend_from_slice(val);
    leaf_hash(&b)
}

#[derive(Clone, Default)]
pub struct StateMap {
    map: BTreeMap<Vec<u8>, Entry>,
    journal: Option<Vec<(Vec<u8>, Option<Entry>)>>,
    root_cache: Option<Hash>,
}

pub struct Proof {
    pub index: usize,
    pub size: usize,
    pub path: Vec<Hash>,
}

impl StateMap {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.map.get(key).map(|e| e.0.as_slice())
    }
    pub fn put(&mut self, key: &[u8], val: &[u8]) {
        let leaf = leaf_of(key, val);
        let old = self.map.insert(key.to_vec(), (val.to_vec(), leaf));
        if let Some(j) = self.journal.as_mut() {
            j.push((key.to_vec(), old));
        }
        self.root_cache = None;
    }
    pub fn begin(&mut self) {
        assert!(self.journal.is_none(), "nested begin");
        self.journal = Some(Vec::new());
    }
    pub fn commit(&mut self) {
        self.journal = None;
    }
    pub fn rollback(&mut self) {
        if let Some(j) = self.journal.take() {
            for (k, old) in j.into_iter().rev() {
                match old {
                    Some(e) => {
                        self.map.insert(k, e);
                    }
                    None => {
                        self.map.remove(&k);
                    }
                }
            }
            self.root_cache = None;
        }
    }
    fn leaves(&self) -> Vec<Hash> {
        self.map.values().map(|e| e.1).collect()
    }
    pub fn root(&mut self) -> Hash {
        if let Some(r) = self.root_cache {
            return r;
        }
        let r = merkle_root(&self.leaves());
        self.root_cache = Some(r);
        r
    }
    pub fn prove(&self, key: &[u8]) -> Option<Proof> {
        let index = self.map.keys().position(|k| k.as_slice() == key)?;
        let leaves = self.leaves();
        Some(Proof { index, size: leaves.len(), path: merkle_path(&leaves, index) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_order_independent_and_content_bound() {
        let mut a = StateMap::new();
        let mut b = StateMap::new();
        a.put(b"k1", b"v1");
        a.put(b"k2", b"v2");
        b.put(b"k2", b"v2");
        b.put(b"k1", b"v1");
        assert_eq!(a.root(), b.root());
        b.put(b"k2", b"v3");
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn rollback_restores_root_and_content() {
        let mut a = StateMap::new();
        a.put(b"k1", b"v1");
        let r0 = a.root();
        a.begin();
        a.put(b"k1", b"changed");
        a.put(b"k2", b"new");
        assert_ne!(a.root(), r0);
        a.rollback();
        assert_eq!(a.root(), r0);
        assert_eq!(a.get(b"k1"), Some(&b"v1"[..]));
        assert_eq!(a.get(b"k2"), None);
        a.begin();
        a.put(b"k3", b"x");
        a.commit();
        assert_eq!(a.get(b"k3"), Some(&b"x"[..]));
    }

    #[test]
    fn membership_proofs_verify() {
        let mut a = StateMap::new();
        for i in 0..23u32 {
            a.put(&i.to_be_bytes(), &[i as u8; 5]);
        }
        let root = a.root();
        for i in 0..23u32 {
            let p = a.prove(&i.to_be_bytes()).unwrap();
            let leaf = leaf_of(&i.to_be_bytes(), &[i as u8; 5]);
            assert!(verify_path(&leaf, p.index, p.size, &p.path, &root));
            let wrong = leaf_of(&i.to_be_bytes(), &[0xFF; 5]);
            assert!(!verify_path(&wrong, p.index, p.size, &p.path, &root));
        }
        assert!(a.prove(b"missing").is_none());
    }
}
