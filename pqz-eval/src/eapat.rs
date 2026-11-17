//! Phase 1-2: the protected log.
//!
//! Per-record AEAD encryption, keyed tags, a binary Merkle tree per block and
//! ML-DSA-65 signed block headers linked by hash.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use hkdf::SimpleHkdf as Hkdf;
use ml_dsa::{
    Keypair, MlDsa65, Seed, Signer, Signature, SignatureEncoding, SigningKey, Verifier,
    VerifyingKey,
};
use sha3::Sha3_256;

use crate::search::{Bloom, Tag, TagKey, tags_for_record};
use crate::{Record, sha3_parts};

/// Epoch keys: AEAD master, tag key and the ML-DSA-65 block signing key.
pub struct EpochKeys {
    master: [u8; 32],
    pub tag_key: TagKey,
    signing: SigningKey<MlDsa65>,
    verifying: VerifyingKey<MlDsa65>,
}

impl EpochKeys {
    pub fn from_seed(seed: u64) -> Self {
        let master = crate::derive_key(seed, b"pqz-eapat-master");
        let tag_key = TagKey::from_seed(seed);
        let seed_bytes = crate::derive_key(seed, b"pqz-mldsa65");
        let sig_seed: Seed = seed_bytes.into();
        let signing = SigningKey::<MlDsa65>::from_seed(&sig_seed);
        let verifying = signing.verifying_key();
        EpochKeys {
            master,
            tag_key,
            signing,
            verifying,
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature<MlDsa65> = self.signing.try_sign(msg).expect("ML-DSA signing");
        sig.to_vec()
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match Signature::<MlDsa65>::try_from(sig) {
            Ok(s) => self.verifying.verify(msg, &s).is_ok(),
            Err(_) => false,
        }
    }
}

/// Sign a block header with the epoch key. Exposed so the construction
/// experiment can time signing separately from Merkle hashing.
pub fn sign_header(keys: &EpochKeys, header: &BlockHeader) -> Vec<u8> {
    keys.sign(&header.to_bytes())
}

/// One encrypted record as stored in a block. The HE ciphertext of `b` is not
/// kept here (see `he`); storing one per record would break the memory budget.
#[derive(Clone)]
pub struct EncryptedRecord {
    pub id: u64,
    pub ts: u64,
    pub ciphertext: Vec<u8>,
    pub tags: Vec<Tag>,
}

/// Per-record key: `HKDF-SHA3-256(master, "rec" || id_le)`.
fn record_key(master: &[u8; 32], id: u64) -> [u8; 32] {
    let hk = Hkdf::<Sha3_256>::new(None, master);
    let mut info = [0u8; 11];
    info[..3].copy_from_slice(b"rec");
    info[3..].copy_from_slice(&id.to_le_bytes());
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("32 bytes is a valid HKDF length");
    key
}

/// GCM nonce. The record key is unique per id and the nonce is the id itself,
/// so (key, nonce) is never reused; uniqueness does not depend on a counter
/// staying alive across restarts.
fn nonce_for(id: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&id.to_le_bytes());
    n
}

fn aad_for(id: u64, ts: u64) -> [u8; 16] {
    let mut aad = [0u8; 16];
    aad[..8].copy_from_slice(&id.to_le_bytes());
    aad[8..].copy_from_slice(&ts.to_le_bytes());
    aad
}

/// AEAD-encrypt the four attributes of a record. Timed separately in
/// `exp1_construction`.
pub fn aead_encrypt(keys: &EpochKeys, r: &Record) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(&record_key(&keys.master, r.id)).expect("256-bit key");
    let nonce_bytes = nonce_for(r.id);
    let nonce = Nonce::<Aes256Gcm>::try_from(&nonce_bytes[..]).expect("96-bit nonce");
    let aad = aad_for(r.id, r.ts);
    let mut pt = [0u8; 16];
    pt[..4].copy_from_slice(&r.a.to_le_bytes());
    pt[4..8].copy_from_slice(&r.b.to_le_bytes());
    pt[8..12].copy_from_slice(&r.c.to_le_bytes());
    pt[12..].copy_from_slice(&r.d.to_le_bytes());
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &pt,
                aad: &aad,
            },
        )
        .expect("AEAD encryption")
}

/// Decrypt a record; returns `None` on any authentication failure.
pub fn aead_decrypt(keys: &EpochKeys, id: u64, ts: u64, ciphertext: &[u8]) -> Option<Record> {
    let cipher = Aes256Gcm::new_from_slice(&record_key(&keys.master, id)).ok()?;
    let nonce_bytes = nonce_for(id);
    let nonce = Nonce::<Aes256Gcm>::try_from(&nonce_bytes[..]).ok()?;
    let aad = aad_for(id, ts);
    let pt = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .ok()?;
    if pt.len() != 16 {
        return None;
    }
    Some(Record {
        id,
        ts,
        a: u32::from_le_bytes(pt[..4].try_into().ok()?),
        b: u32::from_le_bytes(pt[4..8].try_into().ok()?),
        c: u32::from_le_bytes(pt[8..12].try_into().ok()?),
        d: u32::from_le_bytes(pt[12..].try_into().ok()?),
    })
}

/// Full per-record encryption: AEAD ciphertext plus all search tags.
pub fn encrypt_record(keys: &EpochKeys, r: &Record) -> EncryptedRecord {
    EncryptedRecord {
        id: r.id,
        ts: r.ts,
        ciphertext: aead_encrypt(keys, r),
        tags: tags_for_record(r, &keys.tag_key),
    }
}

/// Merkle leaf: `SHA3(0x00 || id || ciphertext || tags...)`.
pub fn leaf_hash(r: &EncryptedRecord) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + r.tags.len());
    let id = r.id.to_le_bytes();
    parts.push(&[0x00]);
    parts.push(&id);
    parts.push(&r.ciphertext);
    for t in &r.tags {
        parts.push(t);
    }
    sha3_parts(&parts)
}

/// Binary Merkle root over `leaves`. An odd node is paired with itself at the
/// next level; nodes are domain-separated (`0x01`).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = if pair.len() == 2 { &pair[1] } else { &pair[0] };
            next.push(sha3_parts(&[&[0x01], &pair[0], right]));
        }
        level = next;
    }
    level[0]
}

/// Signed block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub block_index: u64,
    pub count: u32,
    pub merkle_root: [u8; 32],
    pub summary_digest: [u8; 32],
    pub prev_header_hash: [u8; 32],
}

impl BlockHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(108);
        b.extend_from_slice(&self.block_index.to_le_bytes());
        b.extend_from_slice(&self.count.to_le_bytes());
        b.extend_from_slice(&self.merkle_root);
        b.extend_from_slice(&self.summary_digest);
        b.extend_from_slice(&self.prev_header_hash);
        b
    }

    pub fn hash(&self) -> [u8; 32] {
        sha3_parts(&[&[0x03], &self.to_bytes()])
    }
}

/// A block: header, summary, encrypted records and the header signature.
#[derive(Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub summary: Bloom,
    pub records: Vec<EncryptedRecord>,
    pub signature: Vec<u8>,
}

/// Build and sign one block. `prev_header_hash` is the previous block's
/// `header.hash()` (`[0;32]` for the first block).
pub fn build_block(
    block_index: u64,
    records: Vec<EncryptedRecord>,
    prev_header_hash: [u8; 32],
    keys: &EpochKeys,
) -> Block {
    let summary = Bloom::build(records.len(), records.iter().flat_map(|r| r.tags.iter()));
    let leaves: Vec<[u8; 32]> = records.iter().map(leaf_hash).collect();
    let header = BlockHeader {
        block_index,
        count: records.len() as u32,
        merkle_root: merkle_root(&leaves),
        summary_digest: summary.digest(),
        prev_header_hash,
    };
    let signature = keys.sign(&header.to_bytes());
    Block {
        header,
        summary,
        records,
        signature,
    }
}

/// Verify a block against the epoch keys: record count, summary digest, Merkle
/// root and header signature. Any changed leaf or header field fails.
pub fn verify_block(block: &Block, keys: &EpochKeys) -> Result<(), String> {
    if block.header.count as usize != block.records.len() {
        return Err("record count does not match header".into());
    }
    let summary = Bloom::build(
        block.records.len(),
        block.records.iter().flat_map(|r| r.tags.iter()),
    );
    if summary.digest() != block.header.summary_digest {
        return Err("summary digest mismatch".into());
    }
    let leaves: Vec<[u8; 32]> = block.records.iter().map(leaf_hash).collect();
    if merkle_root(&leaves) != block.header.merkle_root {
        return Err("Merkle root mismatch".into());
    }
    if !keys.verify(&block.header.to_bytes(), &block.signature) {
        return Err("header signature invalid".into());
    }
    Ok(())
}

/// Verify every block and the hash link between consecutive headers. A dropped,
/// reordered or edited block fails.
pub fn verify_chain(blocks: &[Block], keys: &EpochKeys) -> Result<(), String> {
    let mut prev = [0u8; 32];
    for (i, block) in blocks.iter().enumerate() {
        if block.header.block_index != i as u64 {
            return Err(format!(
                "block index mismatch at position {i}: {}",
                block.header.block_index
            ));
        }
        if block.header.prev_header_hash != prev {
            return Err(format!("prev-header link mismatch at block {i}"));
        }
        verify_block(block, keys)?;
        prev = block.header.hash();
    }
    Ok(())
}

/// Epoch finalization: hash of all header hashes, in order.
pub fn finalize_epoch(blocks: &[Block]) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(blocks.len() + 1);
    let hashes: Vec<[u8; 32]> = blocks.iter().map(|b| b.header.hash()).collect();
    parts.push(b"pqz-epoch");
    for h in &hashes {
        parts.push(h);
    }
    sha3_parts(&parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#gen::r#gen;
    use crate::Layout;

    fn keys() -> EpochKeys {
        EpochKeys::from_seed(0xabc)
    }

    fn build(keys: &EpochKeys, n: usize, mb: usize) -> Vec<Block> {
        let records = r#gen(n, n / 10, Layout::Clustered, 3);
        let encrypted: Vec<_> = records.iter().map(|r| encrypt_record(keys, r)).collect();
        let mut blocks = Vec::new();
        let mut prev = [0u8; 32];
        for (i, chunk) in encrypted.chunks(mb).enumerate() {
            let block = build_block(i as u64, chunk.to_vec(), prev, keys);
            prev = block.header.hash();
            blocks.push(block);
        }
        blocks
    }

    #[test]
    fn aead_roundtrip_and_tamper() {
        let keys = keys();
        let r = r#gen(1, 0, Layout::Clustered, 1)[0];
        let ct = aead_encrypt(&keys, &r);
        let back = aead_decrypt(&keys, r.id, r.ts, &ct).expect("decrypt");
        assert_eq!(back, r);

        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(aead_decrypt(&keys, r.id, r.ts, &bad).is_none());
        assert!(
            aead_decrypt(&keys, r.id, r.ts + 1, &ct).is_none(),
            "AAD binds the timestamp"
        );
    }

    #[test]
    fn empty_and_single_merkle_roots() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
        let l = [[7u8; 32]];
        assert_eq!(merkle_root(&l), l[0]);
    }

    #[test]
    fn chain_verifies_and_finalization_is_stable() {
        let keys = keys();
        let blocks = build(&keys, 100, 10);
        verify_chain(&blocks, &keys).expect("valid chain");
        assert_eq!(finalize_epoch(&blocks), finalize_epoch(&blocks));

        let rebuilt = build(&keys, 100, 10);
        assert_eq!(finalize_epoch(&blocks), finalize_epoch(&rebuilt));
    }

    #[test]
    fn tampered_leaf_fails() {
        let keys = keys();
        let mut blocks = build(&keys, 30, 10);
        blocks[1].records[0].ciphertext[3] ^= 0xff;
        assert!(verify_block(&blocks[1], &keys).is_err());
        assert!(verify_chain(&blocks, &keys).is_err());
    }

    #[test]
    fn dropped_block_fails() {
        let keys = keys();
        let mut blocks = build(&keys, 40, 10);
        blocks.remove(1);
        assert!(verify_chain(&blocks, &keys).is_err());
    }

    #[test]
    fn tampered_header_fails() {
        let keys = keys();
        let mut blocks = build(&keys, 20, 10);
        blocks[0].header.count += 1;
        assert!(verify_block(&blocks[0], &keys).is_err());
    }

    #[test]
    fn wrong_key_fails_signature() {
        let blocks = build(&keys(), 10, 5);
        let other = EpochKeys::from_seed(0xdef);
        assert!(verify_block(&blocks[0], &other).is_err());
    }
}
