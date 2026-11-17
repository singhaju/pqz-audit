//! w38 stage 3: request / bundle checks for the PACKED format (Exec P2 or P2r + packed chunk proofs).
//! The old `request.rs` is unchanged. A bundle = Auth proof + packed Exec proof + one packed chunk proof per chunk (a single RC proof is one
//! chunk that holds all blocks). `lists` are the AA's own tag / header lists (see `pchunk.rs`).

use crate::air::ExecPublic;
use crate::auth::AuthPublic;
use crate::chunk::{iv_state, ChunkLists, RcChunkPublic};
use crate::pair::{pair_n_words, verify_pair, Fmt};
use crate::pchunk::{check_sealed, plain as pc};
use crate::request::{native_request_checks, NativeChecks};
use crate::variants::{c1, FriOpts};

/// C1 for packed chunks: the chunk statements chain from the IV to the digest of the Exec statement and describe its stream.
pub fn check_stream_link_p(exec_pub: &ExecPublic, chunks: &[RcChunkPublic]) -> Result<(), String> {
    if chunks.is_empty() {
        return Err("link: no chunk".into());
    }
    let total = pair_n_words(exec_pub.n_blocks, exec_pub.block_size);
    let mut blocks = 0usize;
    for (i, p) in chunks.iter().enumerate() {
        if p.chunk_index != i {
            return Err(format!("link: chunk_index {} at position {i}", p.chunk_index));
        }
        if p.block_size != exec_pub.block_size {
            return Err(format!("link: block_size differ (exec {} vs chunk {i} {})", exec_pub.block_size, p.block_size));
        }
        if p.total_words != total {
            return Err(format!("link: total_words differ (exec {total} vs chunk {i} {})", p.total_words));
        }
        if p.hdr_before != blocks {
            return Err(format!("link: hdr_before of chunk {i} is {} (expected {blocks})", p.hdr_before));
        }
        if i == 0 && p.s_in != iv_state(total as u64) {
            return Err("link: chunk 0 does not start at the IV".into());
        }
        if i > 0 && p.s_in != chunks[i - 1].s_out {
            return Err(format!("link: s_in of chunk {i} != s_out of chunk {}", i - 1));
        }
        blocks += p.n_blocks_chunk;
    }
    if blocks != exec_pub.n_blocks {
        return Err(format!("link: n_blocks differ (exec {} vs chunks {blocks})", exec_pub.n_blocks));
    }
    let so = &chunks[chunks.len() - 1].s_out;
    if exec_pub.digest.len() != 4 || so[..4] != exec_pub.digest[..] {
        return Err("link: R_RC final state != R_Exec digest".into());
    }
    Ok(())
}

/// Every native check of a packed bundle: stream link, lists (alpha / beta / acc), C_Q link, scope.
pub fn native_bundle_checks_p(
    nc: NativeChecks,
    auth_pub: &AuthPublic,
    exec_pub: &ExecPublic,
    chunks: &[RcChunkPublic],
    lists: &[ChunkLists],
    rid: u64,
) -> Result<(), String> {
    if nc.link {
        check_stream_link_p(exec_pub, chunks)?;
        if lists.len() != chunks.len() {
            return Err("lists: one list per chunk required".into());
        }
        for (p, l) in chunks.iter().zip(lists) {
            check_sealed::<c1::Val>(p, l)?;
        }
    }
    native_request_checks(nc, auth_pub, exec_pub, rid)
}

pub fn verify_request_p(
    nc: NativeChecks,
    o: &FriOpts,
    f: Fmt,
    auth_proof: &c1::P,
    auth_pub: &AuthPublic,
    exec_proof: &c1::P,
    exec_pub: &ExecPublic,
    rid: u64,
) -> Result<(), String> {
    native_request_checks(nc, auth_pub, exec_pub, rid)?;
    crate::rel::plain::verify_auth(o, auth_proof, auth_pub).map_err(|e| format!("auth: {e}"))?;
    verify_pair(o, exec_proof, exec_pub, f).map_err(|e| format!("exec: {e}"))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_bundle_p(
    nc: NativeChecks,
    o: &FriOpts,
    f: Fmt,
    auth_proof: &c1::P,
    auth_pub: &AuthPublic,
    exec_proof: &c1::P,
    exec_pub: &ExecPublic,
    chunk_proofs: &[c1::P],
    chunks: &[RcChunkPublic],
    lists: &[ChunkLists],
    rid: u64,
) -> Result<(), String> {
    if chunk_proofs.len() != chunks.len() {
        return Err("link: one proof per chunk statement required".into());
    }
    native_bundle_checks_p(nc, auth_pub, exec_pub, chunks, lists, rid)?;
    crate::rel::plain::verify_auth(o, auth_proof, auth_pub).map_err(|e| format!("auth: {e}"))?;
    verify_pair(o, exec_proof, exec_pub, f).map_err(|e| format!("exec: {e}"))?;
    for (i, (pr, p)) in chunk_proofs.iter().zip(chunks).enumerate() {
        pc::verify_chunk(o, pr, p).map_err(|e| format!("rc[{i}]: {e}"))?;
    }
    Ok(())
}
