//! Shared fixture of the w35 tests. Small N (13 blocks = 6500 records). Release mode only.
#![allow(dead_code)]

use pqz_eval::eapat::EpochKeys;
use pqz_eval::r#gen::r#gen;
use pqz_eval::search::{Formula, Tag};
use pqz_eval::{Layout, Predicate, Record, B_DOMAIN, W, X, Y};
use pqz_plonky3_w36::chunk::seal;
use std::sync::OnceLock;
use pqz_integrated_w46::w35::*;
use pqz_integrated_w46::*;
use pqz_plonky3_w36::chunk::{self, State};

pub const SEED: u64 = DEFAULT_SEED;
pub const DUMMY_OMEGA: [u8; 32] = [7u8; 32];

/// Records with NO hit from `r#gen`, then the given ids made hits (a = X, b >= Y, d = W).
pub fn records_with_hits(n: usize, hit_ids: &[usize], seed: u64) -> Vec<Record> {
    let mut rs = r#gen(n, 0, Layout::Clustered, seed);
    for &id in hit_ids {
        let r = &mut rs[id];
        r.a = X;
        r.b = Y + ((id as u32).wrapping_mul(7919) % (B_DOMAIN - Y));
        r.c = 0;
        r.d = W;
    }
    rs
}

/// plain reference (count, sum of b) of P1 over the records
pub fn truth(records: &[Record]) -> (u64, u64) {
    let mut c = (0u64, 0u64);
    for r in records {
        if Predicate::P1.matches(r) {
            c.0 += 1;
            c.1 += r.b as u64;
        }
    }
    c
}

pub struct Fx {
    pub records: Vec<Record>,
    pub seed: u64,
    pub w: World35,
    pub f: Formula,
    pub proofs: Vec<ChunkProof>,
    pub auth: AuthProof,
    pub an: Anchor,
    pub ctx: [u64; 4],
    pub flags: Vec<bool>,
}

impl Fx {
    pub fn new(records: Vec<Record>, c: usize, seed: u64) -> Fx {
        Fx::new_fmt(records, c, seed, WFmt::Old)
    }
    pub fn new_fmt(records: Vec<Record>, c: usize, seed: u64, fmt: WFmt) -> Fx {
        let keys = EpochKeys::from_seed(seed);
        let (f, _t) = predicate_formula(&keys);
        let log = build_log(&records, &keys);
        let flags = search(&log, &f).flags;
        let w = World35::prepare_fmt(log, c, fmt);
        let (proofs, _) = w.prove_chunks().expect("chunk proofs");
        let (auth, _) = auth_stage(&DUMMY_OMEGA, 1, "P1: A = x", seed).expect("auth");
        let ctx = pqz_plonky3_w36::request::exec_context(&pqz_plonky3_w36::c1::perm(), auth.stmt.b_q, auth.stmt.d_q, RID);
        let an = Anchor { r_e: w.r_e, n_e: w.n as u64, g_e: w.g as u64 };
        Fx { records, seed, w, f, proofs, auth, an, ctx, flags }
    }

    /// hits at the given record ids; seed chosen (from SEED upwards) so that BPS has no false positive: flags == exactly the hit blocks
    pub fn with_hits(n: usize, hit_ids: &[usize], c: usize) -> Fx {
        Fx::with_hits_fmt(n, hit_ids, c, WFmt::Old)
    }
    pub fn with_hits_fmt(n: usize, hit_ids: &[usize], c: usize, fmt: WFmt) -> Fx {
        for k in 0..60u64 {
            let seed = SEED + k;
            let rs = records_with_hits(n, hit_ids, seed);
            let keys = EpochKeys::from_seed(seed);
            let (f, _t) = predicate_formula(&keys);
            let log = build_log(&rs, &keys);
            let flags = search(&log, &f).flags;
            let mut want = vec![false; n / BLOCK];
            for &id in hit_ids {
                want[id / BLOCK] = true;
            }
            if flags == want {
                return Fx::new_fmt(rs, c, seed, fmt);
            }
        }
        panic!("no seed without a Bloom false positive in 60 tries");
    }

    pub fn ranges(&self, gm: usize) -> Vec<(usize, usize)> {
        plan_runs(&self.flags, &self.w.plan, gm)
    }

    pub fn honest_with_flags(&self, flags: &[bool], gm: usize) -> CspResponse {
        let ranges = plan_runs(flags, &self.w.plan, gm);
        let (runs, _) = prove_runs(&self.w, &ranges, self.ctx).expect("runs");
        respond(&self.w, &self.f, &ranges, runs).expect("honest openings")
    }

    pub fn honest(&self, gm: usize) -> CspResponse {
        self.honest_with_flags(&self.flags, gm)
    }

    /// run over blocks first1..=last1 (1-based) of THIS stream from `s_in`
    pub fn run_over(&self, first1: usize, last1: usize, s_in: &State) -> RunClaim {
        prove_run_over_fmt(self.w.block_words(first1 - 1, last1 - first1 + 1), s_in, first1, last1, self.ctx, THETA, self.w.fmt).expect("run")
    }

    /// state after the first `nb` blocks of the stream (nb = 0: the IV)
    pub fn state_after_blocks(&self, nb: usize) -> State {
        let iv = chunk::iv_state((self.w.g * self.w.fmt.rows_per_block(BLOCK)) as u64);
        if nb == 0 {
            iv
        } else {
            chunk::state_after::<pqz_plonky3_w36::c1::Val, 12, _>(&pqz_plonky3_w36::c1::perm(), &iv, self.w.block_words(0, nb))
        }
    }

    pub fn openings_except(&self, covered: &[bool], skip: &[usize]) -> Vec<(u64, Vec<BloomOpening>)> {
        let mut v = Vec::new();
        for i in 0..self.w.g {
            if covered[i] || skip.contains(&i) {
                continue;
            }
            v.push((i as u64 + 1, self.w.blooms[i].openings_for(&self.f).expect("openings")));
        }
        v
    }

    pub fn full(&self, resp: &CspResponse, sw: ReqChecks) -> Res<(ReqTimes35, (u64, u64))> {
        verify_requester35_fmt(&self.an, &self.f, &self.auth, resp, sw, self.w.fmt)
    }

    pub fn aa(&self, sw: AaChecks) -> Result<AaOut, String> {
        aa_finalize_fmt(&self.proofs, &self.w.blocks, &self.w.material(), sw, self.w.fmt)
    }
}

pub const HITS_ONE: [usize; 1] = [600];
pub const HIT_RUN: usize = 40;

pub fn hit_ids(starts: &[usize]) -> Vec<usize> {
    starts.iter().flat_map(|&s| s..s + HIT_RUN).collect()
}

/// N = 6500 (G = 13), c = 4: chunks = blocks [1-4], [5-8], [9-12], [13]. One hit run, in block 2 (chunk 0).
pub fn fx_one() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| Fx::with_hits(6500, &hit_ids(&[600]), 4))
}

/// Same, hits in block 2 (chunk 0) and block 10 (chunk 2); chunk 1 has none.
pub fn fx_two() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| Fx::with_hits(6500, &hit_ids(&[600, 4600]), 4))
}

/// w46: the same fixtures in the P2r format
pub fn fx_one_p() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| Fx::with_hits_fmt(6500, &hit_ids(&[600]), 4, WFmt::P2r))
}
pub fn fx_two_p() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| Fx::with_hits_fmt(6500, &hit_ids(&[600, 4600]), 4, WFmt::P2r))
}

pub fn first_tag(f: &Formula) -> Tag {
    match f {
        Formula::Leaf(t) => t[0],
        _ => panic!("leaf expected"),
    }
}

impl Fx {
    /// Recompute the chunk proofs of chunks j.. so that chunk j starts at `s0` and the later ones continue from the new state
    /// (everything honest otherwise). `no_iv_rule`: chunk 0 is proved with the AIR that lacks the IV rule.
    pub fn rechain(&self, j: usize, s0: State, no_iv_rule: bool) -> Vec<ChunkProof> {
        let o = opts();
        let mut out: Vec<ChunkProof> = self.proofs[..j].to_vec();
        let mut s = s0;
        let perm = pqz_plonky3_w36::c1::perm();
        for k in j..self.proofs.len() {
            let mut p = self.proofs[k].stmt.clone();
            let cw = self.w.block_words(p.hdr_before, p.n_blocks_chunk);
            p.s_in = s;
            p.s_out = chunk::state_after::<pqz_plonky3_w36::c1::Val, 12, _>(&perm, &s, cw);
            let (lists, proof) = match self.w.fmt {
                WFmt::Old => {
                    let lists = chunk::lists_of(cw);
                    seal::<pqz_plonky3_w36::c1::Val>(&mut p, &lists);
                    let proof = if k == 0 && no_iv_rule {
                        let a = chunk::plain::ChunkA::new(chunk::plain::consts(), BLOCK as u64, p.n_words() as u64, false);
                        chunk::plain::prove_chunk_with(&o, &a, cw, &p).unwrap()
                    } else {
                        chunk::plain::prove_chunk(&o, cw, &p).unwrap()
                    };
                    (lists, proof)
                }
                WFmt::P2r => {
                    let lists = pqz_plonky3_w36::pchunk::lists_of_packed(cw, BLOCK);
                    pqz_plonky3_w36::pchunk::seal_p::<pqz_plonky3_w36::c1::Val>(&mut p, &lists);
                    let proof = if k == 0 && no_iv_rule {
                        let a = pqz_plonky3_w36::pchunk::plain::PcA::new(pqz_plonky3_w36::pchunk::plain::consts(), BLOCK as u64, pqz_plonky3_w36::pchunk::pc_n_words(&p) as u64, false);
                        pqz_plonky3_w36::pchunk::plain::prove_chunk_with(&o, &a, cw, &p).unwrap()
                    } else {
                        pqz_plonky3_w36::pchunk::plain::prove_chunk(&o, cw, &p).unwrap()
                    };
                    (lists, proof)
                }
            };
            s = p.s_out;
            out.push(ChunkProof::new(pqz_plonky3_w36::c1::to_bytes(&proof), p, lists));
        }
        out
    }

    /// The LP proves a stream `words` (same shape as the honest one, some header words changed) with consistent chunk proofs from the IV:
    /// every chunk statement is honest for THAT stream (alpha, beta, acc sealed from the stream's own tag slots and header words).
    pub fn reprove_stream(&self, words: &[Vec<u64>]) -> Vec<ChunkProof> {
        let o = opts();
        let perm = pqz_plonky3_w36::c1::perm();
        let mut out: Vec<ChunkProof> = Vec::new();
        let rpb = self.w.fmt.rows_per_block(BLOCK);
        let mut s = chunk::iv_state((self.w.g * rpb) as u64);
        for k in 0..self.proofs.len() {
            let mut p = self.proofs[k].stmt.clone();
            let cw = &words[p.hdr_before * rpb..(p.hdr_before + p.n_blocks_chunk) * rpb];
            p.s_in = s;
            p.s_out = chunk::state_after::<pqz_plonky3_w36::c1::Val, 12, _>(&perm, &s, cw);
            p.hdr_first.copy_from_slice(&cw[0]);
            let (lists, proof) = match self.w.fmt {
                WFmt::Old => {
                    let lists = chunk::lists_of(cw);
                    seal::<pqz_plonky3_w36::c1::Val>(&mut p, &lists);
                    (lists, chunk::plain::prove_chunk(&o, cw, &p).unwrap())
                }
                WFmt::P2r => {
                    let lists = pqz_plonky3_w36::pchunk::lists_of_packed(cw, BLOCK);
                    pqz_plonky3_w36::pchunk::seal_p::<pqz_plonky3_w36::c1::Val>(&mut p, &lists);
                    (lists, pqz_plonky3_w36::pchunk::plain::prove_chunk(&o, cw, &p).unwrap())
                }
            };
            s = p.s_out;
            out.push(ChunkProof::new(pqz_plonky3_w36::c1::to_bytes(&proof), p, lists));
        }
        out
    }

    /// B list consistent with `proofs` (sigma at the chunk ends they state) and the material `m`.
    pub fn blocks_for(&self, proofs: &[ChunkProof], m: &AaMaterial) -> Vec<Block35> {
        let (ds, _) = derive_slots(m);
        let pubs: Vec<_> = proofs.iter().map(|p| p.stmt.clone()).collect();
        let sig = sigmas_from(&pubs, self.w.g);
        (0..self.w.g).map(|g0| build_block(m, &ds, g0, sig[g0]).0).collect()
    }
}
