//! Algorithm 2 (regulatory audit) of L-HCPM, cache-HIT path only.
//!   1: delta <- Cache.Get(txId)
//!   2-4: on a miss, SamplePre(...)  -> NOT IMPLEMENTED (returns Err(CacheMiss))
//!   5: m <- RLWE.Dec(sk_G, ct_G; delta)
//!   6: cm' <- H(m || r_shared || H(pk_G) || cm_T);  7-9: reject if cm' != cm_G;  10: return m
use crate::bfv::{Ciphertext, Params, PublicKey, SecretKey};
use crate::mimc::Mimc;
use crate::par::run_split;
use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::{Rng, RngCore};
use std::collections::HashMap;

pub const SIS_M: usize = 8448; // paper's m for the cached preimage (n = 256, m = 8448, q = 2^32)

#[derive(Debug, PartialEq, Eq)]
pub enum AuditError {
    CacheMiss,
    VerificationFailed,
}

pub struct Instance {
    pub tx_id: [u8; 32],
    pub ct: Ciphertext,
    pub cm_g: Fr,
    pub r_shared: Fr,
    pub m: u64, // ground truth, used by tests only
    pub plain: Vec<u64>,
}

pub struct AuditCtx {
    pub params: Params,
    pub sk: SecretKey,
    pub pk: PublicKey,
    pub mimc: Mimc,
    pub cache: HashMap<[u8; 32], Vec<u32>>,
    pub h_pk: Fr,
    pub cm_t: Fr,
}

impl AuditCtx {
    /// Everything here is setup: keys, H(pk_G), cache fill, ciphertexts.
    pub fn setup<R: RngCore + Rng>(rng: &mut R, cache_entries: usize, instances: usize) -> (Self, Vec<Instance>) {
        let params = Params::new(4096, 28, 3.2);
        let (sk, pk) = params.keygen(rng);
        let mimc = Mimc::new();
        // H(pk_G): MiMC-hash of every 64-bit residue word of pk_G (one word per field element)
        let words: Vec<Fr> = pk.p0.iter().chain(pk.p1.iter()).flat_map(|v| v.iter().map(|&w| Fr::from(w))).collect();
        let h_pk = mimc.hash(&words);
        let cm_t = Fr::rand(rng); // stands for H(A_G); A_G is not generated (TrapGen not run)
        let mut ctx = AuditCtx { params, sk, pk, mimc, cache: HashMap::with_capacity(cache_entries + instances), h_pk, cm_t };
        let mut insts = Vec::new();
        for _ in 0..instances {
            let mut tx_id = [0u8; 32];
            rng.fill_bytes(&mut tx_id);
            let t = 1u64 << ctx.params.tlog;
            let plain: Vec<u64> = (0..ctx.params.n).map(|_| rng.gen_range(0..t)).collect();
            let m = plain[0];
            let ct = ctx.params.encrypt(&ctx.pk, &plain, rng);
            let r_shared = Fr::rand(rng);
            let cm_g = ctx.mimc.hash(&[Fr::from(m), r_shared, ctx.h_pk, ctx.cm_t]);
            let delta: Vec<u32> = (0..SIS_M).map(|_| rng.gen()).collect();
            ctx.cache.insert(tx_id, delta);
            insts.push(Instance { tx_id, ct, cm_g, r_shared, m, plain });
        }
        for _ in 0..cache_entries {
            let mut tx_id = [0u8; 32];
            rng.fill_bytes(&mut tx_id);
            let delta: Vec<u32> = (0..SIS_M).map(|_| rng.gen()).collect();
            ctx.cache.insert(tx_id, delta);
        }
        (ctx, insts)
    }

    /// Algorithm 2 on a cache hit. Returns the recovered amount m.
    pub fn audit(&self, tx_id: &[u8; 32], ct: &Ciphertext, cm_g: &Fr, r_shared: &Fr) -> Result<u64, AuditError> {
        let delta = self.cache.get(tx_id).ok_or(AuditError::CacheMiss)?; // step 1
        std::hint::black_box(delta); // delta_G is fetched; the paper does not say how it enters RLWE.Dec
        let pt = self.params.decrypt(&self.sk, ct); // step 5
        let m = pt[0];
        std::hint::black_box(&pt);
        let cm = self.mimc.hash(&[Fr::from(m), *r_shared, self.h_pk, self.cm_t]); // step 6
        if cm != *cm_g {
            return Err(AuditError::VerificationFailed); // steps 7-9
        }
        Ok(m) // step 10
    }

    /// q independent audits in one call (stage `audit_hit_q`). Audit k uses instance (start + k) mod len: its own txId,
    /// ciphertext, r_shared and cm_G (q different ciphertexts when q <= len). Nothing is shared between the q audits.
    pub fn audit_q(&self, insts: &[Instance], start: usize, q: usize) -> Vec<Result<u64, AuditError>> {
        let mut out = Vec::with_capacity(q);
        for k in 0..q {
            let i = &insts[(start + k) % insts.len()];
            out.push(self.audit(std::hint::black_box(&i.tx_id), std::hint::black_box(&i.ct), std::hint::black_box(&i.cm_g), std::hint::black_box(&i.r_shared)));
        }
        out
    }

    /// (e405, `--threads T` > 1) Same q items as `audit_q(insts, start, q)`: audit k uses instance (start + k) mod len. The q audits are
    /// split into `threads` contiguous ranges (sizes differ by at most 1) run by scoped workers started together by a barrier; the
    /// workers only read `self` and `insts` (no lock, nothing shared between audits). Returns (results in item order, wall ms from the
    /// barrier release to the last worker's end); the worker creation is not timed. Check with `audit_q_all_ok(insts, start, ..)`.
    pub fn audit_q_threads(&self, insts: &[Instance], start: usize, q: usize, threads: usize) -> (Vec<Result<u64, AuditError>>, f64) {
        run_split(q, threads, || (), |_, k| {
            let i = &insts[(start + k) % insts.len()];
            self.audit(std::hint::black_box(&i.tx_id), std::hint::black_box(&i.ct), std::hint::black_box(&i.cm_g), std::hint::black_box(&i.r_shared))
        })
    }
}

/// Check (untimed) that every one of the q audits returned the true amount of its own instance.
pub fn audit_q_all_ok(insts: &[Instance], start: usize, res: &[Result<u64, AuditError>]) -> bool {
    res.iter().enumerate().all(|(k, r)| *r == Ok(insts[(start + k) % insts.len()].m))
}
