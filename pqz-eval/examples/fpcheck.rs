//! Read-only diagnostic for the block-summary false-positive rate.
//!
//! Builds blocks exactly as `bench::build_data` does (same generator seed,
//! same tag key, same m_B, same `eapat::build_block` Bloom sizing) and reports
//! true blocks, retained blocks, false positives and the per-tag a=x rate.
//! It never writes into `src/`.

use std::collections::BTreeSet;

use pqz_eval::Predicate;
use pqz_eval::bench::DEFAULT_SEED;
use pqz_eval::r#gen::r#gen;
use pqz_eval::search::{
    ATTR_A, Bloom, Formula, Tag, TagKey, bps_eval, eq_tag, formula_for, tags_for_record,
};
use pqz_eval::{B_DOMAIN, Layout, Record, X, Y, Z, sha3_256, W};

const MB: usize = 500;

/// Copied verbatim from `src/bench.rs` (it is private there).
fn seed_for(base: u64, parts: &[&str]) -> u64 {
    let mut buf = base.to_le_bytes().to_vec();
    for p in parts {
        buf.extend_from_slice(p.as_bytes());
        buf.push(0);
    }
    let h = sha3_256(&buf);
    u64::from_le_bytes(h[..8].try_into().expect("8 bytes"))
}

/// Mirror of `Bloom::with_fp_rate` so the example can inspect the bit vector.
struct DbgBloom {
    bits: Vec<u64>,
    nbits: usize,
    k: usize,
    /// Index width in bytes used by the probe (2 = current code).
    width: usize,
}

impl DbgBloom {
    fn new(m: usize, fp_rate: f64, width: usize) -> Self {
        let ln2 = std::f64::consts::LN_2;
        let nbits = ((m as f64) * (-fp_rate.ln()) / (ln2 * ln2)).ceil() as usize;
        let nbits = nbits.max(64);
        let k = (((nbits as f64) / (m as f64)) * ln2).round() as usize;
        let k = k.clamp(1, 16 / width);
        DbgBloom {
            bits: vec![0u64; nbits.div_ceil(64)],
            nbits,
            k,
            width,
        }
    }

    fn index(&self, tag: &Tag, i: usize) -> usize {
        match self.width {
            2 => u16::from_le_bytes([tag[2 * i], tag[2 * i + 1]]) as usize % self.nbits,
            4 => {
                let j = 4 * i;
                u32::from_le_bytes([tag[j], tag[j + 1], tag[j + 2], tag[j + 3]]) as usize
                    % self.nbits
            }
            _ => unreachable!(),
        }
    }

    fn insert(&mut self, tag: &Tag) {
        for i in 0..self.k {
            let idx = self.index(tag, i);
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    fn contains(&self, tag: &Tag) -> bool {
        (0..self.k).all(|i| {
            let idx = self.index(tag, i);
            self.bits[idx / 64] & (1u64 << (idx % 64)) != 0
        })
    }

    fn set_bits(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Bit positions that the k indices of `tag` can ever reach.
    fn reachable(&self, tag: &Tag, mask: &mut [bool]) -> usize {
        for i in 0..self.k {
            mask[self.index(tag, i)] = true;
        }
        mask.iter().filter(|b| **b).count()
    }
}

struct Diag {
    nbits: usize,
    k: usize,
    inserted: usize,
    distinct: usize,
    set: usize,
}

#[derive(Default)]
struct PredCounts {
    true_blocks: usize,
    retained: usize,
}

struct Report {
    n: usize,
    sigma: usize,
    layout: Layout,
    seed: u64,
    n_blocks: usize,
    preds: Vec<PredCounts>,
    ax_absent_blocks: usize,
    ax_present_blocks: usize,
    diag: Diag,
    /// Blocks with no hit at all: how often each P4 leaf alone says "present".
    leaf_b: usize,
    leaf_c: usize,
    leaf_d: usize,
    nonhit_blocks: usize,
    /// P4 retained split by the a=x probe on non-hit blocks.
    ax_false_p4_retained: usize,
    ax_false_blocks: usize,
    ax_true_p4_retained: usize,
    ax_true_blocks: usize,
    ref_fp: usize,
    ref_blocks: usize,
    ref_diag: Diag,
    ax_bits_hist: [usize; 9],
    ax_pos_set: [usize; 8],
    ax_pos_total: usize,
    p_sum: f64,
}

#[allow(clippy::too_many_arguments)]
fn run_one(n: usize, sigma: usize, layout: Layout, seed: u64) -> Report {
    let records: Vec<Record> = r#gen(n, sigma, layout, seed);
    let key = TagKey::from_seed(seed);
    let a_x = eq_tag(&key, ATTR_A, X);

    let formulas: Vec<Formula> = Predicate::ALL.iter().map(|p| formula_for(*p, &key)).collect();
    let f_ax = Formula::leaf(vec![a_x]);
    let f_b = Formula::leaf(pqz_eval::search::range_tags(&key, pqz_eval::search::ATTR_B, Y, B_DOMAIN));
    let f_c = Formula::leaf(pqz_eval::search::range_tags(&key, pqz_eval::search::ATTR_C, 0, Z));
    let f_d = Formula::leaf(vec![eq_tag(&key, pqz_eval::search::ATTR_D, W)]);

    let mut preds: Vec<PredCounts> = (0..4).map(|_| PredCounts::default()).collect();
    let mut ax_absent_blocks = 0usize;
    let mut ax_present_blocks = 0usize;
    let mut leaf_b = 0usize;
    let mut leaf_c = 0usize;
    let mut leaf_d = 0usize;
    let mut nonhit_blocks = 0usize;
    let mut ax_false_p4_retained = 0usize;
    let mut ax_false_blocks = 0usize;
    let mut ax_true_p4_retained = 0usize;
    let mut ax_true_blocks = 0usize;
    let mut ref_fp = 0usize;
    let mut ref_blocks = 0usize;
    // Histogram over non-hit blocks of how many of a_x's k probe positions are set.
    let mut ax_bits_hist = [0usize; 9];
    let mut ax_pos_set = [0usize; 8];
    let mut ax_pos_total = 0usize;
    let mut p_sum = 0.0f64;

    let mut n_blocks = 0usize;
    let mut diag: Option<Diag> = None;
    let mut ref_diag: Option<Diag> = None;

    for chunk in records.chunks(MB) {
        n_blocks += 1;
        let block_tags: Vec<Vec<Tag>> = chunk.iter().map(|r| tags_for_record(r, &key)).collect();
        let bloom = Bloom::build(block_tags.len(), block_tags.iter().flatten());

        if diag.is_none() {
            let mut dbg = DbgBloom::new(block_tags.len() * 45, 0.01, 2);
            let mut distinct: BTreeSet<Tag> = BTreeSet::new();
            for t in block_tags.iter().flatten() {
                dbg.insert(t);
                distinct.insert(*t);
            }
            let mut mask = vec![false; dbg.nbits];
            for t in block_tags.iter().flatten() {
                dbg.reachable(t, &mut mask);
            }
            let reachable = mask.iter().filter(|b| **b).count();
            diag = Some(Diag {
                nbits: bloom.nbits(),
                k: bloom.k(),
                inserted: block_tags.len() * 45,
                distinct: distinct.len(),
                set: dbg.set_bits(),
            });
            let _ = reachable;
            // The reference filter uses 4-byte indices (k <= 4).
            let mut rf = DbgBloom::new(block_tags.len() * 45, 0.01, 4);
            let mut rdistinct: BTreeSet<Tag> = BTreeSet::new();
            for t in block_tags.iter().flatten() {
                rf.insert(t);
                rdistinct.insert(*t);
            }
            ref_diag = Some(Diag {
                nbits: rf.nbits,
                k: rf.k,
                inserted: block_tags.len() * 45,
                distinct: rdistinct.len(),
                set: rf.set_bits(),
            });
        }

        let mut has_ax = false;
        for r in chunk {
            if r.a == X {
                has_ax = true;
            }
        }
        if has_ax {
            ax_present_blocks += 1;
        } else {
            ax_absent_blocks += 1;
        }

        for (i, p) in Predicate::ALL.iter().enumerate() {
            if chunk.iter().any(|r| p.matches(r)) {
                preds[i].true_blocks += 1;
            }
            if bps_eval(&bloom, &formulas[i]) {
                preds[i].retained += 1;
            }
        }

        if !has_ax {
            nonhit_blocks += 1;
            if bps_eval(&bloom, &f_b) {
                leaf_b += 1;
            }
            if bps_eval(&bloom, &f_c) {
                leaf_c += 1;
            }
            if bps_eval(&bloom, &f_d) {
                leaf_d += 1;
            }
            let ax = bps_eval(&bloom, &f_ax);
            let p4 = bps_eval(&bloom, &formulas[3]);
            if ax {
                ax_true_blocks += 1;
                if p4 {
                    ax_true_p4_retained += 1;
                }
            } else {
                ax_false_blocks += 1;
                if p4 {
                    ax_false_p4_retained += 1;
                }
            }

            let mut rf = DbgBloom::new(block_tags.len() * 45, 0.01, 4);
            for t in block_tags.iter().flatten() {
                rf.insert(t);
            }
            ref_blocks += 1;
            if rf.contains(&a_x) {
                ref_fp += 1;
            }

            let mut dbg2 = DbgBloom::new(block_tags.len() * 45, 0.01, 2);
            for t in block_tags.iter().flatten() {
                dbg2.insert(t);
            }
            let mut nset = 0usize;
            for i in 0..dbg2.k {
                let idx = dbg2.index(&a_x, i);
                if dbg2.bits[idx / 64] & (1u64 << (idx % 64)) != 0 {
                    nset += 1;
                    ax_pos_set[i] += 1;
                }
            }
            ax_bits_hist[nset] += 1;
            ax_pos_total += 1;
            p_sum += dbg2.set_bits() as f64 / 65536.0;
        }
    }

    Report {
        n,
        sigma,
        layout,
        seed,
        n_blocks,
        preds,
        ax_absent_blocks,
        ax_present_blocks,
        diag: diag.unwrap(),
        leaf_b,
        leaf_c,
        leaf_d,
        nonhit_blocks,
        ax_false_p4_retained,
        ax_false_blocks,
        ax_true_p4_retained,
        ax_true_blocks,
        ref_fp,
        ref_blocks,
        ref_diag: ref_diag.unwrap(),
        ax_bits_hist,
        ax_pos_set,
        ax_pos_total,
        p_sum,
    }
}

fn print_report(tag: &str, r: &Report) {
    let d = &r.diag;
    println!(
        "DIAG {tag} n={} sigma={} layout={} seed={:#x} blocks={} nbits={} k={} inserted={} distinct={} set={} fit={:.3}",
        r.n,
        r.sigma,
        r.layout.name(),
        r.seed,
        r.n_blocks,
        d.nbits,
        d.k,
        d.inserted,
        d.distinct,
        d.set,
        d.set as f64 / d.nbits as f64
    );
    let rd = &r.ref_diag;
    println!(
        "REFDIAG {tag} nbits={} k={} set={} fit={:.3}",
        rd.nbits,
        rd.k,
        rd.set,
        rd.set as f64 / rd.nbits as f64
    );
    let addr = d.nbits.min(1usize << 16);
    println!(
        "ADDR {tag} n={} sigma={} layout={} nbits={} index_width_bytes=2 addressable_bits={} unused_bits={} used_bits={} occupancy_used={:.4}",
        r.n,
        r.sigma,
        r.layout.name(),
        d.nbits,
        addr,
        d.nbits - addr,
        d.set,
        d.set as f64 / addr as f64
    );
    println!(
        "AX {tag} n={} sigma={} layout={} blocks_total={} blocks_with_ax_record={} blocks_without_ax={}",
        r.n,
        r.sigma,
        r.layout.name(),
        r.n_blocks,
        r.ax_present_blocks,
        r.ax_absent_blocks
    );
    println!(
        "AXFP {tag} n={} sigma={} layout={} blocks_without_ax={} bloom_ax_present={} rate={:.4}",
        r.n,
        r.sigma,
        r.layout.name(),
        r.ax_absent_blocks,
        r.ax_true_blocks,
        r.ax_true_blocks as f64 / r.ax_absent_blocks.max(1) as f64
    );
    for (i, p) in Predicate::ALL.iter().enumerate() {
        let c = &r.preds[i];
        let fp = c.retained.saturating_sub(c.true_blocks);
        let denom = r.n_blocks - c.true_blocks;
        println!(
            "ROW {tag} n={} sigma={} layout={} pred={} blocks={} true={} retained={} fp={} fp_rate={:.4}",
            r.n,
            r.sigma,
            r.layout.name(),
            p.name(),
            r.n_blocks,
            c.true_blocks,
            c.retained,
            fp,
            fp as f64 / denom.max(1) as f64
        );
    }
    println!(
        "P4SPLIT {tag} n={} sigma={} layout={} nonhit_blocks={} ax_probe_false_blocks={} p4_retained_when_ax_false={} ax_probe_true_blocks={} p4_retained_when_ax_true={} leaf_b={} leaf_c={} leaf_d={}",
        r.n,
        r.sigma,
        r.layout.name(),
        r.nonhit_blocks,
        r.ax_false_blocks,
        r.ax_false_p4_retained,
        r.ax_true_blocks,
        r.ax_true_p4_retained,
        r.leaf_b,
        r.leaf_c,
        r.leaf_d
    );
    println!(
        "REF {tag} n={} sigma={} layout={} blocks_without_ax={} ref_ax_present={} ref_rate={:.4}",
        r.n,
        r.sigma,
        r.layout.name(),
        r.ref_blocks,
        r.ref_fp,
        r.ref_fp as f64 / r.ref_blocks.max(1) as f64
    );
    let p = r.p_sum / r.ax_pos_total.max(1) as f64;
    let q_model = p.powi(r.diag.k as i32);
    println!(
        "AXBITS {tag} n={} sigma={} layout={} nonhit_blocks={} hist={:?} pos_set={:?} mean_fit_first65536={:.4} p^k={:.4}",
        r.n,
        r.sigma,
        r.layout.name(),
        r.ax_pos_total,
        r.ax_bits_hist,
        &r.ax_pos_set[..r.diag.k],
        p,
        q_model
    );
}

fn main() {
    println!("# pqz-eval Bloom false-positive diagnostic (read-only)");
    println!("# DEFAULT_SEED={DEFAULT_SEED:#x} mb={MB} target_fp=0.01");

    // Main grid: the seeding exp1 uses, so clustered rows reproduce the pilot.
    println!("\n## main grid (exp1 seeding: seed_for(base, [\"exp1\", series, n]))");
    for n in [100_000usize, 500_000, 1_000_000] {
        for sigma in [1000usize, 10_000] {
            let series = if sigma == 1000 { "fixed_nq1000" } else { "sigma1pct" };
            let seed = seed_for(DEFAULT_SEED, &["exp1", series, &n.to_string()]);
            for layout in [Layout::Clustered, Layout::Scattered] {
                let tag = format!("main/exp1");
                let report = run_one(n, sigma, layout, seed);
                print_report(&tag, &report);
            }
        }
    }

    // Same tag key and same generator seed, only N changes: this is the direct
    // test of whether the per-block rate depends on N at all.
    println!("\n## fixed seed, varying N (same tag key and data seed)");
    for n2 in [100_000usize, 500_000, 1_000_000] {
        let seed = 0x5eed_0000_0000_0001u64;
        let report = run_one(n2, 1000, Layout::Clustered, seed);
        print_report("fixedseed", &report);
    }

    // Pilot reproduction: exp2a (N=1e6, sigma=1%, P1..P4, both layouts).
    println!("\n## pilot reproduction: exp2a seeding");
    let n = 1_000_000usize;
    let sigma = n / 100;
    for layout in [Layout::Clustered, Layout::Scattered] {
        let seed = seed_for(DEFAULT_SEED, &["exp2a", layout.name()]);
        let report = run_one(n, sigma, layout, seed);
        print_report("pilot/exp2a", &report);
    }

    // Pilot reproduction: exp2b 0.1% (same N, same sigma=1000, both layouts).
    println!("\n## pilot reproduction: exp2b sigma=0.1% seeding (n=1e6, sigma=1000)");
    for layout in [Layout::Clustered, Layout::Scattered] {
        let seed = seed_for(
            DEFAULT_SEED,
            &["exp2b", layout.name(), "0.1", &n.to_string()],
        );
        let report = run_one(n, 1000, layout, seed);
        print_report("pilot/exp2b0.1", &report);
    }

    // Same N and sigma as exp1 fixed_nq1000 at N=1e6, but different seeds:
    // this separates "grows with N" from "different data seed".
    println!("\n## seed sensitivity: n=1e6, sigma=1000, clustered, several exp1-style seeds");
    for extra in ["seedA", "seedB", "seedC"] {
        let seed = seed_for(DEFAULT_SEED, &["exp1", "fixed_nq1000", &n.to_string(), extra]);
        let report = run_one(n, 1000, Layout::Clustered, seed);
        print_report("seedvar", &report);
    }
}
