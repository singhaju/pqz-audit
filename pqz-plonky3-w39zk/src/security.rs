//! Security-bit estimator: "same formula, our application to Plonky3".
//!
//! This is a line-by-line port of the winter-air 0.13.1 estimator (`src/proof/security.rs`:
//! `ConjecturedSecurity::compute`, `ProvenSecurity::compute`, `proven_security_protocol_unique_decoding`,
//! `proven_security_protocol_for_given_proximity_parameter`, `compute_upper_m`), restricted to LINEAR batching
//! (the only mode the w30/w31 options use; with linear batching `num_constraints` and `num_committed_polys` drop out).
//! The port exists because winterfell computes the bits only from a winterfell `Proof` object, which Plonky3 does not
//! produce. `tests/security_port.rs` checks the port against the real winterfell value on a real w30 proof.
//!
//! The estimator is NOT proven to be the right model for Plonky3 (different FRI variant, DEEP/quotient layout, grinding
//! placement). Treat the output as a common yardstick for the comparison, not as a security claim about Plonky3.

#[derive(Clone, Debug)]
pub struct SecInput {
    /// bits of the BASE field modulus (Goldilocks 64, KoalaBear 31)
    pub base_field_bits: u32,
    /// degree of the extension (field_extension().degree())
    pub ext_degree: u32,
    /// trace domain size (rows, a power of two)
    pub trace_len: usize,
    /// blowup factor (2^log_blowup)
    pub blowup: usize,
    pub num_queries: usize,
    /// grinding bits of the query phase
    pub grinding: u32,
    /// FRI folding factor (8 in w30)
    pub folding_factor: usize,
    /// number of FRI folding layers
    pub num_fri_layers: usize,
    /// collision resistance of the commitment hash in bits (Blake3_256: 128)
    pub collision_resistance: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecBits {
    pub conjectured: u32,
    pub proven_unique_decoding: u32,
    pub proven_list_decoding: u32,
}

const GRINDING_CONTRIBUTION_FLOOR: u32 = 80;
const MAX_PROXIMITY_PARAMETER: u64 = 1000;

pub fn estimate(i: &SecInput) -> SecBits {
    SecBits {
        conjectured: conjectured(i),
        proven_unique_decoding: unique_decoding(i).min(i.collision_resistance as u64) as u32,
        proven_list_decoding: list_decoding(i),
    }
}

fn conjectured(i: &SecInput) -> u32 {
    let field_security = i.base_field_bits * i.ext_degree;
    let security_per_query = i.blowup.ilog2();
    let mut query_security = security_per_query * i.num_queries as u32;
    if query_security >= GRINDING_CONTRIBUTION_FLOOR {
        query_security += i.grinding;
    }
    std::cmp::min(std::cmp::min(field_security, query_security) - 1, i.collision_resistance)
}

fn list_decoding(i: &SecInput) -> u32 {
    let m_min: usize = 3;
    let m_max = compute_upper_m(i.trace_len);
    let m_opt = (m_min as u32..m_max as u32)
        .max_by_key(|&a| for_given_m(i, a as usize))
        .expect("m_max > m_min");
    std::cmp::min(for_given_m(i, m_opt as usize), i.collision_resistance as u64) as u32
}

fn for_given_m(i: &SecInput, m: usize) -> u64 {
    let ext_bits = (i.base_field_bits * i.ext_degree) as f64;
    let q = i.num_queries as f64;
    let m = m as f64;
    let rho = 1.0 / i.blowup as f64;
    let alpha = (1.0 + 0.5 / m) * rho.sqrt();
    let max_deg = i.blowup as f64 + 1.0;
    let lde = (i.trace_len * i.blowup) as f64;
    let h = i.trace_len as f64;
    let num_openings = 2.0;
    let mut e = vec![];
    let l = m / (rho - (2.0 * m / lde));
    // linear batching: batching_factor = 1 (log2 = 0)
    e.push(-l.log2() + ext_bits);
    e.push(-(l * l * (max_deg * (h + num_openings - 1.0) + (h - 1.0))).log2() + ext_bits);
    e.push(ext_bits - (((m + 0.5).powf(7.0) / (3.0 * rho.powf(1.5))) * lde.powf(2.0)).log2());
    e.push(i.grinding as f64 - alpha.powf(q).log2());
    e.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

fn unique_decoding(i: &SecInput) -> u64 {
    let ext_bits = (i.base_field_bits * i.ext_degree) as f64;
    let q = i.num_queries as f64;
    let lde = (i.trace_len * i.blowup) as f64;
    let h = i.trace_len as f64;
    let num_openings = 2.0;
    let rho_plus = (h + num_openings) / lde;
    let alpha = (1.0 + rho_plus) * 0.5;
    let max_deg = i.blowup as f64 + 1.0;
    let mut e = vec![];
    e.push(ext_bits);
    e.push(-(max_deg * (h + num_openings - 1.0) + (h - 1.0)).log2() + ext_bits);
    e.push(ext_bits - lde.log2());
    let ff = i.folding_factor as f64;
    let mn = (0..i.num_fri_layers).map(|_| ext_bits - ((ff - 1.0) * (lde + 1.0)).log2()).fold(f64::INFINITY, |a, b| a.min(b));
    e.push(mn);
    e.push(i.grinding as f64 - alpha.powf(q).log2());
    e.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

fn compute_upper_m(h: usize) -> f64 {
    let h = h as f64;
    let ratio = (h + 2.0) / h;
    let m_max = (1.0 / (2.0 * (ratio.sqrt() - 1.0))).ceil();
    assert!(m_max >= h / 2.0);
    std::cmp::min(m_max as u64, MAX_PROXIMITY_PARAMETER) as f64
}

/// Number of FRI folding layers the winterfell estimator would count for an LDE of `lde` points
/// (folding factor `ff`, remainder of at most `max_remainder` points): `FriOptions::num_fri_layers`.
pub fn winterfell_layers(mut lde: usize, ff: usize, max_remainder: usize) -> usize {
    let mut r = 0;
    while lde > max_remainder {
        lde /= ff;
        r += 1;
    }
    r
}

/// Plonky3 FRI layers: fold from `log_lde` down to `log_blowup + log_final_poly_len` with arity at most `max_log_arity`.
pub fn plonky3_layers(log_trace: usize, log_blowup: usize, log_final_poly_len: usize, max_log_arity: usize) -> usize {
    let from = log_trace + log_blowup;
    let to = log_blowup + log_final_poly_len;
    if from <= to {
        0
    } else {
        (from - to).div_ceil(max_log_arity)
    }
}
