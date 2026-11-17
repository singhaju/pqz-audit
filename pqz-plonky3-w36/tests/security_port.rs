//! The Rust port of the winter-air 0.13.1 estimator (src/security.rs) must give exactly the bits that winterfell prints for
//! a real w30 proof (same options: 40 queries, blowup 8, grinding 16, ext 2, folding 8, remainder degree 31, Blake3/Sha3 = 128).

use pqz_plonky3_w36::security::{estimate, winterfell_layers, SecInput};
use pqz_proof::exec::prove_exec;
use pqz_proof::prove::security_of;
use pqz_proof::rescue::F as F30;

#[test]
fn port_equals_winterfell_on_a_real_proof() {
    for n in [1000usize, 5000] {
        let w = pqz_proof::data::Workload::synthetic(n, 100, 1);
        let ctx = [F30::new(1), F30::new(2), F30::new(3), F30::new(4)];
        let (proof, _p) = prove_exec(&w, 1 << 31, ctx).expect("prove");
        let real = security_of(&proof);
        let len = proof.trace_info().length();
        let i = SecInput {
            base_field_bits: 64,
            ext_degree: 2,
            trace_len: len,
            blowup: 8,
            num_queries: 40,
            grinding: 16,
            folding_factor: 8,
            num_fri_layers: winterfell_layers(len * 8, 8, 32),
            collision_resistance: 128,
        };
        let mine = estimate(&i);
        println!("n={n} trace_len={len} winterfell=({},{},{}) port=({},{},{})", real.conjectured_bits, real.proven_unique_decoding_bits, real.proven_list_decoding_bits, mine.conjectured, mine.proven_unique_decoding, mine.proven_list_decoding);
        assert_eq!(mine.conjectured, real.conjectured_bits);
        assert_eq!(mine.proven_unique_decoding, real.proven_unique_decoding_bits);
        assert_eq!(mine.proven_list_decoding, real.proven_list_decoding_bits);
    }
}
