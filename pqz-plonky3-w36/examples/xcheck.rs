//! Stage B pre-timing check: (count, sum) of every system on the same data (seed 1, block 100) at every N of the matrix.
//! Systems here: the w30 reference statement (`exec_public`, the statement the w30 prover proves and its verifier checks;
//! read-only library dependency) and the Plonky3 statements of C1, C1r0, C2 (integer reference function, no circuit code).
//! w31 is checked by `xcheck31/` (a separate crate: two crates named pqz-proof cannot share one lockfile); the shell
//! script `scripts/xcheck.sh` compares the two outputs.
//! Output: one line per N, "XCHECK n=... w30=(c,s) c1=(c,s) c1r0=(c,s) c2=(c,s) EQUAL|MISMATCH". Exit code 1 on MISMATCH.
//! The Plonky3 timed children additionally verify their own proof against that statement every run.

use pqz_plonky3_w36::data::Workload;
use pqz_plonky3_w36::{c1, c1r0, c2};

const THETA: u64 = 1 << 31;

fn main() {
    let mut bad = false;
    for n in [1_000usize, 10_000, 50_000, 100_000] {
        let w30 = pqz_proof::data::Workload::synthetic(n, 100, 1);
        let ctx30 = [pqz_proof::rescue::F::new(1), pqz_proof::rescue::F::new(2), pqz_proof::rescue::F::new(3), pqz_proof::rescue::F::new(4)];
        let p30 = pqz_proof::exec::exec_public(&w30, THETA, ctx30);
        let w = Workload::synthetic(n, 100, 1);
        let a = c1::public_for(&w, THETA, [1, 2, 3, 4]);
        let b = c1r0::public_for(&w, THETA, [1, 2, 3, 4]);
        let c = c2::public_for(&w, THETA, [1, 2, 3, 4]);
        // w31 packs b as ONE bit (CHANGES-w31.md: b in {0,1}); its sum should equal the sum of the low bit of b over the matches
        let lsb: u64 = w30.words.iter().filter(|x| x[7].as_int() == 0 && x[4].as_int() >= THETA).map(|x| x[5].as_int() & 1).sum();
        let r30 = (p30.count, p30.sum);
        let ra = (a.count, a.sum_int());
        let rb = (b.count, b.sum_int());
        let rc = (c.count, c.sum_int());
        let eq = r30 == ra && r30 == rb && r30 == rc;
        if !eq {
            bad = true;
        }
        println!("XCHECK n={n} w30_lsb_sum={lsb} w30={r30:?} c1={ra:?} c1r0={rb:?} c2={rc:?} blocks30={} {}", p30.n_blocks, if eq { "EQUAL" } else { "MISMATCH" });
    }
    if bad {
        std::process::exit(1);
    }
}
