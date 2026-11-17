//! Stage C, gate G-C1 part 2: per-relation rejection tests for R_RC and R_Auth (plain C1 config).
//! For every constraint family at least one tamper, 5 trials each; the honest proof of the same instance is checked first.
//! Release build only (in a debug build the prover panics on a bad trace). The test fails only if a verifier ACCEPTS.
//! Kinds of tamper: (stream/witness) the prover is given a changed stream/witness and builds an internally consistent trace;
//! (cell) the honest trace is built and one cell is changed; (public) an honest proof is verified against a changed statement.
//! A summary CSV is written to results/stageC/gc1_reject_{rc,auth}.csv.
use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::prove;

use pqz_plonky3_w38::auth::{honest_auth_instance, AuthPublic, AuthWitness};
use pqz_plonky3_w38::data::{Rng, Workload};
use pqz_plonky3_w38::rc::RcPublic;
use pqz_plonky3_w38::rel::plain;
use pqz_plonky3_w38::{c1, FriOpts};

type V = c1::Val;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Accepted,
    ProverErr,
    ProverPanic,
    DeserFail,
    VerifyFail,
}

fn tally(r: &[Kind]) -> (usize, usize) {
    let acc = r.iter().filter(|&&k| k == Kind::Accepted).count();
    (r.len() - acc, acc)
}

// ------------------------------------------------------------------------------------------------ R_RC

struct RcCase {
    words: Vec<Vec<u64>>,
    prove_pub: RcPublic,
    cells: Vec<(usize, usize, u64)>, // (row, col, added value)
    ver_pub: RcPublic,
}

fn rc_attempt(o: &FriOpts, c: &RcCase) -> Kind {
    let prove_it = || -> Result<_, String> {
        let a = plain::rc_air(c.prove_pub.block_size as u64, c.prove_pub.n_words() as u64);
        let mut tr = a.build_trace(&plain::perm(), &c.words);
        for &(r, col, add) in &c.cells {
            let i = r * a.lay.width + col;
            tr.values[i] += V::from_u64(add);
        }
        let pv = c.prove_pub.to_values::<V>(&a.lay);
        prove(&c1::config(o), &a, tr, &pv).map_err(|e| format!("{e:?}"))
    };
    let proof = match catch_unwind(AssertUnwindSafe(prove_it)) {
        Err(_) => return Kind::ProverPanic,
        Ok(Err(_)) => return Kind::ProverErr,
        Ok(Ok(p)) => p,
    };
    let bytes = plain::to_bytes(&proof);
    let proof = match plain::from_bytes(&bytes) {
        Ok(p) => p,
        Err(_) => return Kind::DeserFail,
    };
    match plain::verify_rc(o, &proof, &c.ver_pub) {
        Ok(()) => Kind::Accepted,
        Err(_) => Kind::VerifyFail,
    }
}

fn below(r: &mut Rng, n: u64) -> u64 {
    r.next_u64() % n
}

#[test]
fn rc_rejection_per_family() {
    let o = FriOpts::from_env();
    let (n, bs) = (1000usize, 100usize);
    let w = Workload::synthetic(n, bs, 11);
    let words: Vec<Vec<u64>> = c1::words(&w);
    let pubh = plain::rc_public(&words, bs);
    let nw = words.len();
    let lay = plain::rc_air(bs as u64, nw as u64).lay;
    let honest = RcCase { words: words.clone(), prove_pub: pubh.clone(), cells: vec![], ver_pub: pubh.clone() };
    assert_eq!(rc_attempt(&o, &honest), Kind::Accepted, "honest proof must verify first");

    // helpers: random record index (not a header), random header index (not first)
    let rec = |r: &mut Rng| -> usize {
        loop {
            let i = 1 + below(r, (nw - 1) as u64) as usize;
            if words[i][7] == 0 {
                return i;
            }
        }
    };
    let hdr = |r: &mut Rng| -> usize { (1 + below(r, (w.n_blocks - 1) as u64) as usize) * (bs + 1) };
    let mid = |r: &mut Rng| -> usize { 1 + below(r, (nw - 3) as u64) as usize }; // transition rows only

    type Gen<'a> = Box<dyn Fn(&mut Rng) -> RcCase + 'a>;
    let base = |ws: Vec<Vec<u64>>, cells: Vec<(usize, usize, u64)>, ppub: RcPublic, vpub: RcPublic| RcCase {
        words: ws,
        prove_pub: ppub,
        cells,
        ver_pub: vpub,
    };
    let mut fams: Vec<(&str, &str, Gen)> = Vec::new();
    // cell tampers (honest stream, honest public)
    macro_rules! cell {
        ($name:expr, $fam:expr, $row:expr, $col:expr) => {
            fams.push((
                $name,
                $fam,
                Box::new(|r: &mut Rng| {
                    let row: usize = $row(r);
                    let col: usize = $col(r);
                    base(words.clone(), vec![(row, col, 1 + below(r, 1000))], pubh.clone(), pubh.clone())
                }),
            ));
        };
    }
    cell!("cell_poseidon2_internal", "R1", |r: &mut Rng| mid(r), |r: &mut Rng| 20 + below(r, (lay.p - 40) as u64) as usize);
    cell!("cell_word_v_absorbed", "R2", |r: &mut Rng| mid(r), |_r: &mut Rng| lay.c_word + 4);
    cell!("cell_word_any_absorbed", "R2", |r: &mut Rng| mid(r), |r: &mut Rng| lay.c_word + below(r, 8) as usize);
    cell!("cell_first_row_capacity", "R2-first", |_r: &mut Rng| 0usize, |r: &mut Rng| 8 + below(r, 4) as usize);
    cell!("cell_first_row_word", "R2/R3-first", |_r: &mut Rng| 0usize, |r: &mut Rng| lay.c_word + below(r, 8) as usize);
    cell!("cell_K0", "R3/R5-K", |_r: &mut Rng| 0usize, |_r: &mut Rng| lay.c_k);
    cell!("cell_K_row", "R5-K", |r: &mut Rng| mid(r), |r: &mut Rng| lay.c_k + below(r, 3) as usize);
    cell!("cell_cnt0", "R3", |_r: &mut Rng| 0usize, |_r: &mut Rng| lay.c_cnt);
    cell!("cell_cnt_row", "R5-cnt", |r: &mut Rng| mid(r), |_r: &mut Rng| lay.c_cnt);
    cell!("cell_mb0", "R3", |_r: &mut Rng| 0usize, |_r: &mut Rng| lay.c_mb);
    cell!("cell_mb_row", "R4/R5-mb", |r: &mut Rng| mid(r), |_r: &mut Rng| lay.c_mb);
    cell!("cell_hdr0", "R3", |_r: &mut Rng| 0usize, |_r: &mut Rng| lay.c_hdr);
    cell!("cell_hdr_row", "R5-hdr", |r: &mut Rng| mid(r), |_r: &mut Rng| lay.c_hdr);
    cell!("cell_idx", "R6", |r: &mut Rng| mid(r), |_r: &mut Rng| lay.c_idx);
    cell!("cell_last_flag", "R6", |r: &mut Rng| mid(r), |_r: &mut Rng| lay.c_last);
    cell!("cell_inv", "R6", |r: &mut Rng| mid(r), |_r: &mut Rng| lay.c_inv);
    cell!("cell_seen", "R6", |r: &mut Rng| mid(r), |_r: &mut Rng| lay.c_seen);
    cell!("cell_last_row_hdr", "R7", |_r: &mut Rng| nw - 1, |_r: &mut Rng| lay.c_hdr);
    cell!("cell_last_row_cnt", "R7", |_r: &mut Rng| nw - 1, |_r: &mut Rng| lay.c_cnt);
    cell!("cell_last_row_mb", "R7", |_r: &mut Rng| nw - 1, |_r: &mut Rng| lay.c_mb);
    cell!("cell_last_row_output", "R7/R1", |_r: &mut Rng| nw - 1, |_r: &mut Rng| lay.p - 1 - 0);

    // stream tampers (prover given the changed stream and the honest public; trace internally consistent)
    macro_rules! stream {
        ($name:expr, $fam:expr, $f:expr) => {
            fams.push((
                $name,
                $fam,
                Box::new(|r: &mut Rng| {
                    let mut ws = words.clone();
                    let f: &dyn Fn(&mut Vec<Vec<u64>>, &mut Rng) = &$f;
                    f(&mut ws, r);
                    base(ws, vec![], pubh.clone(), pubh.clone())
                }),
            ));
        };
    }
    stream!("stream_pid_changed", "R5-record", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = rec(r);
        ws[i][0] += 1 + below(r, 100);
    });
    stream!("stream_epoch_changed", "R5-record", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = rec(r);
        ws[i][1] += 1 + below(r, 100);
    });
    stream!("stream_seq_changed", "R5-record", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = rec(r);
        ws[i][2] += 1 + below(r, 100);
    });
    stream!("stream_record_dropped", "R2/R5/R6/R7", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = rec(r);
        ws.remove(i);
    });
    stream!("stream_record_duplicated", "R5/R6/R7", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = rec(r);
        let x = ws[i].clone();
        ws.insert(i, x);
    });
    stream!("stream_records_reordered", "R5", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = rec(r);
        if i + 1 < ws.len() && ws[i + 1][7] == 0 {
            ws.swap(i, i + 1);
        } else {
            ws.swap(i - 1, i);
            if ws[i - 1][7] == 1 {
                ws.swap(i - 1, i);
                ws[i][2] += 1;
            }
        }
    });
    stream!("stream_flag_not_boolean", "R4-flag", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = rec(r);
        ws[i][7] = 2 + below(r, 100);
    });
    stream!("stream_header_mB_wrong", "R4-mB", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = hdr(r);
        ws[i][2] = 1 + below(r, (bs - 1) as u64); // not 0 and not block_size
    });
    stream!("stream_header_epoch_changed", "R5-header", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = hdr(r);
        ws[i][0] += 1 + below(r, 100);
    });
    stream!("stream_header_pid_changed", "R5-header", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = hdr(r);
        ws[i][3] += 1 + below(r, 100);
    });
    stream!("stream_header_seqstart_changed", "R5-header", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = hdr(r);
        ws[i][4] += 1 + below(r, 100);
    });
    stream!("stream_header_flag_cleared", "R5/R4", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let i = hdr(r);
        ws[i][7] = 0;
    });
    stream!("stream_first_header_changed", "R3", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        let j = [0usize, 3, 4][below(r, 3) as usize];
        ws[0][j] += 1 + below(r, 100);
    });
    stream!("stream_first_header_mB_wrong", "R3-mB", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        ws[0][2] = 1 + below(r, (bs - 1) as u64);
    });
    stream!("stream_last_record_dropped", "R7-cnt", |ws: &mut Vec<Vec<u64>>, _r: &mut Rng| {
        ws.pop();
    });
    stream!("stream_extra_record_at_end", "R7/R6", |ws: &mut Vec<Vec<u64>>, _r: &mut Rng| {
        let mut x = ws.last().unwrap().clone();
        x[2] += 1;
        ws.push(x);
    });
    stream!("stream_empty_block_dropped", "R5-hdr/R7", |ws: &mut Vec<Vec<u64>>, r: &mut Rng| {
        // drop a whole block (header + records)
        let b = 1 + below(r, (w.n_blocks - 1) as u64) as usize;
        let s = b * (bs + 1);
        ws.drain(s..s + bs + 1);
    });

    // public tampers (honest proof, changed statement)
    macro_rules! public {
        ($name:expr, $fam:expr, $f:expr) => {
            fams.push((
                $name,
                $fam,
                Box::new(|r: &mut Rng| {
                    let mut p = pubh.clone();
                    let f: &dyn Fn(&mut RcPublic, &mut Rng) = &$f;
                    f(&mut p, r);
                    base(words.clone(), vec![], pubh.clone(), p)
                }),
            ));
        };
    }
    public!("public_digest_changed", "R7", |p: &mut RcPublic, r: &mut Rng| {
        let j = below(r, 4) as usize;
        p.digest[j] = (p.digest[j] + 1 + below(r, 1 << 20)) % pqz_plonky3_w38::data::GOLDILOCKS_P;
    });
    public!("public_n_blocks_changed", "R7/R2", |p: &mut RcPublic, r: &mut Rng| {
        p.n_blocks += 1 + below(r, 5) as usize;
    });
    public!("public_n_blocks_smaller", "R7/R2", |p: &mut RcPublic, r: &mut Rng| {
        p.n_blocks -= 1 + below(r, 5) as usize;
    });
    public!("public_header0_changed", "R3", |p: &mut RcPublic, r: &mut Rng| {
        let j = [0usize, 3, 4][below(r, 3) as usize];
        p.header0[j] += 1 + below(r, 100);
    });
    public!("public_block_size_changed", "R3/R4/R7", |p: &mut RcPublic, _r: &mut Rng| {
        p.block_size += 1;
    });

    let mut rows = Vec::new();
    let mut accepted_total = 0;
    for (name, fam, g) in &fams {
        let mut res = Vec::new();
        let mut rng = Rng::new(0x57a6ec_u64 ^ name.len() as u64 ^ (name.as_bytes()[name.len() - 1] as u64) << 8);
        for _ in 0..5 {
            let c = g(&mut rng);
            res.push(rc_attempt(&o, &c));
        }
        let (rej, acc) = tally(&res);
        let kinds: Vec<String> = res.iter().map(|k| format!("{k:?}")).collect();
        eprintln!("rc {name:34} {fam:14} rejected {rej}/5 accepted {acc}  {}", kinds.join(","));
        rows.push(format!("{name},{fam},5,{rej},{acc},{}", kinds.join("|")));
        accepted_total += acc;
    }
    std::fs::create_dir_all("results/stageC").ok();
    std::fs::write(
        "results/stageC/gc1_reject_rc.csv",
        format!("tamper,family,trials,rejected,accepted,kinds\n{}\n", rows.join("\n")),
    )
    .ok();
    assert_eq!(accepted_total, 0, "a tampered R_RC statement was ACCEPTED");
}

// ------------------------------------------------------------------------------------------------ R_Auth

struct AuthCase {
    prove_pub: AuthPublic,
    wit: AuthWitness,
    cells: Vec<(usize, usize, u64)>,
    ver_pub: AuthPublic,
}

fn auth_attempt(o: &FriOpts, c: &AuthCase) -> Kind {
    let prove_it = || -> Result<_, String> {
        let p = &c.prove_pub;
        if p.depth < 1 || p.depth > 40 {
            return Err("depth".into());
        }
        let a = plain::auth_air(p.depth);
        let mut tr = a.build_trace(&plain::perm(), p, &c.wit)?;
        for &(r, col, add) in &c.cells {
            let i = r * a.lay.width + col;
            tr.values[i] += V::from_u64(add);
        }
        let pv = p.to_values::<V>();
        prove(&c1::config(o), &a, tr, &pv).map_err(|e| format!("{e:?}"))
    };
    let proof = match catch_unwind(AssertUnwindSafe(prove_it)) {
        Err(_) => return Kind::ProverPanic,
        Ok(Err(_)) => return Kind::ProverErr,
        Ok(Ok(p)) => p,
    };
    let bytes = plain::to_bytes(&proof);
    let proof = match plain::from_bytes(&bytes) {
        Ok(p) => p,
        Err(_) => return Kind::DeserFail,
    };
    match plain::verify_auth(o, &proof, &c.ver_pub) {
        Ok(()) => Kind::Accepted,
        Err(_) => Kind::VerifyFail,
    }
}

#[test]
fn auth_rejection_per_family() {
    let o = FriOpts::from_env();
    let depth = 10usize;
    let (pubh, wit) = honest_auth_instance::<V, _>(&c1::perm(), depth, 5);
    let lay = plain::auth_air(depth).lay;
    let honest = AuthCase { prove_pub: pubh.clone(), wit: wit.clone(), cells: vec![], ver_pub: pubh.clone() };
    assert_eq!(auth_attempt(&o, &honest), Kind::Accepted, "honest proof must verify first");
    let d = depth;

    type Gen<'a> = Box<dyn Fn(&mut Rng) -> AuthCase + 'a>;
    // row ranges: merge rows 2..d+1, range rows d+4..d+12, used rows 0..d+12
    let used = |r: &mut Rng| 1 + below(r, (d + 12) as u64) as usize;
    let merge = |r: &mut Rng| 2 + below(r, d as u64) as usize;
    let range = |r: &mut Rng| d + 4 + below(r, 9) as usize;
    let mut fams: Vec<(&str, &str, Gen)> = Vec::new();
    macro_rules! cell {
        ($name:expr, $fam:expr, $row:expr, $col:expr, $minadd:expr) => {
            fams.push((
                $name,
                $fam,
                Box::new(|r: &mut Rng| {
                    let row: usize = $row(r);
                    let col: usize = $col(r);
                    let add = $minadd + below(r, 1000);
                    AuthCase { prove_pub: pubh.clone(), wit: wit.clone(), cells: vec![(row, col, add)], ver_pub: pubh.clone() }
                }),
            ));
        };
    }
    cell!("cell_poseidon2_internal", "A1", |r: &mut Rng| used(r), |r: &mut Rng| 20 + below(r, (lay.p - 40) as u64) as usize, 1);
    cell!("cell_flag_fl1", "A2", |r: &mut Rng| below(r, 64) as usize, |_r: &mut Rng| lay.c_fl1, 1);
    cell!("cell_flag_fl2", "A2", |r: &mut Rng| below(r, 64) as usize, |_r: &mut Rng| lay.c_fl2, 1);
    cell!("cell_flag_fm", "A2", |r: &mut Rng| below(r, 64) as usize, |_r: &mut Rng| lay.c_fm, 1);
    cell!("cell_flag_fb1", "A2/A3", |r: &mut Rng| below(r, 64) as usize, |_r: &mut Rng| lay.c_fb1, 1);
    cell!("cell_flag_fb2", "A2/A3", |r: &mut Rng| below(r, 64) as usize, |_r: &mut Rng| lay.c_fb2, 1);
    cell!("cell_flag_fr", "A2/A4", |r: &mut Rng| below(r, 64) as usize, |r: &mut Rng| lay.c_fr + below(r, 9) as usize, 1);
    cell!("cell_idx", "A2", |r: &mut Rng| used(r), |_r: &mut Rng| lay.c_idx, 1);
    cell!("cell_invb1", "A2", |r: &mut Rng| used(r), |_r: &mut Rng| lay.c_invb1, 1);
    cell!("cell_seen", "A2", |r: &mut Rng| used(r), |_r: &mut Rng| lay.c_seen, 1);
    cell!("cell_policy_held_constant", "A2", |r: &mut Rng| used(r), |r: &mut Rng| lay.c_p + below(r, 12) as usize, 1);
    cell!("cell_dg", "A2/A3", |r: &mut Rng| used(r), |r: &mut Rng| lay.c_dg + below(r, 4) as usize, 1);
    cell!("cell_dir_bit", "A3-merge", |r: &mut Rng| merge(r), |_r: &mut Rng| lay.c_d, 1);
    cell!("cell_sibling", "A3-merge", |r: &mut Rng| merge(r), |r: &mut Rng| lay.c_sib + below(r, 4) as usize, 1);
    cell!("cell_range_bit_sum", "A4", |r: &mut Rng| range(r), |r: &mut Rng| lay.c_bd + below(r, 32) as usize, 1);
    cell!("cell_range_bit_not_boolean", "A4-bool", |r: &mut Rng| below(r, 64) as usize, |r: &mut Rng| lay.c_bd + below(r, 32) as usize, 2);
    cell!("cell_last_row_seen", "A2", |_r: &mut Rng| 63usize, |_r: &mut Rng| lay.c_seen, 1);

    // witness / statement tampers through the prover
    macro_rules! wit {
        ($name:expr, $fam:expr, $f:expr) => {
            fams.push((
                $name,
                $fam,
                Box::new(|r: &mut Rng| {
                    let mut p = pubh.clone();
                    let mut w = wit.clone();
                    let f: &dyn Fn(&mut AuthPublic, &mut AuthWitness, &mut Rng) = &$f;
                    f(&mut p, &mut w, r);
                    AuthCase { prove_pub: pubh.clone(), wit: w, cells: vec![], ver_pub: pubh.clone() }.with_prove_pub(p)
                }),
            ));
        };
    }
    impl AuthCase {
        // prover builds from `p` but the verifier keeps the honest statement
        fn with_prove_pub(mut self, p: AuthPublic) -> Self {
            self.prove_pub = p;
            self
        }
    }
    wit!("witness_sibling_wrong", "A3-root", |_p, w, r| {
        let i = below(r, d as u64) as usize;
        w.siblings[i][0] ^= 1 + below(r, 1 << 20);
    });
    wit!("witness_index_wrong", "A3-merge/root", |_p, w, r| {
        w.index ^= 1 << below(r, d as u64);
    });
    wit!("witness_leaf_uid_wrong", "A2/A3-first", |_p, w, r| {
        w.leaf.uid += 1 + below(r, 1000);
    });
    wit!("witness_leaf_v_a_wrong", "A2/A3-first", |_p, w, r| {
        w.leaf.v_a += 1 + below(r, 1000);
    });
    wit!("witness_leaf_blind_wrong", "A3-root", |_p, w, r| {
        w.leaf.blind ^= 1 + below(r, 1 << 20);
    });
    wit!("witness_leaf_level_wrong", "A3-root/A4", |_p, w, r| {
        w.leaf.level += 1 + below(r, 5);
    });
    // scope outside the policy (the policy leaf is the honest one; the claimed scope is not covered)
    wit!("scope_s_lo_below_policy", "A4", |p, _w, _r| {
        p.scope.s.0 = 400;
    });
    wit!("scope_s_hi_above_policy", "A4", |p, _w, _r| {
        p.scope.s.1 = 4001 + 10;
    });
    wit!("scope_e_lo_below_policy", "A4", |p, _w, _r| {
        p.scope.e.0 = 0;
    });
    wit!("scope_t_hi_above_policy", "A4", |p, _w, _r| {
        p.scope.t.1 = 5001;
    });
    wit!("scope_p_above_policy", "A4", |p, _w, _r| {
        p.scope.p = 8;
    });
    wit!("scope_level_above_policy", "A4", |p, _w, _r| {
        p.scope.level = 4;
    });
    wit!("scope_e_hi_above_policy", "A4", |p, _w, _r| {
        p.scope.e.1 = 9;
    });
    wit!("scope_t_lo_below_policy_wrap", "A4-wrap", |p, _w, r| {
        // claimed lower bound is below the policy's: diff wraps in the field; must still fail
        p.scope.t.0 = 0;
        p.scope.s.0 = 1 + below(r, 400);
    });
    wit!("public_depth_not_matching_witness", "A3/A2", |p, _w, _r| {
        p.depth = d; // placeholder (same): replaced below by a different-depth public in the `public` family
    });
    fams.pop(); // drop the placeholder

    // public tampers (honest proof against a changed statement)
    macro_rules! public {
        ($name:expr, $fam:expr, $f:expr) => {
            fams.push((
                $name,
                $fam,
                Box::new(|r: &mut Rng| {
                    let mut p = pubh.clone();
                    let f: &dyn Fn(&mut AuthPublic, &mut Rng) = &$f;
                    f(&mut p, r);
                    AuthCase { prove_pub: pubh.clone(), wit: wit.clone(), cells: vec![], ver_pub: p }
                }),
            ));
        };
    }
    public!("public_uid", "A3/A2", |p, r| p.uid += 1 + below(r, 1000));
    public!("public_v_a", "A3/A2", |p, r| p.v_a += 1 + below(r, 1000));
    public!("public_v_auth", "A3", |p, r| p.v_auth += 1 + below(r, 1000));
    public!("public_r_pol", "A3-root", |p, r| p.r_pol[below(r, 4) as usize] ^= 1 + below(r, 1 << 20));
    public!("public_b_q", "A3-bind", |p, r| p.b_q[below(r, 4) as usize] ^= 1 + below(r, 1 << 20));
    public!("public_d_q", "A3-bind", |p, r| p.d_q[below(r, 4) as usize] ^= 1 + below(r, 1 << 20));
    public!("public_omega", "A3-bind", |p, r| p.omega[below(r, 4) as usize] ^= 1 + below(r, 1 << 20));
    public!("public_scope_field", "A4", |p, r| match below(r, 8) {
        0 => p.scope.s.0 += 1 + below(r, 50),
        1 => p.scope.s.1 += 1 + below(r, 50),
        2 => p.scope.e.0 += 1 + below(r, 50),
        3 => p.scope.e.1 += 1 + below(r, 50),
        4 => p.scope.t.0 += 1 + below(r, 50),
        5 => p.scope.t.1 += 1 + below(r, 50),
        6 => p.scope.p += 1 + below(r, 50),
        _ => p.scope.level += 1 + below(r, 50),
    });
    public!("public_depth_plus_1", "A2/A3", |p, _r| p.depth += 1);
    public!("public_depth_minus_1", "A2/A3", |p, _r| p.depth -= 1);

    let mut rows = Vec::new();
    let mut accepted_total = 0;
    for (name, fam, g) in &fams {
        let mut res = Vec::new();
        let mut rng = Rng::new(0xa07b_u64 ^ name.len() as u64 ^ (name.as_bytes()[name.len() - 1] as u64) << 8);
        for _ in 0..5 {
            let c = g(&mut rng);
            res.push(auth_attempt(&o, &c));
        }
        let (rej, acc) = tally(&res);
        let kinds: Vec<String> = res.iter().map(|k| format!("{k:?}")).collect();
        eprintln!("auth {name:34} {fam:14} rejected {rej}/5 accepted {acc}  {}", kinds.join(","));
        rows.push(format!("{name},{fam},5,{rej},{acc},{}", kinds.join("|")));
        accepted_total += acc;
    }
    std::fs::create_dir_all("results/stageC").ok();
    std::fs::write(
        "results/stageC/gc1_reject_auth.csv",
        format!("tamper,family,trials,rejected,accepted,kinds\n{}\n", rows.join("\n")),
    )
    .ok();
    let _ = PrimeField64::as_canonical_u64(&V::ZERO);
    assert_eq!(accepted_total, 0, "a tampered R_Auth statement was ACCEPTED");
}
