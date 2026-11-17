//! Runs the real binary on tiny points and checks the csv of the SPEC-w16 stages.
use std::process::Command;

fn run(extra: &[&str], dir: &str) -> String {
    let out = std::env::temp_dir().join(dir);
    let _ = std::fs::remove_dir_all(&out);
    let st = Command::new(env!("CARGO_BIN_EXE_dong-bench-par"))
        .args(extra)
        .args(["--out", out.to_str().unwrap()])
        .output()
        .expect("run dong-bench");
    assert!(st.status.success(), "dong-bench failed: {}", String::from_utf8_lossy(&st.stderr));
    std::fs::read_to_string(out.join("raw_runs.csv")).unwrap()
}

#[test]
fn cov_and_q_sweep_writes_all_stages() {
    // cov 10 and 30, q 1 and 3; --big-above 20 makes cov 30 (and q*cov = 30, 90) use --runs-big 2 with 1 warm-up
    let csv = run(&["--cov", "10,30", "--q", "1,3", "--runs", "3", "--warmup", "0", "--runs-big", "2", "--big-above", "20", "--params-tag", "t1"], "dong-cli-test-1");
    let mut lines = csv.lines();
    assert_eq!(lines.next().unwrap(), "baseline,stage,params,run,ms");
    let rows: Vec<Vec<&str>> = lines.map(|l| l.split(',').collect()).collect();
    let count = |stage: &str, params: &str| rows.iter().filter(|r| r[1] == stage && r[2] == params).count();
    assert_eq!(count("proofgen", "s=3;c=10;n=100;runs=3;t1"), 3);
    assert_eq!(count("verify", "s=3;c=10;n=100;runs=3;t1"), 3);
    assert_eq!(count("verify_q", "s=3;c=10;n=100;q=1;runs=3;t1"), 3);
    // q*c = 30 > 20 -> big: 2 timed runs
    assert_eq!(count("verify_q", "s=3;c=10;n=100;q=3;runs=2;t1"), 2);
    // c = 30 > 20 -> big for every stage
    assert_eq!(count("proofgen", "s=3;c=30;n=300;runs=2;t1"), 2);
    assert_eq!(count("verify", "s=3;c=30;n=300;runs=2;t1"), 2);
    assert_eq!(count("verify_q", "s=3;c=30;n=300;q=1;runs=2;t1"), 2);
    assert_eq!(count("verify_q", "s=3;c=30;n=300;q=3;runs=2;t1"), 2);
    assert_eq!(rows.len(), 3 + 3 + 3 + 2 + 2 + 2 + 2 + 2);
    assert!(rows.iter().all(|r| r[0] == "dong" && r[4].parse::<f64>().unwrap() > 0.0));
}

#[test]
fn q_alone_is_exp4b_verify_q_only_at_cov_1000() {
    // cov defaults to 1000; q=1 keeps it fast (1000 hashes + 1000 scalar mults per run)
    let csv = run(&["--q", "1", "--runs", "1", "--warmup", "0", "--runs-big", "1"], "dong-cli-test-2");
    let rows: Vec<&str> = csv.lines().skip(1).collect();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].starts_with("dong,verify_q,s=3;c=1000;n=10000;q=1;runs=1,0,"), "{}", rows[0]);
}

#[test]
fn default_grid_unchanged_quick() {
    let csv = run(&["--quick"], "dong-cli-test-3");
    let rows: Vec<&str> = csv.lines().skip(1).collect();
    assert_eq!(rows.len(), 4 * 3);
    assert!(rows.iter().any(|r| r.starts_with("dong,proofgen,s=3;c=10,0,")));
    assert!(rows.iter().any(|r| r.starts_with("dong,verify,s=3;c=50,2,")));
}
