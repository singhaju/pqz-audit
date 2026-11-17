//! w30 (A2): command-line tests of `lhcpm-bench --only-setup` (runs the real binary).
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lhcpm-bench"))
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("lhcpm-setup-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[test]
fn only_setup_writes_raw_csv_and_meta_json() {
    let d = tmpdir("ok");
    let o = bin().args(["--only-setup", "--runs", "2", "--params-tag", "clitest", "--out", d.to_str().unwrap()]).output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let csv = std::fs::read_to_string(d.join("raw.csv")).unwrap();
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines[0], "stage,run,secs,pk_bytes,vk_bytes");
    assert_eq!(lines.len(), 1 + 4); // 2 runs of groth16_setup_mint + 2 of bfv_keygen_regulator, 1 warm-up not written
    assert!(lines[1].starts_with("groth16_setup_mint,0,"));
    assert!(lines[2].starts_with("groth16_setup_mint,1,"));
    assert!(lines[3].starts_with("bfv_keygen_regulator,0,"));
    let meta = std::fs::read_to_string(d.join("meta.json")).unwrap();
    assert!(meta.contains("\"params_tag\": \"clitest\"") && meta.contains("\"runs\": 2") && meta.contains("\"warmup\": 1"));
    assert!(!d.join("raw_runs.csv").exists(), "no other mode may run");
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("groth16_setup_mint") && out.contains("(2 runs, 1 warm-up)"), "{out}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn only_setup_rejects_more_than_one_thread_and_other_modes() {
    let d = tmpdir("bad");
    let o = bin().args(["--only-setup", "--threads", "2", "--out", d.to_str().unwrap()]).output().unwrap();
    assert!(!o.status.success());
    let o = bin().args(["--only-setup", "--only-batch-q", "--q", "2", "--out", d.to_str().unwrap()]).output().unwrap();
    assert!(!o.status.success());
    assert!(!d.join("raw.csv").exists());
}
