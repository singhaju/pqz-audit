//! env.txt: what a reader needs to judge or repeat a run (CPU, rustc, Cargo.lock hash, crate versions).

use crate::hashing::{h, hex};
use std::fs;
use std::process::Command;

const CARGO_LOCK: &str = include_str!("../Cargo.lock");

fn read(p: &str) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn cpu_model() -> String {
    read("/proc/cpuinfo")
        .and_then(|s| s.lines().find(|l| l.starts_with("model name")).map(|l| l.split(':').nth(1).unwrap_or("").trim().to_string()))
        .unwrap_or_else(|| "unknown".into())
}

fn cores() -> String {
    read("/proc/cpuinfo").map(|s| s.lines().filter(|l| l.starts_with("processor")).count().to_string()).unwrap_or_else(|| "unknown".into())
}

fn lock_version(name: &str) -> String {
    let mut found: Vec<String> = Vec::new();
    let mut lines = CARGO_LOCK.lines();
    while let Some(l) = lines.next() {
        if l.trim() == format!("name = \"{}\"", name) {
            if let Some(v) = lines.next() {
                found.push(v.trim().trim_start_matches("version = ").trim_matches('"').to_string());
            }
        }
    }
    if found.is_empty() {
        "not in lock file".into()
    } else {
        found.join(", ")
    }
}

/// Cargo.lock as compiled into this binary: SHA3-256 (computed here) and SHA-256 (via `sha256sum`, if present).
fn lock_hashes() -> (String, String) {
    let sha3 = hex(&h(&[CARGO_LOCK.as_bytes()]));
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.lock");
    let sha2 = Command::new("sha256sum")
        .arg(path)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().next().map(|x| x.to_string()))
        .unwrap_or_else(|| "sha256sum not available".into());
    (sha3, sha2)
}

/// `extra` lines are appended as given (run configuration).
pub fn env_txt(program: &str, extra: &[String]) -> String {
    let (sha3, sha2) = lock_hashes();
    let mut s = String::new();
    s.push_str(&format!("program: {} (pqz-ledger {})\n", program, env!("CARGO_PKG_VERSION")));
    s.push_str("status: PROVISIONAL simulation, one process, no network (see README.md)\n");
    s.push_str(&format!("cpu_model: {}\n", cpu_model()));
    s.push_str(&format!("logical_cpus: {}\n", cores()));
    s.push_str(&format!("scaling_governor: {}\n", read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").unwrap_or_else(|| "unknown".into())));
    s.push_str(&format!("kernel: {}\n", read("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into())));
    s.push_str(&format!("rustc: {}\n", env!("PQZ_RUSTC_VERSION")));
    s.push_str("profile: release (opt-level 3, lto, codegen-units 1)\n");
    s.push_str(&format!("feature_mutation: {}\n", cfg!(feature = "mutation")));
    s.push_str(&format!("cargo_lock_sha256: {}\n", sha2));
    s.push_str(&format!("cargo_lock_sha3_256_of_compiled_copy: {}\n", sha3));
    for c in ["ml-dsa", "sha3", "rand_chacha", "rand_core"] {
        s.push_str(&format!("crate {}: {}\n", c, lock_version(c)));
    }
    for e in extra {
        s.push_str(e);
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn env_text_has_the_required_fields() {
        let t = env_txt("test", &["runs: 3".to_string()]);
        for k in ["cpu_model:", "rustc: rustc", "cargo_lock_sha256:", "cargo_lock_sha3_256_of_compiled_copy:", "crate ml-dsa: 0.1.1", "crate sha3: 0.12.0", "runs: 3"] {
            assert!(t.contains(k), "missing {}", k);
        }
    }
}
