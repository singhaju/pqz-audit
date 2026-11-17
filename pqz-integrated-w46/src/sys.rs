//! Small /proc helpers (Linux).
use std::fs;

pub fn status_kb(key: &str) -> u64 {
    let s = fs::read_to_string("/proc/self/status").unwrap_or_default();
    for l in s.lines() {
        if let Some(r) = l.strip_prefix(key) {
            return r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

pub fn pid_status_kb(pid: u32, key: &str) -> u64 {
    let s = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    for l in s.lines() {
        if let Some(r) = l.strip_prefix(key) {
            return r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Reset the peak-RSS counter (VmHWM) of this process. Returns false if the kernel refused.
pub fn reset_hwm() -> bool {
    fs::write("/proc/self/clear_refs", "5").is_ok()
}

pub fn loadavg1() -> String {
    fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|x| x.to_string()))
        .unwrap_or_default()
}

pub fn mem_available_kb() -> u64 {
    let s = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    for l in s.lines() {
        if let Some(r) = l.strip_prefix("MemAvailable:") {
            return r.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    0
}

pub fn cmd_out(cmd: &str, args: &[&str]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unavailable".into())
}
