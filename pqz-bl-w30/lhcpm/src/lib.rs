//! L-HCPM (Sun, Mahfuz, Wang, TDSC 2026) regulator audit (cache HIT) and Groth16 on stand-in circuits. See FIDELITY.md.
pub mod audit;
pub mod batch;
pub mod bfv;
pub mod circuits;
pub mod mimc;
pub mod par;
pub mod ring;
pub mod setup_w30;

#[cfg(test)]
mod tests;
