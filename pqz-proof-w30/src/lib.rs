//! PROVISIONAL hash-based STARK prototypes (winterfell 0.13.1) of the PQZK relations of PQZ-Audit.
//! Read DESIGN.md first: it states what each AIR proves and, more importantly, what it does not.

pub mod auth;
pub mod chain;
pub mod chain_link;
pub mod cover;
pub mod covermerkle;
pub mod data;
pub mod exec;
pub mod exec_link;
pub mod par_link;
pub mod prove;
pub mod rc;
pub mod rc_link;
pub mod rescue;
pub mod split;
pub mod request;
