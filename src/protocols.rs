//! The implementation of "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"
//! by Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! (CCS'20: Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security
//! 1769-1787 (2020),
//! DOI: 10.1145/3372297.3423367)
//!
//! The equation and figure numbers in the comments, and the notation used
//! refers to the version of the paper published at <https://eprint.iacr.org/2021/060.pdf>

mod aux_gen;
mod interactive_signing;
mod key_init;
mod key_refresh;
mod key_resharing;

#[cfg(test)]
mod misbehavior_tests;

pub use aux_gen::{AuxGen, AuxGenAssociatedData, AuxGenProtocol};
pub use interactive_signing::{
    InteractiveSigning, InteractiveSigningAssociatedData, InteractiveSigningProtocol, PrehashedMessage,
};
pub use key_init::{KeyInit, KeyInitAssociatedData, KeyInitProtocol};
pub use key_refresh::{KeyRefresh, KeyRefreshAssociatedData, KeyRefreshProtocol};
pub use key_resharing::{KeyResharing, KeyResharingProtocol, NewHolder, OldHolder};
