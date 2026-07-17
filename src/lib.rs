//! Convert SP1 Groth16 proof artifacts to snarkjs-compatible JSON.
//!
//! Main path:
//! `SP1ProofWithPublicValues::load("proof.bin")` -> `proof.json`,
//! `public.json`, `verification_key.json`.

pub mod error;
pub mod export;
pub mod snarkjs;
pub mod sp1;

pub use error::{Result, Sp1ToSnarkjsError};
pub use export::{convert_sp1_proof, convert_sp1_proof_file, write_artifacts, ExportedArtifacts};
pub use snarkjs::{SnarkJsProof, SnarkJsVerificationKey};
