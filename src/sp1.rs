use std::path::Path;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use sp1_verifier::Groth16Bn254Proof;

use crate::error::{Result, Sp1ToSnarkjsError};

const SP1_GROTH16_METADATA_BYTES: usize = 96;
const GROTH16_PROOF_BYTES: usize = 256;
const SP1_GROTH16_ENCODED_BYTES: usize = SP1_GROTH16_METADATA_BYTES + GROTH16_PROOF_BYTES;
const SUPPORTED_SP1_VERSION: &str = "v6.1.0";

pub fn load_sp1_proof(path: impl AsRef<Path>) -> Result<SP1ProofWithPublicValues> {
    SP1ProofWithPublicValues::load(path.as_ref())
        .map_err(|err| Sp1ToSnarkjsError::Sp1(err.to_string()))
}

fn groth16_proof(proof: &SP1ProofWithPublicValues) -> Result<&Groth16Bn254Proof> {
    if proof.sp1_version != SUPPORTED_SP1_VERSION {
        return Err(Sp1ToSnarkjsError::UnsupportedSp1Version {
            actual: proof.sp1_version.clone(),
        });
    }

    if proof.tee_proof.is_some() {
        return Err(Sp1ToSnarkjsError::TeeProofUnsupported);
    }

    match &proof.proof {
        SP1Proof::Groth16(groth16) if groth16.encoded_proof.is_empty() => {
            Err(Sp1ToSnarkjsError::MockProof)
        }
        SP1Proof::Groth16(groth16) => Ok(groth16),
        _ => Err(Sp1ToSnarkjsError::NotGroth16),
    }
}

pub fn sp1_groth16_public_inputs(proof: &SP1ProofWithPublicValues) -> Result<Vec<String>> {
    Ok(groth16_proof(proof)?.public_inputs.to_vec())
}

pub fn sp1_groth16_proof_bytes(proof: &SP1ProofWithPublicValues) -> Result<Vec<u8>> {
    let groth16 = groth16_proof(proof)?;
    let encoded = hex::decode(&groth16.encoded_proof)?;

    if encoded.len() != SP1_GROTH16_ENCODED_BYTES {
        return Err(Sp1ToSnarkjsError::InvalidEncodedProofLength {
            actual: encoded.len(),
            expected: SP1_GROTH16_ENCODED_BYTES,
        });
    }

    for (index, public_input) in groth16.public_inputs[2..5].iter().enumerate() {
        let expected = decimal_to_bytes32(public_input)?;
        let start = index * 32;
        if encoded[start..start + 32] != expected {
            return Err(Sp1ToSnarkjsError::EncodedMetadataMismatch);
        }
    }

    Ok(encoded[SP1_GROTH16_METADATA_BYTES..].to_vec())
}

fn decimal_to_bytes32(value: &str) -> Result<[u8; 32]> {
    let bytes = value
        .parse::<Fr>()
        .map_err(|_| Sp1ToSnarkjsError::InvalidDecimal(value.to_owned()))?;
    let bytes = bytes.into_bigint().to_bytes_be();

    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(padded)
}
