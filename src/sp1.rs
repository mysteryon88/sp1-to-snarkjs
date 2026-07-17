use std::{fs, path::Path};

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use serde::{Deserialize, Serialize};
use sp1_primitives::io::SP1PublicValues;
use sp1_verifier::{Groth16Bn254Proof, ProofFromNetwork, SP1Proof};

use crate::error::{Result, Sp1ToSnarkjsError};

const SP1_GROTH16_METADATA_BYTES: usize = 96;
const GROTH16_PROOF_BYTES: usize = 256;
const SP1_GROTH16_ENCODED_BYTES: usize = SP1_GROTH16_METADATA_BYTES + GROTH16_PROOF_BYTES;
const SUPPORTED_SP1_VERSION: &str = "v6.1.0";
const GNARK_MASK: u8 = 0b11 << 6;
const GNARK_POSITIVE: u8 = 0b10 << 6;
const GNARK_NEGATIVE: u8 = 0b11 << 6;
const GNARK_INFINITY: u8 = 0b01 << 6;
const ARK_POSITIVE: u8 = 0;
const ARK_NEGATIVE: u8 = 0b10 << 6;
const ARK_INFINITY: u8 = 0b01 << 6;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SP1ProofWithPublicValues {
    pub proof: SP1Proof,
    pub public_values: SP1PublicValues,
    pub sp1_version: String,
    pub tee_proof: Option<Vec<u8>>,
}

impl From<ProofFromNetwork> for SP1ProofWithPublicValues {
    fn from(proof: ProofFromNetwork) -> Self {
        Self {
            proof: proof.proof,
            public_values: proof.public_values,
            sp1_version: proof.sp1_version,
            tee_proof: None,
        }
    }
}

fn ark_error(message: impl Into<String>) -> Sp1ToSnarkjsError {
    Sp1ToSnarkjsError::ArkConversion(message.into())
}

fn gnark_compressed_to_ark(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() != 32 && bytes.len() != 64 {
        return Err(ark_error("invalid compressed point length"));
    }

    let mut encoded = bytes.to_vec();
    let ark_flag = match encoded[0] & GNARK_MASK {
        GNARK_POSITIVE => ARK_POSITIVE,
        GNARK_NEGATIVE => ARK_NEGATIVE,
        GNARK_INFINITY => ARK_INFINITY,
        _ => return Err(ark_error("invalid gnark point flag")),
    };
    encoded[0] = encoded[0] & !GNARK_MASK | ark_flag;
    encoded.reverse();
    Ok(encoded)
}

fn compressed_g1(bytes: &[u8; 32]) -> Result<G1Affine> {
    G1Affine::deserialize_with_mode(
        gnark_compressed_to_ark(bytes)?.as_slice(),
        Compress::Yes,
        Validate::Yes,
    )
    .map_err(|error| ark_error(error.to_string()))
}

fn compressed_g2(bytes: &[u8; 64]) -> Result<G2Affine> {
    G2Affine::deserialize_with_mode(
        gnark_compressed_to_ark(bytes)?.as_slice(),
        Compress::Yes,
        Validate::Yes,
    )
    .map_err(|error| ark_error(error.to_string()))
}

fn uncompressed_g1(bytes: &[u8; 64]) -> Result<G1Affine> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(G1Affine::zero());
    }

    let mut encoded = Vec::with_capacity(65);
    encoded.extend(bytes[..32].iter().rev());
    encoded.extend(bytes[32..].iter().rev());
    encoded.push(0);
    G1Affine::deserialize_with_mode(encoded.as_slice(), Compress::No, Validate::Yes)
        .map_err(|error| ark_error(error.to_string()))
}

fn uncompressed_g2(bytes: &[u8; 128]) -> Result<G2Affine> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Ok(G2Affine::zero());
    }

    let mut encoded = Vec::with_capacity(129);
    encoded.extend(bytes[..64].iter().rev());
    encoded.extend(bytes[64..].iter().rev());
    encoded.push(0);
    G2Affine::deserialize_with_mode(encoded.as_slice(), Compress::No, Validate::Yes)
        .map_err(|error| ark_error(error.to_string()))
}

fn take<'a>(buffer: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| ark_error("point-data length overflow"))?;
    let value = buffer
        .get(*offset..end)
        .ok_or_else(|| ark_error("truncated point data"))?;
    *offset = end;
    Ok(value)
}

fn read_u32(buffer: &[u8], offset: &mut usize) -> Result<usize> {
    let bytes: [u8; 4] = take(buffer, offset, 4)?
        .try_into()
        .map_err(|_| ark_error("invalid u32 encoding"))?;
    Ok(u32::from_be_bytes(bytes) as usize)
}

pub(crate) fn load_ark_proof_from_bytes(buffer: &[u8]) -> Result<Proof<Bn254>> {
    if buffer.len() != GROTH16_PROOF_BYTES {
        return Err(ark_error("invalid Groth16 proof length"));
    }

    Ok(Proof {
        a: uncompressed_g1(buffer[..64].try_into().unwrap())?,
        b: uncompressed_g2(buffer[64..192].try_into().unwrap())?,
        c: uncompressed_g1(buffer[192..].try_into().unwrap())?,
    })
}

pub(crate) fn load_ark_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<VerifyingKey<Bn254>> {
    if buffer.len() < 292 {
        return Err(ark_error("invalid Groth16 verification-key length"));
    }

    let alpha_g1 = compressed_g1(buffer[..32].try_into().unwrap())?;
    let beta_g2 = compressed_g2(buffer[64..128].try_into().unwrap())?;
    let gamma_g2 = compressed_g2(buffer[128..192].try_into().unwrap())?;
    let delta_g2 = compressed_g2(buffer[224..288].try_into().unwrap())?;

    let mut offset = 288;
    let ic_len = read_u32(buffer, &mut offset)?;
    let mut gamma_abc_g1 = Vec::new();
    for _ in 0..ic_len {
        let point: &[u8; 32] = take(buffer, &mut offset, 32)?
            .try_into()
            .map_err(|_| ark_error("invalid IC point length"))?;
        gamma_abc_g1.push(compressed_g1(point)?);
    }

    let commitment_arrays = read_u32(buffer, &mut offset)?;
    for _ in 0..commitment_arrays {
        let indexes = read_u32(buffer, &mut offset)?;
        let byte_len = indexes
            .checked_mul(4)
            .ok_or_else(|| ark_error("commitment-index length overflow"))?;
        take(buffer, &mut offset, byte_len)?;
    }

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

pub fn load_sp1_proof(path: impl AsRef<Path>) -> Result<SP1ProofWithPublicValues> {
    let bytes = fs::read(path)?;
    match bincode::deserialize(&bytes) {
        Ok(proof) => Ok(proof),
        Err(error) => bincode::deserialize::<ProofFromNetwork>(&bytes)
            .map(Into::into)
            .map_err(|_| Sp1ToSnarkjsError::Sp1(error.to_string())),
    }
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

#[cfg(test)]
mod ark_tests {
    use ark_ec::AffineRepr;

    use super::{load_ark_groth16_verifying_key_from_bytes, load_ark_proof_from_bytes};

    #[test]
    fn decodes_bundled_groth16_verifying_key() {
        let vk =
            load_ark_groth16_verifying_key_from_bytes(*sp1_verifier::GROTH16_VK_BYTES).unwrap();

        assert_eq!(vk.gamma_abc_g1.len(), 6);
    }

    #[test]
    fn decodes_zero_gnark_proof_shape() {
        let proof = load_ark_proof_from_bytes(&[0; 256]).unwrap();

        assert!(proof.a.is_zero());
        assert!(proof.b.is_zero());
        assert!(proof.c.is_zero());
    }
}
