use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use sp1_sdk::{ProofFromNetwork, SP1Proof, SP1ProofWithPublicValues, SP1PublicValues};
use sp1_to_snarkjs::{
    error::Sp1ToSnarkjsError,
    sp1::{load_sp1_proof, sp1_groth16_proof_bytes, sp1_groth16_public_inputs},
};
use sp1_verifier::Groth16Bn254Proof;

const INPUTS: [&str; 5] = ["1", "2", "3", "4", "5"];

fn encoded_proof() -> String {
    let mut bytes = Vec::with_capacity(352);
    for value in [3u8, 4, 5] {
        bytes.extend_from_slice(&[0u8; 31]);
        bytes.push(value);
    }
    bytes.extend_from_slice(&[0xabu8; 256]);
    hex::encode(bytes)
}

fn proof(encoded_proof: String) -> SP1ProofWithPublicValues {
    SP1ProofWithPublicValues::new(
        SP1Proof::Groth16(Groth16Bn254Proof {
            public_inputs: INPUTS.map(str::to_owned),
            encoded_proof,
            ..Default::default()
        }),
        SP1PublicValues::new(),
        "v6.1.0".to_owned(),
    )
}

#[test]
fn exposes_all_five_sp1_public_inputs() {
    let actual = sp1_groth16_public_inputs(&proof(encoded_proof())).unwrap();
    let expected = INPUTS.map(str::to_owned).to_vec();

    assert_eq!(actual, expected);
}

#[test]
fn extracts_only_the_256_byte_groth16_proof() {
    let actual = sp1_groth16_proof_bytes(&proof(encoded_proof())).unwrap();

    assert_eq!(actual, vec![0xabu8; 256]);
}

#[test]
fn rejects_empty_mock_groth16_proof() {
    let error = sp1_groth16_proof_bytes(&proof(String::new())).unwrap_err();

    assert!(matches!(error, Sp1ToSnarkjsError::MockProof));
}

#[test]
fn rejects_unsupported_sp1_version() {
    let mut candidate = proof(encoded_proof());
    candidate.sp1_version = "6.3.1".to_owned();

    let error = sp1_groth16_proof_bytes(&candidate).unwrap_err();

    assert!(matches!(
        error,
        Sp1ToSnarkjsError::UnsupportedSp1Version { actual }
            if actual == "6.3.1"
    ));
}

#[test]
fn rejects_tee_prefixed_proof() {
    let mut candidate = proof(encoded_proof());
    candidate.tee_proof = Some(vec![1, 2, 3]);

    let error = sp1_groth16_proof_bytes(&candidate).unwrap_err();

    assert!(matches!(error, Sp1ToSnarkjsError::TeeProofUnsupported));
}

#[test]
fn rejects_non_hex_encoded_proof_at_the_expected_length() {
    let error = sp1_groth16_proof_bytes(&proof("g".repeat(704))).unwrap_err();

    assert!(matches!(error, Sp1ToSnarkjsError::Hex(_)));
}

#[test]
fn rejects_wrong_encoded_proof_length() {
    let error = sp1_groth16_proof_bytes(&proof(hex::encode([0u8; 351]))).unwrap_err();

    assert!(matches!(
        error,
        Sp1ToSnarkjsError::InvalidEncodedProofLength {
            actual: 702,
            expected: 704
        }
    ));
}

#[test]
fn loads_legacy_network_proof_with_trailing_data() {
    let legacy = ProofFromNetwork {
        proof: proof(encoded_proof()).proof,
        public_values: SP1PublicValues::new(),
        sp1_version: "v6.1.0".to_owned(),
    };
    let mut bytes = bincode::serialize(&legacy).unwrap();
    bytes.extend_from_slice(b"trailing data");
    let path = temporary_proof_path();
    fs::write(&path, bytes).unwrap();

    let loaded = load_sp1_proof(&path).unwrap();
    fs::remove_file(path).unwrap();

    assert!(loaded.tee_proof.is_none());
    assert_eq!(loaded.sp1_version, "v6.1.0");
}

#[test]
fn loads_current_proof_with_trailing_data() {
    let mut bytes = bincode::serialize(&proof(encoded_proof())).unwrap();
    bytes.extend_from_slice(b"trailing data");
    let path = temporary_proof_path();
    fs::write(&path, bytes).unwrap();

    let loaded = load_sp1_proof(&path).unwrap();
    fs::remove_file(path).unwrap();

    assert!(loaded.tee_proof.is_none());
    assert_eq!(loaded.sp1_version, "v6.1.0");
}

#[test]
fn rejects_proof_file_larger_than_16_mib() {
    let mut bytes = bincode::serialize(&proof(encoded_proof())).unwrap();
    bytes.resize(16 * 1024 * 1024 + 1, 0);

    let path = temporary_proof_path();
    fs::write(&path, bytes).unwrap();

    let error = load_sp1_proof(&path).unwrap_err();
    fs::remove_file(path).unwrap();

    assert!(matches!(error, Sp1ToSnarkjsError::Sp1(_)));
}

#[test]
fn rejects_declared_string_length_above_limit() {
    let encoded = encoded_proof();
    let mut bytes = bincode::serialize(&proof(encoded.clone())).unwrap();
    let string_offset = bytes
        .windows(encoded.len())
        .position(|window| window == encoded.as_bytes())
        .unwrap();
    bytes[string_offset - 8..string_offset]
        .copy_from_slice(&(16u64 * 1024 * 1024 + 1).to_le_bytes());
    bytes.truncate(string_offset);
    assert!(bytes.len() < 1024);

    let path = temporary_proof_path();
    fs::write(&path, bytes).unwrap();

    let error = load_sp1_proof(&path).unwrap_err();
    fs::remove_file(path).unwrap();

    assert!(matches!(error, Sp1ToSnarkjsError::Sp1(_)));
}

fn temporary_proof_path() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sp1-to-snarkjs-{}-{nanos}.bin", std::process::id()))
}

#[test]
fn rejects_encoded_metadata_that_disagrees_with_public_inputs() {
    let mut encoded = encoded_proof();
    encoded.replace_range(0..2, "ff");

    let error = sp1_groth16_proof_bytes(&proof(encoded)).unwrap_err();

    assert!(matches!(error, Sp1ToSnarkjsError::EncodedMetadataMismatch));
}
