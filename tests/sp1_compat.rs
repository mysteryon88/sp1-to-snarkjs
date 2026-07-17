use sp1_primitives::io::SP1PublicValues;
use sp1_to_snarkjs::{
    error::Sp1ToSnarkjsError,
    sp1::{sp1_groth16_proof_bytes, sp1_groth16_public_inputs, SP1ProofWithPublicValues},
};
use sp1_verifier::{Groth16Bn254Proof, SP1Proof};

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
    SP1ProofWithPublicValues {
        proof: SP1Proof::Groth16(Groth16Bn254Proof {
            public_inputs: INPUTS.map(str::to_owned),
            encoded_proof,
            ..Default::default()
        }),
        public_values: SP1PublicValues::new(),
        sp1_version: "v6.1.0".to_owned(),
        tee_proof: None,
    }
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
fn rejects_non_hex_encoded_proof() {
    let error = sp1_groth16_proof_bytes(&proof("not-hex".to_owned())).unwrap_err();

    assert!(matches!(error, Sp1ToSnarkjsError::Hex(_)));
}

#[test]
fn rejects_wrong_encoded_proof_length() {
    let error = sp1_groth16_proof_bytes(&proof(hex::encode([0u8; 351]))).unwrap_err();

    assert!(matches!(
        error,
        Sp1ToSnarkjsError::InvalidEncodedProofLength {
            actual: 351,
            expected: 352
        }
    ));
}

#[test]
fn rejects_encoded_metadata_that_disagrees_with_public_inputs() {
    let mut encoded = encoded_proof();
    encoded.replace_range(0..2, "ff");

    let error = sp1_groth16_proof_bytes(&proof(encoded)).unwrap_err();

    assert!(matches!(error, Sp1ToSnarkjsError::EncodedMetadataMismatch));
}
