use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Proof, VerifyingKey};
use serde::{Deserialize, Serialize};

/// snarkjs Groth16 `proof.json` for BN254/bn128.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkJsProof {
    pub pi_a: [String; 3],
    pub pi_b: [[String; 2]; 3],
    pub pi_c: [String; 3],
    pub protocol: String,
    pub curve: String,
}

/// snarkjs Groth16 `verification_key.json` for BN254/bn128.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkJsVerificationKey {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    pub vk_alpha_1: [String; 3],
    pub vk_beta_2: [[String; 2]; 3],
    pub vk_gamma_2: [[String; 2]; 3],
    pub vk_delta_2: [[String; 2]; 3],
    #[serde(rename = "IC")]
    pub ic: Vec<[String; 3]>,
}

pub fn field_to_decimal<F: PrimeField>(value: &F) -> String {
    value.into_bigint().to_string()
}

fn fq_to_decimal(value: &Fq) -> String {
    field_to_decimal(value)
}

fn fq2_to_decimal_pair(value: &Fq2) -> [String; 2] {
    // snarkjs/ffjavascript represents Fq2 as [c0, c1].
    [fq_to_decimal(&value.c0), fq_to_decimal(&value.c1)]
}

pub fn g1_to_snarkjs(point: &G1Affine) -> [String; 3] {
    if point.is_zero() {
        return ["0".to_owned(), "1".to_owned(), "0".to_owned()];
    }
    [
        fq_to_decimal(&point.x),
        fq_to_decimal(&point.y),
        "1".to_owned(),
    ]
}

pub fn g2_to_snarkjs(point: &G2Affine) -> [[String; 2]; 3] {
    if point.is_zero() {
        return [
            ["0".to_owned(), "0".to_owned()],
            ["1".to_owned(), "0".to_owned()],
            ["0".to_owned(), "0".to_owned()],
        ];
    }
    [
        fq2_to_decimal_pair(&point.x),
        fq2_to_decimal_pair(&point.y),
        ["1".to_owned(), "0".to_owned()],
    ]
}

impl From<&Proof<ark_bn254::Bn254>> for SnarkJsProof {
    fn from(proof: &Proof<ark_bn254::Bn254>) -> Self {
        Self {
            pi_a: g1_to_snarkjs(&proof.a),
            pi_b: g2_to_snarkjs(&proof.b),
            pi_c: g1_to_snarkjs(&proof.c),
            protocol: "groth16".to_owned(),
            curve: "bn128".to_owned(),
        }
    }
}

impl SnarkJsVerificationKey {
    pub fn from_ark_vk(vk: &VerifyingKey<ark_bn254::Bn254>, public_inputs_len: usize) -> Self {
        Self {
            protocol: "groth16".to_owned(),
            curve: "bn128".to_owned(),
            n_public: public_inputs_len,
            vk_alpha_1: g1_to_snarkjs(&vk.alpha_g1),
            vk_beta_2: g2_to_snarkjs(&vk.beta_g2),
            vk_gamma_2: g2_to_snarkjs(&vk.gamma_g2),
            vk_delta_2: g2_to_snarkjs(&vk.delta_g2),
            ic: vk.gamma_abc_g1.iter().map(g1_to_snarkjs).collect(),
        }
    }
}
