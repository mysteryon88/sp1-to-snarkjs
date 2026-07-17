use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str::FromStr;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_snark::SNARK;
use serde::{Deserialize, Serialize};
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_verifier::{load_ark_groth16_verifying_key_from_bytes, load_ark_proof_from_bytes};

use crate::error::{Result, Sp1ToSnarkjsError};
use crate::snarkjs::{SnarkJsProof, SnarkJsVerificationKey};
use crate::sp1::{load_sp1_proof, sp1_groth16_proof_bytes, sp1_groth16_public_inputs};

fn fr_from_decimal(value: &str) -> Result<Fr> {
    Fr::from_str(value).map_err(|_| Sp1ToSnarkjsError::InvalidDecimal(value.to_owned()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedArtifacts {
    pub proof: SnarkJsProof,
    pub public_inputs: Vec<String>,
    pub verification_key: SnarkJsVerificationKey,
}

pub fn convert_sp1_proof_file(proof_path: impl AsRef<Path>) -> Result<ExportedArtifacts> {
    let proof = load_sp1_proof(proof_path)?;
    convert_sp1_proof(&proof)
}

pub fn convert_sp1_proof(sp1_proof: &SP1ProofWithPublicValues) -> Result<ExportedArtifacts> {
    let public_inputs = sp1_groth16_public_inputs(sp1_proof)?;
    let ark_public_inputs = public_inputs
        .iter()
        .map(|s| fr_from_decimal(s))
        .collect::<Result<Vec<_>>>()?;

    let proof_bytes = sp1_groth16_proof_bytes(sp1_proof)?;
    let ark_proof = load_ark_proof_from_bytes(&proof_bytes)
        .map_err(|err| Sp1ToSnarkjsError::ArkConversion(err.to_string()))?;

    let ark_vk = load_ark_groth16_verifying_key_from_bytes(*sp1_verifier::GROTH16_VK_BYTES)
        .map_err(|err| Sp1ToSnarkjsError::ArkConversion(err.to_string()))?;

    let expected_ic_len = public_inputs.len() + 1;
    if ark_vk.gamma_abc_g1.len() != expected_ic_len {
        return Err(Sp1ToSnarkjsError::IcLengthMismatch {
            ic_len: ark_vk.gamma_abc_g1.len(),
            public_len: public_inputs.len(),
        });
    }

    let pvk = prepare_verifying_key(&ark_vk);
    let ok = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &ark_public_inputs, &ark_proof)
        .map_err(|_| Sp1ToSnarkjsError::ArkVerificationFailed)?;
    if !ok {
        return Err(Sp1ToSnarkjsError::ArkVerificationFailed);
    }

    Ok(ExportedArtifacts {
        proof: SnarkJsProof::from(&ark_proof),
        public_inputs,
        verification_key: SnarkJsVerificationKey::from_ark_vk(&ark_vk, ark_public_inputs.len()),
    })
}

pub fn write_artifacts(artifacts: &ExportedArtifacts, out_dir: impl AsRef<Path>) -> Result<()> {
    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)?;

    write_pretty(out_dir.join("proof.json"), &artifacts.proof)?;
    write_pretty(out_dir.join("public.json"), &artifacts.public_inputs)?;
    write_pretty(
        out_dir.join("verification_key.json"),
        &artifacts.verification_key,
    )?;
    Ok(())
}

fn write_pretty(path: PathBuf, value: &impl Serialize) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub fn run_snarkjs_verify(out_dir: impl AsRef<Path>) -> anyhow::Result<()> {
    let out = out_dir.as_ref();
    let status = Command::new("snarkjs")
        .arg("groth16")
        .arg("verify")
        .arg(out.join("verification_key.json"))
        .arg(out.join("public.json"))
        .arg(out.join("proof.json"))
        .status()?;

    if !status.success() {
        anyhow::bail!("snarkjs groth16 verify failed with status {status}");
    }
    Ok(())
}
