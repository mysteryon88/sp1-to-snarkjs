use sp1_to_snarkjs::{convert_sp1_proof_file, write_artifacts};

fn main() -> anyhow::Result<()> {
    let artifacts = convert_sp1_proof_file("proof.bin")?;
    write_artifacts(&artifacts, "snarkjs")?;
    Ok(())
}
