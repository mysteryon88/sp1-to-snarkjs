use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use sp1_to_snarkjs::export::{convert_sp1_proof_file, run_snarkjs_verify, write_artifacts};

#[derive(Debug, Parser)]
#[command(name = "sp1-to-snarkjs")]
#[command(
    about = "Convert SP1 Groth16 artifacts to snarkjs proof.json/public.json/verification_key.json"
)]
struct Cli {
    /// Export snarkjs JSON files from an SP1ProofWithPublicValues .bin artifact.
    #[arg(short, long)]
    proof: PathBuf,

    /// Output directory for proof.json, public.json, verification_key.json.
    #[arg(short, long, default_value = "snarkjs")]
    out: PathBuf,

    /// After export, run external `snarkjs groth16 verify ...`.
    #[arg(long)]
    snarkjs_verify: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let artifacts = convert_sp1_proof_file(&cli.proof)
        .with_context(|| format!("converting SP1 proof {}", cli.proof.display()))?;
    write_artifacts(&artifacts, &cli.out)
        .with_context(|| format!("writing artifacts to {}", cli.out.display()))?;

    println!("wrote {}", cli.out.join("proof.json").display());
    println!("wrote {}", cli.out.join("public.json").display());
    println!("wrote {}", cli.out.join("verification_key.json").display());
    println!("nPublic = {}", artifacts.public_inputs.len());

    if cli.snarkjs_verify {
        run_snarkjs_verify(&cli.out).context("external snarkjs verification failed")?;
    }

    Ok(())
}
