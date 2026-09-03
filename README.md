# SP1 to snarkjs

[![dependency status](https://deps.rs/repo/github/mysteryon88/sp1-to-snarkjs/status.svg)](https://deps.rs/repo/github/mysteryon88/sp1-to-snarkjs)

Utilities for converting existing [SP1](https://github.com/succinctlabs/sp1)
Groth16 `proof.bin` artifacts into JSON compatible with
[snarkjs](https://github.com/iden3/snarkjs):

- `proof.json`
- `public.json`
- `verification_key.json`

Supports the SP1 6.3.1 Groth16 wrapper on BN254. The converter verifies every
proof with Arkworks before writing JSON. It does not generate SP1 proofs.

## Installation

Install the CLI from GitHub:

```bash
cargo install --git https://github.com/mysteryon88/sp1-to-snarkjs
```

Or add the library to a Rust project:

```bash
cargo add --git https://github.com/mysteryon88/sp1-to-snarkjs
```

## Convert for snarkjs

```bash
sp1-to-snarkjs \
  --proof proof.bin \
  --out snarkjs \
  --snarkjs-verify
```

The command writes:

```text
snarkjs/proof.json
snarkjs/public.json
snarkjs/verification_key.json
```

`--snarkjs-verify` runs the equivalent of:

```bash
snarkjs groth16 verify \
  snarkjs/verification_key.json \
  snarkjs/public.json \
  snarkjs/proof.json
```

No separate `vk.bin` is required. The wrapper verification key bundled by
`sp1-verifier` is exported as `verification_key.json`.

## Library usage

```rust
use sp1_to_snarkjs::{convert_sp1_proof_file, write_artifacts};

fn main() -> sp1_to_snarkjs::Result<()> {
    let artifacts = convert_sp1_proof_file("proof.bin")?;
    write_artifacts(&artifacts, "snarkjs")?;
    Ok(())
}
```

## Examples

The [`sp1-examples`](https://github.com/zk-examples/sp1-examples) submodule
contains arithmetic, Fibonacci, and SHA-256 proofs:

```bash
git submodule update --init
./scripts/import-examples.sh
```

The script converts all three proofs, verifies each export with snarkjs, and
requires snarkjs to reject a mutated public input. Published outputs are under
`artifacts/<case>/snarkjs/`.

## Supported format

- SP1 Groth16
- BN254 / bn128
- Arkworks 0.6
- `sp1-sdk` and `sp1-verifier` 6.3.1
- serialized `sp1_version = "v6.1.0"`
- five wrapper public inputs
- 352 encoded proof bytes: 96 bytes of wrapper metadata and a 256-byte
  Groth16 proof

## Security

The exported `verification_key.json` is the generic SP1 Groth16 wrapper
verification key, not the verification key of the proved program. A successful
snarkjs verification only proves that this wrapper accepts the supplied public
signals; the application must check that they describe its intended statement.

For SP1 `v6.1.0`, check all five wrapper public signals against expected
values:

1. `0`: the intended program's SP1 verification-key hash;
2. `1`: the expected committed public-values digest under the supported SP1 convention;
3. `2`: the application's accepted exit code (normally zero);
4. `3`: the expected SP1 recursion verification-key root for the supported version;
5. `4`: a nonce allowed exactly once by the application's replay policy.

In particular, bind the expected program verification key, public-values
digest, exit code, root, and nonce to the application operation before
accepting a proof.

## Build and test

Run on Linux or WSL:

```bash
cargo build --locked
cargo test --locked
```

## License

MIT
