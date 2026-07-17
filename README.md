# sp1-to-snarkjs

`sp1-to-snarkjs` converts an existing SP1 Groth16 `proof.bin` into snarkjs-compatible JSON:

- `proof.json`
- `public.json`
- `verification_key.json`

This repository does not generate SP1 proofs. Proof generation and native SP1 verification belong in an SP1 examples checkout. Native SP1 verification validates the SP1 artifact through the SP1 SDK; snarkjs verification validates the exported Groth16 wrapper proof against its wrapper verification key and five wrapper public inputs. snarkjs verification is not a replacement for native SP1 verification.

## Supported proof layout

The converter is built against `sp1-sdk` and `sp1-verifier` `6.3.1`. Those
crates emit and verify Groth16 artifacts whose serialized circuit metadata is
exactly `sp1_version = "v6.1.0"`; the converter rejects every other value.

The supported wrapper layout has:

- exactly five public inputs: program verification-key hash, committed public-values digest, exit code, wrapper verification-key root, and proof nonce;
- exactly 352 encoded proof bytes: 96 bytes of SP1 wrapper metadata followed by a 256-byte Groth16 proof.

The wrapper verification key comes from the linked `sp1-verifier` `6.3.1`
crate. Every conversion is verified with Arkworks before JSON is written.

## Build and test on Linux

```bash
cargo build --locked
cargo test --locked
```

Install `snarkjs` if you want external verification:

```bash
npm install --global snarkjs@0.7.6
```

## Submodule import workflow

Initialize the examples submodule after cloning this repository:

```bash
git submodule update --init
```

The `scripts/import-examples.sh` helper is available only in this repository
checkout; it is not included in the packaged crate. It reads these proofs
directly from the submodule:

```text
sp1-examples/artifacts/arithmetic/proof.bin
sp1-examples/artifacts/fibonacci/proof.bin
sp1-examples/artifacts/sha256/proof.bin
```

Run:

```bash
./scripts/import-examples.sh
```

Converted JSON is written to and published from:

```text
artifacts/<case>/snarkjs/proof.json
artifacts/<case>/snarkjs/public.json
artifacts/<case>/snarkjs/verification_key.json
```

The import script verifies each exported wrapper proof with snarkjs and requires snarkjs to reject a mutated arithmetic public input.
It does not copy the source `proof.bin` files into this repository. An alternate
examples checkout can still be supplied as `./scripts/import-examples.sh <path>`.

## Packaged CLI workflow

```bash
sp1-to-snarkjs \
  --proof sp1-examples/artifacts/arithmetic/proof.bin \
  --out artifacts/arithmetic/snarkjs \
  --snarkjs-verify
```

Library usage is shown in `examples/library_usage.rs`.

## Publishing

```bash
cargo package --locked
cargo publish --dry-run --locked
```
