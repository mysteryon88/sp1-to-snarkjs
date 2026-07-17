#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.cargo/bin:/snap/bin:$PATH"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/sp1-split-target}"

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [path-to-sp1-examples]" >&2
  exit 2
fi

EXAMPLES_ROOT="$(cd -- "${1:-$ROOT/sp1-examples}" && pwd)"
cd "$ROOT"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

for command_name in cargo node snarkjs; do
  require "$command_name"
done

for case_name in arithmetic fibonacci sha256; do
  source_proof="$EXAMPLES_ROOT/artifacts/$case_name/proof.bin"
  output_dir="$ROOT/artifacts/$case_name/snarkjs"

  if [[ ! -s "$source_proof" ]]; then
    echo "missing or empty proof: $source_proof" >&2
    exit 1
  fi

  cargo run --release --locked -- \
    --proof "$source_proof" \
    --out "$output_dir" \
    --snarkjs-verify

  test -s "$output_dir/proof.json"
  test -s "$output_dir/public.json"
  test -s "$output_dir/verification_key.json"
  test ! -e "$ROOT/artifacts/$case_name/proof.bin"
  echo "SNARKJS_OK $case_name"
done

negative_public="$ROOT/artifacts/arithmetic/snarkjs/public.invalid.json"
trap 'rm -f -- "$negative_public"' EXIT
node - "$ROOT/artifacts/arithmetic/snarkjs/public.json" "$negative_public" <<'NODE'
const fs = require("node:fs");

const source = process.argv[2];
const destination = process.argv[3];
const values = JSON.parse(fs.readFileSync(source, "utf8"));
values[0] = (BigInt(values[0]) + 1n).toString();
fs.writeFileSync(destination, `${JSON.stringify(values, null, 2)}\n`);
NODE

if snarkjs groth16 verify \
  "$ROOT/artifacts/arithmetic/snarkjs/verification_key.json" \
  "$negative_public" \
  "$ROOT/artifacts/arithmetic/snarkjs/proof.json"; then
  echo "snarkjs accepted a changed public input" >&2
  exit 1
fi

echo "SNARKJS_REJECTED_MUTATED_PUBLIC"
echo "ALL_IMPORTED_PROOFS_OK"
