use thiserror::Error;

pub type Result<T> = std::result::Result<T, Sp1ToSnarkjsError>;

#[derive(Debug, Error)]
pub enum Sp1ToSnarkjsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("SP1 artifact error: {0}")]
    Sp1(String),

    #[error("unsupported SP1 artifact version `{actual}`; expected `v6.1.0`")]
    UnsupportedSp1Version { actual: String },

    #[error("input proof is not an SP1 Groth16 proof")]
    NotGroth16,

    #[error("mock Groth16 proofs cannot be converted")]
    MockProof,

    #[error("TEE-prefixed SP1 proofs are not supported")]
    TeeProofUnsupported,

    #[error("invalid decimal field element `{0}`")]
    InvalidDecimal(String),

    #[error("invalid SP1 Groth16 encoded_proof length: {actual}; expected {expected} bytes")]
    InvalidEncodedProofLength { actual: usize, expected: usize },

    #[error("SP1 encoded_proof metadata does not match public inputs 2 through 4")]
    EncodedMetadataMismatch,

    #[error("SP1 Arkworks conversion failed: {0}")]
    ArkConversion(String),

    #[error("verification key IC length mismatch: vk has {ic_len} IC points, but proof has {public_len} public inputs; expected IC = public + 1")]
    IcLengthMismatch { ic_len: usize, public_len: usize },

    #[error("Arkworks verification failed")]
    ArkVerificationFailed,
}
