//! Shared `CodexWatch` wire contract and task state semantics.

mod codec;
mod state;
mod types;
mod validation;

pub use codec::{
    CodecError, DecodedBatch, EncodedBatch, MAX_DECOMPRESSED_BATCH_BYTES, decode_batch,
    decode_batch_with_payload, encode_batch, sha256_bytes, sha256_hex,
};
pub use state::{ReduceError, ReduceOutcome, TaskReducer};
pub use types::*;
pub use validation::{Validate, ValidationError, is_uuid_v7};
