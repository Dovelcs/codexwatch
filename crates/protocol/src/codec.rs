use std::io::{Cursor, Read};

use ciborium::{de::from_reader, ser::into_writer};

use crate::{IngestBatch, Validate, ValidationError};

pub const MAX_DECOMPRESSED_BATCH_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedBatch {
    pub batch_id: uuid::Uuid,
    pub payload_sha256: String,
    pub uncompressed_len: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBatch {
    pub batch: IngestBatch,
    pub payload_sha256: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("invalid batch: {0}")]
    InvalidBatch(#[from] ValidationError),
    #[error("failed to encode CBOR payload: {0}")]
    Encode(#[source] ciborium::ser::Error<std::io::Error>),
    #[error("failed to decode CBOR payload: {0}")]
    Decode(#[source] ciborium::de::Error<std::io::Error>),
    #[error("failed to compress payload: {0}")]
    Compress(#[source] std::io::Error),
    #[error("failed to decompress payload: {0}")]
    Decompress(#[source] std::io::Error),
    #[error("decompressed payload exceeded {MAX_DECOMPRESSED_BATCH_BYTES} bytes")]
    PayloadTooLarge,
    #[error("CBOR payload contained trailing bytes")]
    TrailingData,
}

#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(bytes);
    let mut output = [0_u8; 32];
    output.copy_from_slice(digest.as_slice());
    output
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256_bytes(bytes))
}

/// Encodes, validates, and zstd-compresses an ingest batch.
///
/// # Errors
///
/// Returns an error for an invalid batch, an oversized CBOR payload, or a
/// serialization/compression failure.
pub fn encode_batch(batch: &IngestBatch) -> Result<EncodedBatch, CodecError> {
    batch.validate()?;
    let mut payload = Vec::new();
    into_writer(batch, &mut payload).map_err(CodecError::Encode)?;
    if payload.len() > MAX_DECOMPRESSED_BATCH_BYTES {
        return Err(CodecError::PayloadTooLarge);
    }
    let payload_sha256 = sha256_hex(&payload);
    let bytes = zstd::stream::encode_all(Cursor::new(&payload), 9).map_err(CodecError::Compress)?;
    Ok(EncodedBatch {
        batch_id: batch.batch_id,
        payload_sha256,
        uncompressed_len: payload.len(),
        bytes,
    })
}

/// Decodes and validates a zstd-compressed ingest batch.
///
/// # Errors
///
/// Returns an error for invalid compression, oversized or malformed CBOR, or
/// a batch that violates the wire contract.
pub fn decode_batch(bytes: &[u8]) -> Result<IngestBatch, CodecError> {
    decode_batch_with_payload(bytes).map(|decoded| decoded.batch)
}

/// Decodes a batch while retaining the bounded uncompressed CBOR and digest.
///
/// # Errors
///
/// Returns the same errors as [`decode_batch`].
pub fn decode_batch_with_payload(bytes: &[u8]) -> Result<DecodedBatch, CodecError> {
    let decoder = zstd::stream::Decoder::new(Cursor::new(bytes)).map_err(CodecError::Decompress)?;
    let mut limited = decoder.take((MAX_DECOMPRESSED_BATCH_BYTES + 1) as u64);
    let mut payload = Vec::new();
    limited
        .read_to_end(&mut payload)
        .map_err(CodecError::Decompress)?;
    if payload.len() > MAX_DECOMPRESSED_BATCH_BYTES {
        return Err(CodecError::PayloadTooLarge);
    }

    let payload_sha256 = sha256_hex(&payload);
    let mut cursor = Cursor::new(&payload);
    let batch: IngestBatch = from_reader(&mut cursor).map_err(CodecError::Decode)?;
    if cursor.position() != payload.len() as u64 {
        return Err(CodecError::TrailingData);
    }
    batch.validate()?;
    Ok(DecodedBatch {
        batch,
        payload_sha256,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use crate::{ClientInstance, IngestBatch};

    use super::{
        CodecError, MAX_DECOMPRESSED_BATCH_BYTES, decode_batch_with_payload, encode_batch,
    };

    #[test]
    fn round_trip_batch_codec() {
        let batch = IngestBatch {
            version: 1,
            batch_id: uuid::Uuid::now_v7(),
            generated_at_ms: 1_725_234_567_890,
            client: ClientInstance {
                client_id: "client-a".to_owned(),
                instance_id: uuid::Uuid::now_v7(),
                hostname: "host".to_owned(),
                platform: "linux-x86_64".to_owned(),
                codex_version: "0.148.0".to_owned(),
                started_at_ms: 1_725_234_560_000,
            },
            tasks: Vec::new(),
            heartbeats: Vec::new(),
        };

        let encoded = encode_batch(&batch).expect("encode");
        assert!(encoded.uncompressed_len < MAX_DECOMPRESSED_BATCH_BYTES);
        let decoded = decode_batch_with_payload(&encoded.bytes).expect("decode");
        assert_eq!(decoded.batch, batch);
        assert_eq!(decoded.payload_sha256, encoded.payload_sha256);
    }

    #[test]
    fn decode_rejects_payload_over_decompressed_limit() {
        let expanded = vec![0_u8; MAX_DECOMPRESSED_BATCH_BYTES + 1];
        let compressed = zstd::stream::encode_all(expanded.as_slice(), 1).expect("compress");
        assert!(matches!(
            decode_batch_with_payload(&compressed),
            Err(CodecError::PayloadTooLarge)
        ));
    }

    #[test]
    fn codec_rejects_wrong_protocol_version() {
        let batch = IngestBatch {
            version: 2,
            batch_id: uuid::Uuid::now_v7(),
            generated_at_ms: 1,
            client: ClientInstance {
                client_id: "client-a".to_owned(),
                instance_id: uuid::Uuid::now_v7(),
                hostname: "host".to_owned(),
                platform: "linux-x86_64".to_owned(),
                codex_version: "0.148.0".to_owned(),
                started_at_ms: 1,
            },
            tasks: Vec::new(),
            heartbeats: Vec::new(),
        };
        assert!(matches!(
            encode_batch(&batch),
            Err(CodecError::InvalidBatch(_))
        ));
    }
}
