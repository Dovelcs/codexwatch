use std::{
    collections::BTreeMap,
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use codexwatch_protocol::{
    ContentObjectManifest, ContentPart, ContentUploadChunk, MAX_CONTENT_CHUNK_BYTES, sha256_hex,
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::model::TaskKey;

pub const RETENTION_HOURS: i64 = 72;

#[derive(Debug, Clone)]
pub struct StoredContentInput {
    pub task: TaskKey,
    pub part: ContentPart,
    pub media_type: String,
    pub body: Vec<u8>,
    pub headers: BTreeMap<String, String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SanitizedHeaders(pub BTreeMap<String, String>);

#[derive(Debug, Clone)]
pub struct StoredBlob {
    pub task: TaskKey,
    pub part: ContentPart,
    pub object_sha256: String,
    pub media_type: String,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: Vec<u8>,
    pub chunk_count: u32,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub sanitized_headers: SanitizedHeaders,
}

impl StoredBlob {
    #[must_use]
    pub fn manifest(&self, request_id: Uuid) -> ContentObjectManifest {
        ContentObjectManifest {
            request_id,
            task_ref: self.task.task_ref(),
            session_id: self.task.session_id.clone(),
            thread_id: self.task.thread_id.clone(),
            part: self.part,
            object_sha256: self.object_sha256.clone(),
            media_type: self.media_type.clone(),
            uncompressed_bytes: self.uncompressed_bytes,
            compressed_bytes: self.compressed_bytes.len() as u64,
            chunk_count: self.chunk_count,
            created_at_ms: self.created_at.unix_timestamp() * 1000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn store(&self, input: &StoredContentInput) -> Result<StoredBlob> {
        if input.media_type.trim().is_empty() {
            bail!("content media_type must not be empty");
        }
        let object_sha256 = sha256_hex(&input.body);
        let compressed_bytes = zstd::stream::encode_all(Cursor::new(&input.body), 3)?;
        let path = self.object_path(&object_sha256);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp_path = path.with_extension("tmp");
            std::fs::write(&tmp_path, &compressed_bytes)
                .with_context(|| format!("write blob {tmp_path:?}"))?;
            std::fs::rename(&tmp_path, &path).with_context(|| format!("rename blob {path:?}"))?;
        }

        Ok(StoredBlob {
            task: input.task.clone(),
            part: input.part,
            object_sha256,
            media_type: input.media_type.clone(),
            uncompressed_bytes: input.body.len() as u64,
            compressed_bytes,
            chunk_count: chunk_count(input.body.len()),
            created_at: input.created_at,
            expires_at: input.created_at + Duration::hours(RETENTION_HOURS),
            sanitized_headers: SanitizedHeaders(sanitize_headers(&input.headers)),
        })
    }

    pub fn load_chunks(
        &self,
        object_sha256: &str,
        request_id: Uuid,
    ) -> Result<Vec<ContentUploadChunk>> {
        let bytes = std::fs::read(self.object_path(object_sha256))
            .with_context(|| format!("read object {object_sha256}"))?;
        let chunk_count = chunk_count(bytes.len());
        let mut chunks = Vec::with_capacity(chunk_count as usize);
        for (chunk_index, payload_zstd) in bytes.chunks(MAX_CONTENT_CHUNK_BYTES).enumerate() {
            chunks.push(ContentUploadChunk {
                request_id,
                chunk_index: chunk_index as u32,
                chunk_count,
                object_sha256: object_sha256.to_string(),
                payload_sha256: sha256_hex(payload_zstd),
                payload_zstd: payload_zstd.to_vec(),
                is_last: chunk_index as u32 + 1 == chunk_count,
            });
        }
        Ok(chunks)
    }

    pub fn remove(&self, object_sha256: &str) -> Result<()> {
        let path = self.object_path(object_sha256);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    #[must_use]
    pub fn object_path(&self, object_sha256: &str) -> PathBuf {
        let prefix = &object_sha256[..2.min(object_sha256.len())];
        self.root.join(prefix).join(format!("{object_sha256}.zst"))
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[must_use]
pub fn sanitize_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(key, value)| {
            let lower = key.to_ascii_lowercase();
            let sensitive = matches!(
                lower.as_str(),
                "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
            ) || lower.contains("api-key");
            (!sensitive).then(|| (key.clone(), value.clone()))
        })
        .collect()
}

#[must_use]
pub fn chunk_count(compressed_bytes: usize) -> u32 {
    let chunks = compressed_bytes.div_ceil(MAX_CONTENT_CHUNK_BYTES);
    chunks.max(1) as u32
}
