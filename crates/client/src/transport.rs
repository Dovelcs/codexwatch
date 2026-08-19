use anyhow::Result;
use codexwatch_protocol::{
    ClientCommand, CommandPollResponse, ContentObjectManifest, ContentUploadChunk,
    ContentUploadResult, IngestAck,
};
use reqwest::{Client, StatusCode};
use uuid::Uuid;

use crate::config::ClientConfig;

#[derive(Debug, Clone)]
pub struct ServerApi {
    client: Client,
    base_url: String,
    api_token: String,
}

impl ServerApi {
    pub fn new(config: &ClientConfig) -> Result<Self> {
        Ok(Self {
            client: Client::builder().build()?,
            base_url: config.server_url.trim_end_matches('/').to_string(),
            api_token: config.api_token.clone(),
        })
    }

    pub async fn post_ingest(
        &self,
        payload_sha256: &str,
        body: Vec<u8>,
    ) -> Result<Option<IngestAck>> {
        let response = self
            .client
            .post(format!("{}/api/v1/ingest", self.base_url))
            .bearer_auth(&self.api_token)
            .header("content-type", "application/cbor")
            .header("content-encoding", "zstd")
            .header("x-payload-sha256", payload_sha256)
            .body(body)
            .send()
            .await?;
        match response.status() {
            StatusCode::NO_CONTENT => Ok(None),
            _ => {
                response.error_for_status_ref()?;
                Ok(Some(response.json().await?))
            }
        }
    }

    pub async fn poll_commands(&self, wait_seconds: u32) -> Result<CommandPollResponse> {
        let response = self
            .client
            .get(format!(
                "{}/api/v1/client/commands/next?wait={wait_seconds}",
                self.base_url
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        match response.status() {
            StatusCode::NO_CONTENT => Ok(CommandPollResponse {
                server_time_ms: 0,
                commands: Vec::<ClientCommand>::new(),
            }),
            _ => {
                response.error_for_status_ref()?;
                Ok(response.json().await?)
            }
        }
    }

    pub async fn post_manifests(
        &self,
        command_id: Uuid,
        manifests: &[ContentObjectManifest],
    ) -> Result<()> {
        self.client
            .post(format!(
                "{}/api/v1/client/commands/{command_id}/content/manifests",
                self.base_url
            ))
            .bearer_auth(&self.api_token)
            .json(manifests)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn post_chunk(&self, command_id: Uuid, chunk: &ContentUploadChunk) -> Result<()> {
        self.client
            .post(format!(
                "{}/api/v1/client/commands/{command_id}/content/chunks",
                self.base_url
            ))
            .bearer_auth(&self.api_token)
            .json(chunk)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn post_upload_result(
        &self,
        command_id: Uuid,
        result: &ContentUploadResult,
    ) -> Result<()> {
        self.client
            .post(format!(
                "{}/api/v1/client/commands/{command_id}/result",
                self.base_url
            ))
            .bearer_auth(&self.api_token)
            .json(result)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
