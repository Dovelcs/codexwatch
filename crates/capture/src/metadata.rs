use http::HeaderMap;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MetadataError {
    #[error("missing x-codex-turn-metadata")]
    Missing,
    #[error("invalid turn metadata json: {0}")]
    InvalidJson(String),
    #[error("missing required turn metadata field {0}")]
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedTurnMetadata {
    pub session_id: String,
    pub thread_id: String,
    pub turn_id: String,
    pub request_kind: String,
    pub parent_turn_id: Option<String>,
    pub root_turn_id: Option<String>,
}

impl DecodedTurnMetadata {
    #[must_use]
    pub fn task_ref(&self) -> String {
        format!("{}:{}:{}", self.session_id, self.thread_id, self.turn_id)
    }
}

pub fn extract_turn_metadata(
    headers: &HeaderMap,
    request_json: &Value,
) -> Result<DecodedTurnMetadata, MetadataError> {
    let header_payload = headers
        .get("x-codex-turn-metadata")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body_payload = request_json
        .get("client_metadata")
        .and_then(|value| value.get("x-codex-turn-metadata"))
        .and_then(|value| match value {
            Value::String(text) => Some(text.clone()),
            Value::Object(_) => Some(value.to_string()),
            _ => None,
        });

    let payload = header_payload
        .or(body_payload)
        .ok_or(MetadataError::Missing)?;
    let json: Value = serde_json::from_str(&payload)
        .map_err(|error| MetadataError::InvalidJson(error.to_string()))?;

    Ok(DecodedTurnMetadata {
        session_id: require_string(&json, "session_id")?,
        thread_id: require_string(&json, "thread_id")?,
        turn_id: require_string(&json, "turn_id")?,
        request_kind: require_string(&json, "request_kind")?,
        parent_turn_id: optional_string(&json, "parent_turn_id"),
        root_turn_id: optional_string(&json, "root_turn_id"),
    })
}

fn require_string(json: &Value, field: &'static str) -> Result<String, MetadataError> {
    json.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(MetadataError::MissingField(field))
}

fn optional_string(json: &Value, field: &'static str) -> Option<String> {
    json.get(field).and_then(Value::as_str).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use http::HeaderMap;
    use serde_json::json;

    use super::extract_turn_metadata;

    #[test]
    fn reads_metadata_from_header_or_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-codex-turn-metadata",
            http::HeaderValue::from_static(
                "{\"session_id\":\"s\",\"thread_id\":\"t\",\"turn_id\":\"u\",\"request_kind\":\"turn\"}",
            ),
        );
        let empty = json!({});
        assert_eq!(
            extract_turn_metadata(&headers, &empty)
                .expect("header metadata")
                .turn_id,
            "u"
        );

        let request = json!({
            "client_metadata": {
                "x-codex-turn-metadata": "{\"session_id\":\"s2\",\"thread_id\":\"t2\",\"turn_id\":\"u2\",\"request_kind\":\"turn\"}"
            }
        });
        let headers = HeaderMap::new();
        assert_eq!(
            extract_turn_metadata(&headers, &request)
                .expect("body metadata")
                .thread_id,
            "t2"
        );
    }
}
