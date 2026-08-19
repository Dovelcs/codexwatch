use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use codexwatch_protocol::{CodexTaskMetadata, TaskIdentity, UsageSummary};

use crate::{
    DecodedTurnMetadata, HttpParseError, MetadataError, extract_turn_metadata, parse_http_request,
    parse_http_response, parse_sse_events,
};

#[derive(Debug, Clone)]
pub struct DecodedAttempt {
    pub attempt_id: Uuid,
    pub task_ref: String,
    pub identity: TaskIdentity,
    pub codex: CodexTaskMetadata,
    pub model: Option<String>,
    pub request_complete: bool,
    pub response_complete: bool,
    pub request_json: Value,
    pub response_json_events: Vec<Value>,
    pub decoded_events: Vec<DecodedEvent>,
    pub request_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DecodedError {
    pub wire_type: Option<String>,
    pub code: Option<String>,
    pub message: Option<String>,
    pub param: Option<String>,
    pub reason: Option<String>,
    pub http_status: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedEvent {
    TaskObserved {
        model: Option<String>,
    },
    AttemptStarted {
        attempt_id: Uuid,
        model: Option<String>,
    },
    ToolCall {
        attempt_id: Uuid,
        tool_name: String,
    },
    AttemptCompleted {
        attempt_id: Uuid,
        response_id: Option<String>,
        end_turn: bool,
        usage: UsageSummary,
    },
    AttemptFailed {
        attempt_id: Uuid,
        response_id: Option<String>,
        error: DecodedError,
    },
    AttemptIncomplete {
        attempt_id: Uuid,
        response_id: Option<String>,
        error: DecodedError,
    },
    AttemptCancelled {
        attempt_id: Uuid,
        response_id: Option<String>,
        error: DecodedError,
    },
    HttpError {
        attempt_id: Option<Uuid>,
        error: DecodedError,
    },
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("http parse error: {0}")]
    Http(#[from] HttpParseError),
    #[error("metadata parse error: {0}")]
    Metadata(#[from] MetadataError),
    #[error("request body is not valid json: {0}")]
    InvalidRequestJson(String),
    #[error("response event json is not valid: {0}")]
    InvalidResponseJson(String),
    #[error("sse parse error: {0}")]
    Sse(#[from] crate::SseError),
}

pub fn decode_http_exchange(
    request_bytes: &[u8],
    response_bytes: &[u8],
    request_at_ms: i64,
) -> Result<DecodedAttempt, CaptureError> {
    let request = parse_http_request(request_bytes)?;
    let response = parse_http_response(response_bytes)?;
    let request_json: Value = serde_json::from_slice(&request.body.decoded)
        .map_err(|error| CaptureError::InvalidRequestJson(error.to_string()))?;
    let turn_metadata = extract_turn_metadata(&request.headers, &request_json)?;
    let model = request_json
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let attempt_id = Uuid::now_v7();
    let task_ref = turn_metadata.task_ref();
    let identity = task_identity(&turn_metadata);
    let codex = codex_metadata(&turn_metadata);

    let mut decoded_events = vec![
        DecodedEvent::TaskObserved {
            model: model.clone(),
        },
        DecodedEvent::AttemptStarted {
            attempt_id,
            model: model.clone(),
        },
    ];
    let mut response_json_events = Vec::new();

    if response.status.is_some_and(|status| !status.is_success()) {
        let error = parse_http_error(
            &response.body.decoded,
            response.status.map_or(0, |status| status.as_u16()),
        );
        decoded_events.push(DecodedEvent::HttpError {
            attempt_id: Some(attempt_id),
            error,
        });
    } else {
        for event in parse_sse_events(&response.body.decoded)? {
            let json: Value = serde_json::from_str(&event.data)
                .map_err(|error| CaptureError::InvalidResponseJson(error.to_string()))?;
            map_responses_event(&json, attempt_id, &mut decoded_events);
            response_json_events.push(json);
        }
    }

    Ok(DecodedAttempt {
        attempt_id,
        task_ref,
        identity,
        codex,
        model,
        request_complete: request.body.complete,
        response_complete: response.body.complete,
        request_json,
        response_json_events,
        decoded_events,
        request_at_ms,
    })
}

fn map_responses_event(json: &Value, attempt_id: Uuid, decoded_events: &mut Vec<DecodedEvent>) {
    let kind = json.get("type").and_then(Value::as_str).unwrap_or_default();
    match kind {
        "response.output_item.added" | "response.output_item.done" => {
            if let Some(item) = json.get("item") {
                let item_type = item.get("type").and_then(Value::as_str).unwrap_or_default();
                if is_tool_call_type(item_type) {
                    let tool_name = item
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(item_type)
                        .to_owned();
                    decoded_events.push(DecodedEvent::ToolCall {
                        attempt_id,
                        tool_name,
                    });
                }
            }
        }
        "error" => {
            decoded_events.push(DecodedEvent::AttemptFailed {
                attempt_id,
                response_id: None,
                error: parse_error(json),
            });
        }
        "response.completed" => {
            let response = json.get("response");
            let response_id = response
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let end_turn = response
                .and_then(|value| value.get("end_turn"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let usage = response.and_then(parse_usage);
            decoded_events.push(DecodedEvent::AttemptCompleted {
                attempt_id,
                response_id,
                end_turn,
                usage: usage.unwrap_or_default(),
            });
        }
        "response.failed" => {
            decoded_events.push(DecodedEvent::AttemptFailed {
                attempt_id,
                response_id: response_id(json),
                error: parse_error(json),
            });
        }
        "response.incomplete" => {
            decoded_events.push(DecodedEvent::AttemptIncomplete {
                attempt_id,
                response_id: response_id(json),
                error: parse_error(json),
            });
        }
        "response.cancelled" => {
            decoded_events.push(DecodedEvent::AttemptCancelled {
                attempt_id,
                response_id: response_id(json),
                error: parse_error(json),
            });
        }
        _ => {}
    }
}

fn response_id(json: &Value) -> Option<String> {
    json.get("response")
        .and_then(|response| response.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn parse_usage(response: &Value) -> Option<UsageSummary> {
    let usage = response.get("usage")?;
    Some(UsageSummary {
        input_tokens: usage
            .get("input_tokens")
            .or_else(|| usage.get("prompt_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        output_tokens: usage
            .get("output_tokens")
            .or_else(|| usage.get("completion_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        reasoning_tokens: usage
            .get("output_tokens_details")
            .and_then(|value| value.get("reasoning_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        total_tokens: usage
            .get("total_tokens")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
    })
}

fn parse_error(json: &Value) -> DecodedError {
    let response = json.get("response");
    let error = response
        .and_then(|response| response.get("error"))
        .or_else(|| json.get("error"));
    DecodedError {
        wire_type: error
            .and_then(|value| value.get("type"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| json.get("type").and_then(Value::as_str).map(str::to_owned)),
        code: error
            .and_then(|value| value.get("code"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        message: error
            .and_then(|value| value.get("message"))
            .or_else(|| json.get("message"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        param: error
            .and_then(|value| value.get("param"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        reason: response
            .and_then(|value| value.get("incomplete_details"))
            .and_then(|value| value.get("reason"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        ..DecodedError::default()
    }
}

fn is_tool_call_type(item_type: &str) -> bool {
    matches!(
        item_type,
        "function_call"
            | "tool_search_call"
            | "custom_tool_call"
            | "local_shell_call"
            | "computer_call"
            | "shell_call"
            | "code_interpreter_call"
            | "file_search_call"
            | "web_search_call"
            | "image_generation_call"
            | "mcp_call"
    )
}

fn parse_http_error(body: &[u8], status: u16) -> DecodedError {
    let mut decoded = DecodedError {
        http_status: Some(status),
        message: Some(String::from_utf8_lossy(body).to_string()),
        ..DecodedError::default()
    };
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        let object = json.get("error").unwrap_or(&json);
        decoded.wire_type = object
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_owned);
        decoded.code = object
            .get("code")
            .and_then(Value::as_str)
            .map(str::to_owned);
        decoded.message = object
            .get("message")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or(decoded.message);
        decoded.param = object
            .get("param")
            .and_then(Value::as_str)
            .map(str::to_owned);
    }
    decoded
}

fn task_identity(metadata: &DecodedTurnMetadata) -> TaskIdentity {
    TaskIdentity {
        provider: "codex".to_owned(),
        session_id: metadata.session_id.clone(),
        thread_id: metadata.thread_id.clone(),
        turn_id: metadata.turn_id.clone(),
    }
}

fn codex_metadata(metadata: &DecodedTurnMetadata) -> CodexTaskMetadata {
    CodexTaskMetadata {
        request_kind: metadata.request_kind.clone(),
        parent_turn_id: metadata.parent_turn_id.clone(),
        root_turn_id: metadata.root_turn_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodedEvent, decode_http_exchange};

    #[test]
    fn decodes_tool_attempt_and_failed_attempt() {
        let request_body = "{\"model\":\"gpt-5\",\"client_metadata\":{\"x-codex-turn-metadata\":\"{\\\"session_id\\\":\\\"s1\\\",\\\"thread_id\\\":\\\"t1\\\",\\\"turn_id\\\":\\\"turn1\\\",\\\"request_kind\\\":\\\"turn\\\"}\"}}";
        let request = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\nx-codex-turn-metadata: {{\"session_id\":\"s1\",\"thread_id\":\"t1\",\"turn_id\":\"turn1\",\"request_kind\":\"turn\"}}\r\n\r\n{}",
            request_body.len(),
            request_body
        );
        let body = concat!(
            "event: response.output_item.done\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"name\":\"bash\",\"call_id\":\"call-1\",\"arguments\":\"{}\"}}\n\n",
            "event: response.failed\n",
            "data: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp-1\",\"error\":{\"code\":\"rate_limit_exceeded\",\"message\":\"slow down\"}}}\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        let decoded =
            decode_http_exchange(request.as_bytes(), response.as_bytes(), 0).expect("decode");

        assert_eq!(decoded.identity.turn_id, "turn1");
        assert_eq!(decoded.model.as_deref(), Some("gpt-5"));
        assert!(decoded.decoded_events.iter().any(
            |event| matches!(event, DecodedEvent::ToolCall { tool_name, .. } if tool_name == "bash")
        ));
        assert!(
            decoded
                .decoded_events
                .iter()
                .any(|event| matches!(event, DecodedEvent::AttemptFailed { .. }))
        );
        assert!(decoded.request_complete);
        assert!(decoded.response_complete);
    }

    #[test]
    fn parses_top_level_error_and_http_error_json() {
        let request_body = "{\"model\":\"gpt-5\",\"client_metadata\":{\"x-codex-turn-metadata\":\"{\\\"session_id\\\":\\\"s1\\\",\\\"thread_id\\\":\\\"t1\\\",\\\"turn_id\\\":\\\"turn1\\\",\\\"request_kind\\\":\\\"turn\\\"}\"}}";
        let request = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\nx-codex-turn-metadata: {{\"session_id\":\"s1\",\"thread_id\":\"t1\",\"turn_id\":\"turn1\",\"request_kind\":\"turn\"}}\r\n\r\n{}",
            request_body.len(),
            request_body
        );
        let body = concat!(
            "event: error\n",
            "data: {\"type\":\"error\",\"error\":{\"type\":\"server_error\",\"code\":\"boom\",\"message\":\"nope\",\"param\":\"x\"}}\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let decoded =
            decode_http_exchange(request.as_bytes(), response.as_bytes(), 0).expect("decode");
        assert!(decoded.decoded_events.iter().any(|event| {
            matches!(
                event,
                DecodedEvent::AttemptFailed { error, .. }
                    if error.code.as_deref() == Some("boom")
                        && error.param.as_deref() == Some("x")
                        && error.wire_type.as_deref() == Some("server_error")
            )
        }));

        let error_response = concat!(
            "HTTP/1.1 429 Too Many Requests\r\n",
            "Content-Length: 91\r\n",
            "Content-Type: application/json\r\n",
            "\r\n",
            "{\"error\":{\"type\":\"rate_limit_error\",\"code\":\"rate_limit\",\"message\":\"slow down\",\"param\":\"q\"}}"
        );
        let decoded =
            decode_http_exchange(request.as_bytes(), error_response.as_bytes(), 0).expect("decode");
        assert!(decoded.decoded_events.iter().any(|event| {
            matches!(
                event,
                DecodedEvent::HttpError { error, .. }
                    if error.http_status == Some(429)
                        && error.code.as_deref() == Some("rate_limit")
                        && error.wire_type.as_deref() == Some("rate_limit_error")
                        && error.param.as_deref() == Some("q")
            )
        }));
    }

    #[test]
    fn accepts_local_shell_call_and_marks_incomplete_http_body() {
        let request_body = "{\"model\":\"gpt-5\",\"client_metadata\":{\"x-codex-turn-metadata\":\"{\\\"session_id\\\":\\\"s1\\\",\\\"thread_id\\\":\\\"t1\\\",\\\"turn_id\\\":\\\"turn1\\\",\\\"request_kind\\\":\\\"turn\\\"}\"}}";
        let request = format!(
            "POST /v1/responses HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\nx-codex-turn-metadata: {{\"session_id\":\"s1\",\"thread_id\":\"t1\",\"turn_id\":\"turn1\",\"request_kind\":\"turn\"}}\r\n\r\n{}",
            request_body.len(),
            request_body
        );
        let body = concat!(
            "event: response.output_item.done\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"local_shell_call\",\"call_id\":\"call-1\"}}\n\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{}",
            body.len() + 5,
            body
        );
        let decoded =
            decode_http_exchange(request.as_bytes(), response.as_bytes(), 0).expect("decode");
        assert!(!decoded.response_complete);
        assert!(decoded.decoded_events.iter().any(|event| {
            matches!(event, DecodedEvent::ToolCall { tool_name, .. } if tool_name == "local_shell_call")
        }));
    }
}
