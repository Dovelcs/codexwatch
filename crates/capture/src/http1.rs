use std::collections::BTreeMap;
use std::io::Read;

use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBody {
    pub raw: Vec<u8>,
    pub decoded: Vec<u8>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMessage {
    pub version: Version,
    pub method: Option<Method>,
    pub uri: Option<Uri>,
    pub status: Option<StatusCode>,
    pub headers: HeaderMap,
    pub body: HttpBody,
}

#[derive(Debug, Error)]
pub enum HttpParseError {
    #[error("incomplete http head")]
    IncompleteHead,
    #[error("unsupported or invalid http version")]
    InvalidVersion,
    #[error("invalid method: {0}")]
    InvalidMethod(String),
    #[error("invalid uri: {0}")]
    InvalidUri(String),
    #[error("invalid status code: {0}")]
    InvalidStatus(u16),
    #[error("invalid header name: {0}")]
    InvalidHeaderName(String),
    #[error("invalid header value for {0}")]
    InvalidHeaderValue(String),
    #[error("invalid content length: {0}")]
    InvalidContentLength(String),
    #[error("chunked body parse failed")]
    InvalidChunkedBody,
    #[error("body decode failed: {0}")]
    BodyDecode(String),
}

pub fn parse_http_request(bytes: &[u8]) -> Result<HttpMessage, HttpParseError> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut headers);
    let status = request
        .parse(bytes)
        .map_err(|_| HttpParseError::IncompleteHead)?;
    let header_len = match status {
        httparse::Status::Complete(header_len) => header_len,
        httparse::Status::Partial => return Err(HttpParseError::IncompleteHead),
    };

    let version = parse_version(request.version)?;
    let method = request
        .method
        .ok_or(HttpParseError::IncompleteHead)?
        .parse::<Method>()
        .map_err(|_| {
            HttpParseError::InvalidMethod(request.method.unwrap_or_default().to_owned())
        })?;
    let uri = request
        .path
        .ok_or(HttpParseError::IncompleteHead)?
        .parse::<Uri>()
        .map_err(|_| HttpParseError::InvalidUri(request.path.unwrap_or_default().to_owned()))?;
    let headers = to_header_map(request.headers)?;
    let body = decode_body(&headers, &bytes[header_len..])?;

    Ok(HttpMessage {
        version,
        method: Some(method),
        uri: Some(uri),
        status: None,
        headers,
        body,
    })
}

pub fn parse_http_response(bytes: &[u8]) -> Result<HttpMessage, HttpParseError> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut response = httparse::Response::new(&mut headers);
    let status = response
        .parse(bytes)
        .map_err(|_| HttpParseError::IncompleteHead)?;
    let header_len = match status {
        httparse::Status::Complete(header_len) => header_len,
        httparse::Status::Partial => return Err(HttpParseError::IncompleteHead),
    };

    let version = parse_version(response.version)?;
    let status = StatusCode::from_u16(response.code.ok_or(HttpParseError::IncompleteHead)?)
        .map_err(|_| HttpParseError::InvalidStatus(response.code.unwrap_or_default()))?;
    let headers = to_header_map(response.headers)?;
    let body = decode_body(&headers, &bytes[header_len..])?;

    Ok(HttpMessage {
        version,
        method: None,
        uri: None,
        status: Some(status),
        headers,
        body,
    })
}

fn parse_version(version: Option<u8>) -> Result<Version, HttpParseError> {
    match version {
        Some(1) => Ok(Version::HTTP_11),
        Some(0) => Ok(Version::HTTP_10),
        _ => Err(HttpParseError::InvalidVersion),
    }
}

fn to_header_map(headers: &[httparse::Header<'_>]) -> Result<HeaderMap, HttpParseError> {
    let mut map = HeaderMap::new();
    for header in headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| HttpParseError::InvalidHeaderName(header.name.to_owned()))?;
        let value = HeaderValue::from_bytes(header.value)
            .map_err(|_| HttpParseError::InvalidHeaderValue(header.name.to_owned()))?;
        map.append(name, value);
    }
    Ok(map)
}

fn decode_body(headers: &HeaderMap, body_bytes: &[u8]) -> Result<HttpBody, HttpParseError> {
    let (raw, complete) = if is_chunked(headers) {
        decode_chunked(body_bytes)?
    } else if let Some(content_length) = headers.get(http::header::CONTENT_LENGTH) {
        let expected = content_length
            .to_str()
            .map_err(|_| HttpParseError::InvalidContentLength("<non-utf8>".to_owned()))?
            .parse::<usize>()
            .map_err(|_| {
                HttpParseError::InvalidContentLength(
                    content_length.to_str().unwrap_or_default().to_owned(),
                )
            })?;
        (
            body_bytes[..body_bytes.len().min(expected)].to_vec(),
            body_bytes.len() >= expected,
        )
    } else {
        (body_bytes.to_vec(), true)
    };

    let decoded = decode_content_encoding(headers, &raw)?;
    Ok(HttpBody {
        raw,
        decoded,
        complete,
    })
}

fn is_chunked(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
}

fn decode_chunked(body_bytes: &[u8]) -> Result<(Vec<u8>, bool), HttpParseError> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();

    loop {
        let Some(line_end) = find_crlf(body_bytes, cursor) else {
            return Ok((decoded, false));
        };
        let line = std::str::from_utf8(&body_bytes[cursor..line_end])
            .map_err(|_| HttpParseError::InvalidChunkedBody)?;
        let chunk_size =
            usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|_| HttpParseError::InvalidChunkedBody)?;
        cursor = line_end + 2;

        if chunk_size == 0 {
            loop {
                let Some(trailer_end) = find_crlf(body_bytes, cursor) else {
                    return Ok((decoded, false));
                };
                if trailer_end == cursor {
                    return Ok((decoded, true));
                }
                cursor = trailer_end + 2;
            }
        }

        let end = cursor
            .checked_add(chunk_size)
            .ok_or(HttpParseError::InvalidChunkedBody)?;
        let Some(chunk) = body_bytes.get(cursor..end) else {
            return Ok((decoded, false));
        };
        decoded.extend_from_slice(chunk);
        let Some(chunk_end) = body_bytes.get(end..end + 2) else {
            return Ok((decoded, false));
        };
        if chunk_end != b"\r\n" {
            return Err(HttpParseError::InvalidChunkedBody);
        }
        cursor = end + 2;
    }
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

fn decode_content_encoding(headers: &HeaderMap, raw: &[u8]) -> Result<Vec<u8>, HttpParseError> {
    let encoding = headers
        .get(http::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if encoding.is_empty() {
        return Ok(raw.to_vec());
    }

    match encoding.as_str() {
        "gzip" => {
            let mut decoder = flate2::read::GzDecoder::new(Bytes::copy_from_slice(raw).reader());
            let mut decoded = Vec::new();
            decoder
                .read_to_end(&mut decoded)
                .map_err(|error| HttpParseError::BodyDecode(error.to_string()))?;
            Ok(decoded)
        }
        "br" => {
            let mut decoder = brotli::Decompressor::new(Bytes::copy_from_slice(raw).reader(), 4096);
            let mut decoded = Vec::new();
            decoder
                .read_to_end(&mut decoded)
                .map_err(|error| HttpParseError::BodyDecode(error.to_string()))?;
            Ok(decoded)
        }
        "zstd" => zstd::stream::decode_all(raw)
            .map_err(|error| HttpParseError::BodyDecode(error.to_string())),
        _ => Ok(raw.to_vec()),
    }
}

pub fn headers_to_map(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_http_request, parse_http_response};

    #[test]
    fn parses_chunked_sse_response() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Type: text/event-stream\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "14\r\n",
            "data: {\"type\":\"x\"}\n\n\r\n",
            "0\r\n\r\n"
        );

        let message = parse_http_response(response.as_bytes()).expect("response parse");
        assert_eq!(message.status.expect("status").as_u16(), 200);
        assert_eq!(
            std::str::from_utf8(&message.body.decoded).unwrap(),
            "data: {\"type\":\"x\"}\n\n"
        );
        assert!(message.body.complete);
    }

    #[test]
    fn parses_http_request() {
        let body = "{\"model\":\"gpt\"}";
        let request = "POST /v1/responses HTTP/1.1\r\nHost: example.com\r\nContent-Length: ";
        let request = format!("{request}{}\r\n\r\n{body}", body.len());
        let message = parse_http_request(request.as_bytes()).expect("request parse");
        assert_eq!(message.method.expect("method").as_str(), "POST");
        assert_eq!(message.uri.expect("uri").path(), "/v1/responses");
        assert_eq!(
            std::str::from_utf8(&message.body.decoded).unwrap(),
            "{\"model\":\"gpt\"}"
        );
        assert!(message.body.complete);
    }

    #[test]
    fn marks_short_content_length_as_incomplete() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 10\r\n",
            "\r\n",
            "hello"
        );
        let message = parse_http_response(response.as_bytes()).expect("response parse");
        assert_eq!(message.body.decoded, b"hello");
        assert!(!message.body.complete);
    }

    #[test]
    fn marks_incomplete_chunked_body_as_incomplete() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "5\r\nhello\r\n",
            "3\r\nab"
        );
        let message = parse_http_response(response.as_bytes()).expect("response parse");
        assert_eq!(message.body.decoded, b"hello");
        assert!(!message.body.complete);
    }
}
