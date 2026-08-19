use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

#[derive(Debug, Error)]
pub enum SseError {
    #[error("invalid utf-8 in sse stream")]
    InvalidUtf8,
}

#[derive(Debug, Default, Clone)]
struct EventBuilder {
    event: Option<String>,
    data_lines: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct SseDecoder {
    buffer: Vec<u8>,
    current: EventBuilder,
}

impl SseDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();

        while let Some(line_end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = self.buffer.drain(..=line_end).collect::<Vec<_>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }

            let line = String::from_utf8(line).map_err(|_| SseError::InvalidUtf8)?;
            if line.is_empty() {
                if let Some(event) = self.current.finish() {
                    events.push(event);
                }
                continue;
            }

            if line.starts_with(':') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("event:") {
                self.current.event = Some(rest.trim().to_owned());
            } else if let Some(rest) = line.strip_prefix("data:") {
                self.current.data_lines.push(rest.trim_start().to_owned());
            }
        }

        Ok(events)
    }

    pub fn finish(&mut self) -> Result<Vec<SseEvent>, SseError> {
        if !self.buffer.is_empty() {
            let line = String::from_utf8(std::mem::take(&mut self.buffer))
                .map_err(|_| SseError::InvalidUtf8)?;
            if let Some(rest) = line.strip_prefix("event:") {
                self.current.event = Some(rest.trim().to_owned());
            } else if let Some(rest) = line.strip_prefix("data:") {
                self.current.data_lines.push(rest.trim_start().to_owned());
            }
        }

        Ok(self.current.finish().into_iter().collect())
    }
}

pub fn parse_sse_events(bytes: &[u8]) -> Result<Vec<SseEvent>, SseError> {
    let mut decoder = SseDecoder::new();
    let mut events = decoder.push(bytes)?;
    events.extend(decoder.finish()?);
    Ok(events)
}

impl EventBuilder {
    fn finish(&mut self) -> Option<SseEvent> {
        if self.event.is_none() && self.data_lines.is_empty() {
            return None;
        }
        Some(SseEvent {
            event: self.event.take(),
            data: std::mem::take(&mut self.data_lines).join("\n"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{SseDecoder, parse_sse_events};

    #[test]
    fn parses_fragmented_multiline_events() {
        let stream = b": keepalive\r\nevent: response.output_item.done\r\ndata: {\"type\":\"response.output_item.done\",\r\ndata: \"item\":{\"type\":\"function_call\",\"name\":\"bash\"}}\r\n\r\nevent: response.completed\r\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\"}}\r\n\r\n";
        let events = parse_sse_events(stream).expect("parse sse");
        assert_eq!(events.len(), 2);
        assert!(events[0].data.contains("\"function_call\""));
        assert_eq!(events[1].event.as_deref(), Some("response.completed"));
    }

    #[test]
    fn supports_byte_at_a_time_feed() {
        let mut decoder = SseDecoder::new();
        let mut events = Vec::new();
        for byte in b"data: one\r\ndata: two\r\n\r\n" {
            events.extend(decoder.push(&[*byte]).expect("feed"));
        }
        events.extend(decoder.finish().expect("finish"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "one\ntwo");
    }
}
