use hpack::Decoder;

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Priority {
    pub stream_id: u32,
    pub dependency_stream_id: u32,
    pub exclusive: bool,
    pub weight: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2HeaderBlock {
    pub stream_id: u32,
    pub headers: Vec<(String, String)>,
    pub end_stream: bool,
    pub priority: Option<H2Priority>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2Event {
    Headers(H2HeaderBlock),
    Data {
        stream_id: u32,
        payload: Vec<u8>,
        end_stream: bool,
    },
    Priority(H2Priority),
    RstStream {
        stream_id: u32,
        error_code: u32,
    },
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug_data: Vec<u8>,
    },
}

pub type H2StreamEvent = H2Event;

#[derive(Debug, thiserror::Error)]
pub enum H2DecodeError {
    #[error("invalid HTTP/2 client preface")]
    InvalidPreface,
    #[error("invalid HTTP/2 frame")]
    InvalidFrame,
    #[error("invalid frame padding")]
    InvalidPadding,
    #[error("unexpected continuation frame")]
    UnexpectedContinuation,
    #[error("CONTINUATION stream id mismatch")]
    ContinuationStreamMismatch,
    #[error("HPACK decode failed: {0}")]
    HeaderDecode(String),
}

#[derive(Debug, Clone)]
struct PendingHeaders {
    stream_id: u32,
    end_stream: bool,
    priority: Option<H2Priority>,
    block: Vec<u8>,
}

struct DirectionState {
    buffer: Vec<u8>,
    hpack: Decoder<'static>,
    pending_headers: Option<PendingHeaders>,
    preface_complete: bool,
}

impl Default for DirectionState {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            hpack: Decoder::new(),
            pending_headers: None,
            preface_complete: false,
        }
    }
}

#[derive(Default)]
pub struct H2Decoder {
    client: DirectionState,
    server: DirectionState,
}

impl H2Decoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_client(&mut self, bytes: &[u8]) -> Result<Vec<H2Event>, H2DecodeError> {
        self.push(bytes, true)
    }

    pub fn push_server(&mut self, bytes: &[u8]) -> Result<Vec<H2Event>, H2DecodeError> {
        self.push(bytes, false)
    }

    fn push(&mut self, bytes: &[u8], client_side: bool) -> Result<Vec<H2Event>, H2DecodeError> {
        let state = if client_side {
            &mut self.client
        } else {
            &mut self.server
        };
        state.buffer.extend_from_slice(bytes);
        if client_side {
            consume_client_preface(state)?;
        }
        parse_complete_frames(state)
    }
}

fn consume_client_preface(state: &mut DirectionState) -> Result<(), H2DecodeError> {
    if state.preface_complete {
        return Ok(());
    }
    let compare_len = state.buffer.len().min(CLIENT_PREFACE.len());
    if state.buffer[..compare_len] != CLIENT_PREFACE[..compare_len] {
        return Err(H2DecodeError::InvalidPreface);
    }
    if state.buffer.len() < CLIENT_PREFACE.len() {
        return Ok(());
    }
    state.buffer.drain(..CLIENT_PREFACE.len());
    state.preface_complete = true;
    Ok(())
}

fn parse_complete_frames(state: &mut DirectionState) -> Result<Vec<H2Event>, H2DecodeError> {
    let mut events = Vec::new();
    loop {
        if state.buffer.len() < 9 {
            break;
        }
        let length = ((usize::from(state.buffer[0])) << 16)
            | ((usize::from(state.buffer[1])) << 8)
            | usize::from(state.buffer[2]);
        if state.buffer.len() < 9 + length {
            break;
        }

        let frame_type = state.buffer[3];
        let flags = state.buffer[4];
        let stream_id = u32::from_be_bytes([
            state.buffer[5],
            state.buffer[6],
            state.buffer[7],
            state.buffer[8],
        ]) & 0x7fff_ffff;
        let payload = state.buffer[9..9 + length].to_vec();
        state.buffer.drain(..9 + length);

        match frame_type {
            0x0 => events.push(parse_data_frame(stream_id, flags, &payload)?),
            0x1 => parse_headers_frame(state, stream_id, flags, &payload, &mut events)?,
            0x2 => events.push(H2Event::Priority(parse_priority_payload(
                stream_id, &payload,
            )?)),
            0x3 => {
                if payload.len() != 4 || stream_id == 0 {
                    return Err(H2DecodeError::InvalidFrame);
                }
                events.push(H2Event::RstStream {
                    stream_id,
                    error_code: u32::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]),
                });
            }
            0x7 => {
                if payload.len() < 8 || stream_id != 0 {
                    return Err(H2DecodeError::InvalidFrame);
                }
                events.push(H2Event::GoAway {
                    last_stream_id: u32::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]) & 0x7fff_ffff,
                    error_code: u32::from_be_bytes([
                        payload[4], payload[5], payload[6], payload[7],
                    ]),
                    debug_data: payload[8..].to_vec(),
                });
            }
            0x9 => parse_continuation_frame(state, stream_id, flags, &payload, &mut events)?,
            _ => {}
        }
    }
    Ok(events)
}

fn parse_data_frame(stream_id: u32, flags: u8, payload: &[u8]) -> Result<H2Event, H2DecodeError> {
    if stream_id == 0 {
        return Err(H2DecodeError::InvalidFrame);
    }
    let payload = strip_padding(payload, flags & 0x08 != 0)?;
    Ok(H2Event::Data {
        stream_id,
        payload: payload.to_vec(),
        end_stream: flags & 0x01 != 0,
    })
}

fn parse_headers_frame(
    state: &mut DirectionState,
    stream_id: u32,
    flags: u8,
    payload: &[u8],
    events: &mut Vec<H2Event>,
) -> Result<(), H2DecodeError> {
    if stream_id == 0 {
        return Err(H2DecodeError::InvalidFrame);
    }
    let mut cursor = 0usize;
    let payload = if flags & 0x08 != 0 {
        if payload.is_empty() {
            return Err(H2DecodeError::InvalidPadding);
        }
        let pad_len = usize::from(payload[0]);
        cursor += 1;
        if payload.len() < cursor + pad_len {
            return Err(H2DecodeError::InvalidPadding);
        }
        &payload[..payload.len() - pad_len]
    } else {
        payload
    };

    let priority = if flags & 0x20 != 0 {
        if payload.len() < cursor + 5 {
            return Err(H2DecodeError::InvalidFrame);
        }
        let raw_dependency = u32::from_be_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        let priority = H2Priority {
            stream_id,
            dependency_stream_id: raw_dependency & 0x7fff_ffff,
            exclusive: raw_dependency & 0x8000_0000 != 0,
            weight: payload[cursor + 4],
        };
        cursor += 5;
        Some(priority)
    } else {
        None
    };

    if payload.len() < cursor {
        return Err(H2DecodeError::InvalidFrame);
    }
    let block_fragment = payload[cursor..].to_vec();
    let end_stream = flags & 0x01 != 0;
    if flags & 0x04 != 0 {
        events.push(H2Event::Headers(H2HeaderBlock {
            stream_id,
            headers: decode_headers(&mut state.hpack, &block_fragment)?,
            end_stream,
            priority,
        }));
    } else {
        state.pending_headers = Some(PendingHeaders {
            stream_id,
            end_stream,
            priority,
            block: block_fragment,
        });
    }
    Ok(())
}

fn parse_continuation_frame(
    state: &mut DirectionState,
    stream_id: u32,
    flags: u8,
    payload: &[u8],
    events: &mut Vec<H2Event>,
) -> Result<(), H2DecodeError> {
    let Some(mut pending) = state.pending_headers.take() else {
        return Err(H2DecodeError::UnexpectedContinuation);
    };
    if pending.stream_id != stream_id {
        return Err(H2DecodeError::ContinuationStreamMismatch);
    }
    pending.block.extend_from_slice(payload);
    if flags & 0x04 != 0 {
        events.push(H2Event::Headers(H2HeaderBlock {
            stream_id: pending.stream_id,
            headers: decode_headers(&mut state.hpack, &pending.block)?,
            end_stream: pending.end_stream,
            priority: pending.priority,
        }));
    } else {
        state.pending_headers = Some(pending);
    }
    Ok(())
}

fn strip_padding(payload: &[u8], padded: bool) -> Result<&[u8], H2DecodeError> {
    if !padded {
        return Ok(payload);
    }
    let Some((&pad_len, payload)) = payload.split_first() else {
        return Err(H2DecodeError::InvalidPadding);
    };
    let pad_len = usize::from(pad_len);
    if payload.len() < pad_len {
        return Err(H2DecodeError::InvalidPadding);
    }
    Ok(&payload[..payload.len() - pad_len])
}

fn parse_priority_payload(stream_id: u32, payload: &[u8]) -> Result<H2Priority, H2DecodeError> {
    if stream_id == 0 || payload.len() != 5 {
        return Err(H2DecodeError::InvalidFrame);
    }
    let raw_dependency = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok(H2Priority {
        stream_id,
        dependency_stream_id: raw_dependency & 0x7fff_ffff,
        exclusive: raw_dependency & 0x8000_0000 != 0,
        weight: payload[4],
    })
}

fn decode_headers(
    decoder: &mut Decoder<'static>,
    block: &[u8],
) -> Result<Vec<(String, String)>, H2DecodeError> {
    decoder
        .decode(block)
        .map(|headers| {
            headers
                .into_iter()
                .map(|(name, value)| {
                    (
                        String::from_utf8_lossy(&name).into_owned(),
                        String::from_utf8_lossy(&value).into_owned(),
                    )
                })
                .collect()
        })
        .map_err(|error| H2DecodeError::HeaderDecode(format!("{error:?}")))
}
