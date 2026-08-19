use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSocketFrame {
    pub opcode: u8,
    pub payload: Vec<u8>,
    pub fin: bool,
}

#[derive(Debug, Default, Clone)]
pub struct WebSocketDecoder {
    buffer: Vec<u8>,
    continuation_opcode: Option<u8>,
    continuation_payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum WebSocketError {
    #[error("truncated websocket frame")]
    Truncated,
    #[error("invalid websocket continuation")]
    InvalidContinuation,
}

impl WebSocketDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<WebSocketFrame>, WebSocketError> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = self.try_decode_next()? {
            if frame.opcode == 0x0 {
                let Some(opcode) = self.continuation_opcode else {
                    return Err(WebSocketError::InvalidContinuation);
                };
                self.continuation_payload.extend_from_slice(&frame.payload);
                if frame.fin {
                    frames.push(WebSocketFrame {
                        opcode,
                        payload: std::mem::take(&mut self.continuation_payload),
                        fin: true,
                    });
                    self.continuation_opcode = None;
                }
                continue;
            }

            if !frame.fin {
                self.continuation_opcode = Some(frame.opcode);
                self.continuation_payload = frame.payload;
                continue;
            }

            frames.push(frame);
        }
        Ok(frames)
    }

    fn try_decode_next(&mut self) -> Result<Option<WebSocketFrame>, WebSocketError> {
        if self.buffer.len() < 2 {
            return Ok(None);
        }
        let b0 = self.buffer[0];
        let b1 = self.buffer[1];
        let fin = (b0 & 0x80) != 0;
        let opcode = b0 & 0x0f;
        let masked = (b1 & 0x80) != 0;
        let mut len = usize::from(b1 & 0x7f);
        let mut cursor = 2usize;

        if len == 126 {
            if self.buffer.len() < cursor + 2 {
                return Ok(None);
            }
            len = usize::from(u16::from_be_bytes([
                self.buffer[cursor],
                self.buffer[cursor + 1],
            ]));
            cursor += 2;
        } else if len == 127 {
            if self.buffer.len() < cursor + 8 {
                return Ok(None);
            }
            len = u64::from_be_bytes(
                self.buffer[cursor..cursor + 8]
                    .try_into()
                    .map_err(|_| WebSocketError::Truncated)?,
            ) as usize;
            cursor += 8;
        }

        let mask = if masked {
            if self.buffer.len() < cursor + 4 {
                return Ok(None);
            }
            let mask = [
                self.buffer[cursor],
                self.buffer[cursor + 1],
                self.buffer[cursor + 2],
                self.buffer[cursor + 3],
            ];
            cursor += 4;
            Some(mask)
        } else {
            None
        };
        if self.buffer.len() < cursor + len {
            return Ok(None);
        }

        let payload = self.buffer[cursor..cursor + len].to_vec();
        self.buffer.drain(..cursor + len);

        let payload = if let Some(mask) = mask {
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4])
                .collect()
        } else {
            payload
        };

        Ok(Some(WebSocketFrame {
            opcode,
            payload,
            fin,
        }))
    }
}

pub fn decode_websocket_frames(bytes: &[u8]) -> Result<Vec<WebSocketFrame>, WebSocketError> {
    let mut cursor = 0usize;
    let mut frames = Vec::new();
    while cursor < bytes.len() {
        let b0 = *bytes.get(cursor).ok_or(WebSocketError::Truncated)?;
        let b1 = *bytes.get(cursor + 1).ok_or(WebSocketError::Truncated)?;
        let fin = (b0 & 0x80) != 0;
        let opcode = b0 & 0x0f;
        let masked = (b1 & 0x80) != 0;
        let mut len = usize::from(b1 & 0x7f);
        cursor += 2;

        if len == 126 {
            let bytes = bytes
                .get(cursor..cursor + 2)
                .ok_or(WebSocketError::Truncated)?;
            len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            cursor += 2;
        } else if len == 127 {
            let bytes = bytes
                .get(cursor..cursor + 8)
                .ok_or(WebSocketError::Truncated)?;
            len = u64::from_be_bytes(bytes.try_into().map_err(|_| WebSocketError::Truncated)?)
                as usize;
            cursor += 8;
        }

        let mask = if masked {
            let mask = bytes
                .get(cursor..cursor + 4)
                .ok_or(WebSocketError::Truncated)?;
            cursor += 4;
            Some([mask[0], mask[1], mask[2], mask[3]])
        } else {
            None
        };
        let payload = bytes
            .get(cursor..cursor + len)
            .ok_or(WebSocketError::Truncated)?;
        cursor += len;

        let payload = if let Some(mask) = mask {
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % 4])
                .collect()
        } else {
            payload.to_vec()
        };
        frames.push(WebSocketFrame {
            opcode,
            payload,
            fin,
        });
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::{WebSocketDecoder, decode_websocket_frames};

    #[test]
    fn decodes_masked_text_frame() {
        let frame = [0x81u8, 0x82, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x93];
        let frames = decode_websocket_frames(&frame).expect("ws decode");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"Hi");
    }

    #[test]
    fn reassembles_fragmented_frames() {
        let mut decoder = WebSocketDecoder::new();
        let first = [0x01u8, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2];
        let second = [0x80u8, 0x83, 5, 6, 7, 8, b'!' ^ 5, b'!' ^ 6, b'!' ^ 7];
        assert!(decoder.push(&first).expect("first").is_empty());
        let frames = decoder.push(&second).expect("second");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload, b"hi!!!");
    }
}
