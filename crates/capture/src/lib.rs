#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::match_wildcard_for_single_variants,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::result_unit_err,
    clippy::similar_names
)]

//! Passive capture decoding for CodexWatch.

mod af_packet;
mod h2;
mod http1;
mod metadata;
mod responses;
mod sse;
mod tcp;
mod websocket;

pub use af_packet::{
    PacketDecodeError, ProcLookupError, ProcessFlowDirection, ProcessFlowIndex, ProcessSocketFlow,
    SocketInodeMap,
};
pub use af_packet::{PassiveTap, TapError, TcpSegment, decode_segment};
pub use h2::{H2DecodeError, H2Decoder, H2Event, H2HeaderBlock, H2Priority, H2StreamEvent};
pub use http1::{
    HttpBody, HttpMessage, HttpParseError, headers_to_map, parse_http_request, parse_http_response,
};
pub use metadata::{DecodedTurnMetadata, MetadataError, extract_turn_metadata};
pub use responses::{
    CaptureError, DecodedAttempt, DecodedError, DecodedEvent, decode_http_exchange,
};
pub use sse::{SseDecoder, SseError, SseEvent, parse_sse_events};
pub use tcp::{AssembledChunk, AssemblerResult, TcpAssembler};
pub use websocket::{WebSocketDecoder, WebSocketError, WebSocketFrame, decode_websocket_frames};
