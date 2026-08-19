#![allow(
    clippy::assigning_clones,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_is_multiple_of,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::ref_option,
    clippy::semicolon_if_nothing_returned,
    clippy::single_match_else,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::unnecessary_debug_formatting,
    clippy::unnecessary_wraps,
    clippy::unnested_or_patterns,
    clippy::uninlined_format_args,
    clippy::unused_self,
    clippy::unused_async
)]

pub mod blob;
pub mod capture_lane;
pub mod config;
pub mod decode_support;
pub mod ebpf_lane;
pub mod model;
pub mod service;
pub mod store;
pub mod transport;

pub use blob::StoredContentInput;
pub use config::ClientConfig;
pub use decode_support::*;
pub use model::*;
pub use service::{Cli, ClientIngress, ClientService, FixtureBundle, run_cli};
