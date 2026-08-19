#![allow(
    clippy::cast_possible_truncation,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unused_self
)]

pub mod abi;
pub mod loader;
pub mod profile;

pub use loader::{
    BootIdentity, CaptureLoader, LoaderError, LoaderEvent, OwnedCaptureRecord, RunningCapture,
};
pub use profile::{AttachmentDecision, BuildFingerprint, LoadedProfile, ProfileRegistry};
