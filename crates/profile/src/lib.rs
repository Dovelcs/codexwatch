#![allow(clippy::missing_errors_doc, clippy::unreadable_literal)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttachKind {
    Uprobe,
    Uretprobe,
    Kprobe,
    Kretprobe,
    Tracepoint,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FieldEncoding {
    StringPtrLenCap,
    OptionStringPtrLenCap,
    OptionI64,
    U8Discriminant,
    CodexErrorInfoOption,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReturnEncoding {
    None,
    ResultUsizeRaxRdx,
    RustSretOutPointer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeSignature {
    pub file_offset: u64,
    pub mask_hex: String,
    pub bytes_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldOffset {
    pub name: String,
    pub offset: u64,
    pub encoding: FieldEncoding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ProbeLayout {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldOffset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_argument: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buf_argument: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub len_argument: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_pointer_argument: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_tag_register: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_len_register: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_encoding: Option<ReturnEncoding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeDefinition {
    pub program: String,
    pub attach_kind: AttachKind,
    pub symbol: String,
    pub file_offset: u64,
    pub signature: ProbeSignature,
    pub argument_abi: String,
    #[serde(default)]
    pub layout: ProbeLayout,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KernelHook {
    pub program: String,
    pub attach_kind: AttachKind,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeProfile {
    pub profile_id: String,
    pub codex_version: String,
    pub elf_sha256: String,
    pub architecture: String,
    pub debuglink_name: String,
    pub debuglink_crc32: u32,
    pub validated: bool,
    #[serde(default)]
    pub kernel_hooks: Vec<KernelHook>,
    pub probes: BTreeMap<String, Vec<ProbeDefinition>>,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachPlan {
    pub profile_id: String,
    pub kernel_hooks: Vec<KernelHook>,
    pub probes: Vec<(String, ProbeDefinition)>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("unsupported_codex_build")]
    UnsupportedCodexBuild,
    #[error("elf sha256 mismatch")]
    HashMismatch,
    #[error("invalid zero offset for probe {0}")]
    ZeroOffset(String),
    #[error("masked signature mismatch for probe {0}")]
    SignatureMismatch(String),
}

pub fn load_profile(json: &str) -> Result<ProbeProfile, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn resolve_attach_plan(
    profile: &ProbeProfile,
    elf_bytes: &[u8],
) -> Result<AttachPlan, ProfileError> {
    if !profile.validated {
        return Err(ProfileError::UnsupportedCodexBuild);
    }

    if hex_sha256(elf_bytes) != profile.elf_sha256 {
        return Err(ProfileError::HashMismatch);
    }

    let mut probes = Vec::new();
    for (logical_name, sites) in &profile.probes {
        for site in sites {
            if site.file_offset == 0 || site.signature.file_offset == 0 {
                return Err(ProfileError::ZeroOffset(logical_name.clone()));
            }
            if !matches_signature(elf_bytes, &site.signature) {
                return Err(ProfileError::SignatureMismatch(format!(
                    "{logical_name}@0x{:x}",
                    site.file_offset
                )));
            }
            probes.push((logical_name.clone(), site.clone()));
        }
    }

    Ok(AttachPlan {
        profile_id: profile.profile_id.clone(),
        kernel_hooks: profile.kernel_hooks.clone(),
        probes,
    })
}

fn matches_signature(elf_bytes: &[u8], signature: &ProbeSignature) -> bool {
    let expected = decode_hex(&signature.bytes_hex);
    let mask = decode_hex(&signature.mask_hex);
    if expected.len() != mask.len() {
        return false;
    }

    let Some(start) = usize::try_from(signature.file_offset).ok() else {
        return false;
    };
    let end = start.saturating_add(expected.len());
    let Some(actual) = elf_bytes.get(start..end) else {
        return false;
    };

    actual
        .iter()
        .zip(expected.iter().zip(mask.iter()))
        .all(|(actual, (expected, mask))| (actual & mask) == (expected & mask))
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .filter_map(|chunk| u8::from_str_radix(chunk, 16).ok())
        .collect()
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        AttachKind, FieldEncoding, FieldOffset, ProbeDefinition, ProbeLayout, ProbeProfile,
        ProbeSignature, ProfileError, resolve_attach_plan,
    };
    use std::collections::BTreeMap;

    fn valid_profile(validated: bool) -> ProbeProfile {
        ProbeProfile {
            profile_id: "codex-0.144.1-linux-x86_64".to_owned(),
            codex_version: "0.144.1".to_owned(),
            elf_sha256: super::hex_sha256(b"\x90\x90\xcc\xcc\xdd"),
            architecture: "x86_64".to_owned(),
            debuglink_name: "codex.debug".to_owned(),
            debuglink_crc32: 0xefde_2f0c,
            validated,
            kernel_hooks: Vec::new(),
            probes: BTreeMap::from([(
                "plaintext_write".to_owned(),
                vec![ProbeDefinition {
                    program: "plaintext_write_enter".to_owned(),
                    attach_kind: AttachKind::Uprobe,
                    symbol: "rustls::write".to_owned(),
                    file_offset: 1,
                    signature: ProbeSignature {
                        file_offset: 1,
                        bytes_hex: "90cccc".to_owned(),
                        mask_hex: "ffffff".to_owned(),
                    },
                    argument_abi: "self=rdi,buf=rsi,len=rdx".to_owned(),
                    layout: ProbeLayout {
                        fields: vec![FieldOffset {
                            name: "turn_id".to_owned(),
                            offset: 0x30,
                            encoding: FieldEncoding::StringPtrLenCap,
                        }],
                        self_argument: Some(0),
                        buf_argument: Some(1),
                        len_argument: Some(2),
                        out_pointer_argument: None,
                        return_tag_register: None,
                        return_len_register: None,
                        return_encoding: None,
                    },
                }],
            )]),
            evidence: vec!["synthetic".to_owned()],
        }
    }

    #[test]
    fn unvalidated_profile_fails_closed() {
        let error = resolve_attach_plan(&valid_profile(false), b"\x90\x90\xcc\xcc\xdd")
            .expect_err("must reject");
        assert_eq!(error, ProfileError::UnsupportedCodexBuild);
    }

    #[test]
    fn hash_mismatch_is_rejected() {
        let error = resolve_attach_plan(&valid_profile(true), b"\x00").expect_err("must reject");
        assert_eq!(error, ProfileError::HashMismatch);
    }

    #[test]
    fn signature_mismatch_is_rejected() {
        let mut profile = valid_profile(true);
        profile.elf_sha256 = super::hex_sha256(b"\x90\x91\xcc\xcc\xdd");
        let error =
            resolve_attach_plan(&profile, b"\x90\x91\xcc\xcc\xdd").expect_err("must reject");
        assert_eq!(
            error,
            ProfileError::SignatureMismatch("plaintext_write@0x1".to_owned())
        );
    }

    #[test]
    fn zero_offset_is_rejected() {
        let mut profile = valid_profile(true);
        profile.probes.get_mut("plaintext_write").unwrap()[0].file_offset = 0;
        let error =
            resolve_attach_plan(&profile, b"\x90\x90\xcc\xcc\xdd").expect_err("must reject");
        assert_eq!(
            error,
            ProfileError::ZeroOffset("plaintext_write".to_owned())
        );
    }

    #[test]
    fn valid_profile_resolves() {
        let plan =
            resolve_attach_plan(&valid_profile(true), b"\x90\x90\xcc\xcc\xdd").expect("valid");
        assert_eq!(plan.probes.len(), 1);
    }
}
