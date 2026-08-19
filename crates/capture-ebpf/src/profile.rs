use codexwatch_profile::ProbeProfile;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildFingerprint {
    pub executable_sha256: String,
    pub architecture: String,
    pub codex_version_hint: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedProfile {
    pub profile: ProbeProfile,
    pub verified: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachmentDecision {
    Attach(LoadedProfile),
    UnsupportedBuild(BuildFingerprint),
}

#[derive(Clone, Debug, Default)]
pub struct ProfileRegistry {
    profiles: Vec<ProbeProfile>,
}

impl ProfileRegistry {
    #[must_use]
    pub fn with_builtin_profiles() -> Self {
        let profile = include_str!("../../../profiles/codex-0.144.1-linux-x86_64.json");
        let parsed = codexwatch_profile::load_profile(profile)
            .expect("builtin codex-0.144.1 profile json must parse");
        Self {
            profiles: vec![parsed],
        }
    }

    #[must_use]
    pub fn all(&self) -> &[ProbeProfile] {
        &self.profiles
    }

    #[must_use]
    pub fn resolve(&self, fingerprint: &BuildFingerprint) -> AttachmentDecision {
        let Some(profile) = self.profiles.iter().find(|profile| {
            profile.elf_sha256 == fingerprint.executable_sha256
                && profile.architecture == fingerprint.architecture
        }) else {
            return AttachmentDecision::UnsupportedBuild(fingerprint.clone());
        };

        AttachmentDecision::Attach(LoadedProfile {
            profile: profile.clone(),
            verified: profile.validated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{AttachmentDecision, BuildFingerprint, ProfileRegistry};

    #[test]
    fn builtin_profile_is_fail_closed_until_all_sites_are_proven() {
        let registry = ProfileRegistry::with_builtin_profiles();
        let decision = registry.resolve(&BuildFingerprint {
            executable_sha256: "a96f944d1a596dbfb7fdd84f482be5c50e34b04bb371126840d873e4ebf26902"
                .into(),
            architecture: "x86_64".into(),
            codex_version_hint: Some("0.144.1".into()),
        });
        match decision {
            AttachmentDecision::Attach(profile) => assert!(!profile.verified),
            AttachmentDecision::UnsupportedBuild(_) => panic!("expected builtin profile match"),
        }
    }
}
