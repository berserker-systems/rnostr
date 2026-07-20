//! The sidecar's durable snapshot is also the relay's authorization policy.
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};

pub fn policy_path(file: &Path) -> io::Result<PathBuf> {
    let name = file
        .file_name()
        .ok_or_else(|| invalid("policy path has no filename"))?;
    let parent = file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(fs::canonicalize(parent)?.join(name))
}

pub fn policy_document(file: &Path) -> io::Result<Vec<u8>> {
    if !fs::symlink_metadata(file)?.file_type().is_file() {
        return Err(invalid("policy must be a regular file, not a symlink"));
    }
    fs::read(file)
}

/// NIP-01 replacement order: newer timestamp, then lower event ID.
pub fn compare_versions<T: Ord>(a: (u64, T), b: (u64, T)) -> Ordering {
    a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrySource {
    pub authority: String,
    pub recipient: String,
    pub event_kind: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryPolicy {
    pub source: RegistrySource,
    pub created_at: u64,
    pub event_id: String,
    pub members: BTreeSet<String>,
    #[serde(default)]
    pub extras: BTreeSet<String>,
}

impl RegistryPolicy {
    pub fn read(file: &Path) -> io::Result<Self> {
        Self::parse(&policy_document(file)?)
    }

    pub fn parse(document: &[u8]) -> io::Result<Self> {
        let policy: Self = serde_json::from_slice(document).map_err(invalid)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> io::Result<()> {
        for (field, value) in [
            ("source.authority", &self.source.authority),
            ("source.recipient", &self.source.recipient),
            ("event_id", &self.event_id),
        ]
        .into_iter()
        .chain(self.members.iter().map(|key| ("members", key)))
        .chain(self.extras.iter().map(|key| ("extras", key)))
        {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid(format!(
                    "{field} must contain lowercase 32-byte hex values"
                )));
            }
        }
        if !(30000..40000).contains(&self.source.event_kind) {
            return Err(invalid(
                "source.event_kind must be addressable (30000..40000)",
            ));
        }
        Ok(())
    }

    pub fn allows(&self, pubkey: &str) -> bool {
        self.source.authority == pubkey
            || self.source.recipient == pubkey
            || self.members.contains(pubkey)
            || self.extras.contains(pubkey)
    }
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RegistryPolicy {
        RegistryPolicy {
            source: RegistrySource {
                authority: "a".repeat(64),
                recipient: "b".repeat(64),
                event_kind: 30617,
            },
            created_at: 10,
            event_id: "c".repeat(64),
            members: ["d".repeat(64)].into(),
            extras: BTreeSet::new(),
        }
    }

    #[test]
    fn validates_the_entire_policy_and_keeps_infrastructure_allowed() {
        let policy = policy();
        policy.validate().unwrap();
        for key in ['a', 'b', 'd'] {
            assert!(policy.allows(&key.to_string().repeat(64)));
        }
        assert!(!policy.allows(&"e".repeat(64)));
        let value = serde_json::to_value(&policy).unwrap();
        for field in ["event_id", "members", "extras"] {
            let mut bad = value.clone();
            bad[field] = if field == "event_id" {
                serde_json::json!("bad")
            } else {
                serde_json::json!(["bad"])
            };
            assert!(serde_json::from_value::<RegistryPolicy>(bad)
                .unwrap()
                .validate()
                .is_err());
        }
        for field in ["source", "members", "event_id", "created_at"] {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<RegistryPolicy>(bad).is_err());
        }
    }

    #[test]
    fn replacement_order_prefers_newer_timestamps_then_lower_ids() {
        assert_eq!(compare_versions((20, "f"), (10, "a")), Ordering::Greater);
        assert_eq!(compare_versions((10, "a"), (10, "f")), Ordering::Greater);
        assert_eq!(compare_versions((10, "a"), (10, "a")), Ordering::Equal);
    }
}
