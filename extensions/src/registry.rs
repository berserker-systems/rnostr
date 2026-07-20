use allowlist_policy::{policy_document, policy_path, RegistryPolicy};
use nostr_relay::Result;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc},
    time::Duration,
};
use tracing::{error, info};

#[derive(Debug, Clone)]
pub(crate) struct RegistryWatcher {
    policy: Arc<RwLock<RegistryPolicy>>,
    // The watcher callback holds only a weak sender, so dropping this stops the thread.
    _stop: Arc<mpsc::SyncSender<()>>,
}

impl RegistryWatcher {
    pub(crate) fn watch(file: &Path) -> Result<Self> {
        Self::open(policy_path(file)?, Duration::from_secs(60))
    }

    fn open(file: PathBuf, recovery_interval: Duration) -> Result<Self> {
        let parent = file
            .parent()
            .expect("canonical policy parent")
            .to_path_buf();
        let (stop, stopped) = mpsc::sync_channel(1);
        let stop = Arc::new(stop);
        let changes = Arc::downgrade(&stop);
        let target = file.clone();
        let mut watcher = RecommendedWatcher::new(
            move |event: std::result::Result<notify::Event, notify::Error>| {
                if event.as_ref().map_or(true, |event| {
                    !matches!(event.kind, notify::EventKind::Access(_))
                        && (event.need_rescan() || event.paths.contains(&target))
                }) {
                    if let Some(changes) = changes.upgrade() {
                        let _ = changes.try_send(());
                    }
                }
            },
            notify::Config::default(),
        )?;
        watcher.watch(&parent, RecursiveMode::NonRecursive)?;
        let mut document = policy_document(&file)?;
        let policy = Arc::new(RwLock::new(RegistryPolicy::parse(&document)?));
        let current = policy.clone();
        std::thread::Builder::new().name("registry-policy".into()).spawn(move || {
            let mut failed = false;
            loop {
                match stopped.recv_timeout(recovery_interval) {
                    Ok(()) => {}
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // Reattach after directory recreation; polling also recovers lost events.
                        let _ = watcher.unwatch(&parent);
                        let _ = watcher.watch(&parent, RecursiveMode::NonRecursive);
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
                match reload(&file, &current, &mut document) {
                    Ok(()) => failed = false,
                    Err(err) => {
                        if !failed {
                            error!(file = %file.display(), error = %err, "keeping last valid registry policy");
                        }
                        failed = true;
                    }
                }
            }
        })?;
        Ok(Self {
            policy,
            _stop: stop,
        })
    }

    pub(crate) fn allows(&self, pubkey: &str) -> bool {
        self.policy.read().allows(pubkey)
    }
}

fn reload(file: &Path, policy: &RwLock<RegistryPolicy>, previous: &mut Vec<u8>) -> Result<()> {
    let document = policy_document(file)?;
    if document != *previous {
        let next = RegistryPolicy::parse(&document)?;
        let mut current = policy.write();
        if *current != next {
            *current = next;
            info!(created_at = current.created_at, "loaded registry policy");
        }
        *previous = document;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowlist_policy::RegistrySource;
    use std::{fs, time::Instant};

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
            extras: Default::default(),
        }
    }

    #[test]
    fn policy_reloads_keep_last_valid_and_accept_valid_producer_replacements() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("policy.json");
        let initial = policy();
        let policy = RwLock::new(initial.clone());
        let mut previous = serde_json::to_vec(&initial)?;
        for content in ["", "{", "{}", r#"{"members":[]}"#] {
            fs::write(&file, content)?;
            assert!(reload(&file, &policy, &mut previous).is_err());
            assert_eq!(*policy.read(), initial);
        }
        fs::remove_file(&file)?;
        assert!(reload(&file, &policy, &mut previous).is_err());
        assert_eq!(*policy.read(), initial);
        let mut revoked = initial.clone();
        revoked.created_at = 20;
        revoked.members.clear();
        fs::write(&file, serde_json::to_vec(&revoked)?)?;
        reload(&file, &policy, &mut previous)?;
        assert!(!policy.read().allows(&"d".repeat(64)));
        fs::write(&file, serde_json::to_vec(&initial)?)?;
        reload(&file, &policy, &mut previous)?;
        assert_eq!(*policy.read(), initial);
        Ok(())
    }

    #[test]
    fn notifications_apply_updates_and_recovery_handles_directory_recreation() -> Result<()> {
        for mode in ["inplace", "rename", "recreate"] {
            let dir = tempfile::tempdir()?;
            let parent = dir.path().join("state");
            fs::create_dir(&parent)?;
            let file = parent.join("policy.json");
            let mut policy = policy();
            fs::write(&file, serde_json::to_vec(&policy)?)?;
            let reader = if mode == "recreate" {
                RegistryWatcher::open(policy_path(&file)?, Duration::from_millis(50))?
            } else {
                // Notifications must beat the production 60-second recovery poll.
                RegistryWatcher::watch(&file)?
            };
            for member in [None, Some("e"), Some("d")] {
                if mode == "recreate" {
                    fs::remove_file(&file)?;
                    fs::remove_dir(&parent)?;
                    fs::create_dir(&parent)?;
                }
                policy.created_at += 1;
                policy.members = member.map(|key| key.repeat(64)).into_iter().collect();
                let destination = if mode == "rename" {
                    file.with_extension("tmp")
                } else {
                    file.clone()
                };
                fs::write(&destination, serde_json::to_vec(&policy)?)?;
                if mode == "rename" {
                    fs::rename(destination, &file)?;
                }
                let deadline = Instant::now() + Duration::from_secs(5);
                while *reader.policy.read() != policy {
                    assert!(
                        Instant::now() < deadline,
                        "policy did not refresh after {mode}: {member:?}"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(reader.allows(&"d".repeat(64)), member == Some("d"));
                assert_eq!(reader.allows(&"e".repeat(64)), member == Some("e"));
            }
        }
        Ok(())
    }
}
