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
    path: PathBuf,
    policy: Arc<RwLock<RegistryPolicy>>,
    // The watcher callback holds only a weak sender, so dropping this stops the thread.
    _stop: Arc<mpsc::SyncSender<()>>,
}

impl RegistryWatcher {
    pub(crate) fn watch(
        file: &Path,
        previous: Option<&Self>,
        unchanged_path: bool,
    ) -> Result<Self> {
        // Only NotFound permits fallback; other resolution errors reject the reload.
        let file = match (policy_path(file), previous) {
            (Ok(file), _) => file,
            (Err(err), Some(previous))
                if unchanged_path && err.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(previous.clone());
            }
            (Err(err), _) => return Err(err.into()),
        };
        if let Some(previous) = previous.filter(|previous| previous.path == file) {
            return Ok(previous.clone());
        }
        Self::open(file, Duration::from_secs(60))
    }

    fn open(file: PathBuf, recovery_interval: Duration) -> Result<Self> {
        let parent = file
            .parent()
            .expect("canonical policy parent")
            .to_path_buf();
        let (stop, stopped) = mpsc::sync_channel(1);
        let stop = Arc::new(stop);
        let changes = Arc::downgrade(&stop);
        let mut watcher = RecommendedWatcher::new(
            move |event: std::result::Result<notify::Event, notify::Error>| {
                if event.as_ref().map_or(true, |event| {
                    !matches!(event.kind, notify::EventKind::Access(_))
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
        let path = file.clone();
        std::thread::Builder::new().name("registry-policy".into()).spawn(move || {
            let mut failure = None;
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
                    Ok(()) => {
                        if failure.take().is_some() {
                            info!(file = %file.display(), "registry policy recovered");
                        }
                    }
                    Err(err) => {
                        let message = err.to_string();
                        if failure.as_ref() != Some(&message) {
                            error!(file = %file.display(), error = %message, "keeping last valid registry policy");
                            failure = Some(message);
                        }
                    }
                }
            }
        })?;
        Ok(Self {
            path,
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
        for mode in ["inplace", "rename", "recreate", "case-alias"] {
            let dir = tempfile::tempdir()?;
            let parent = dir.path().join("state");
            fs::create_dir(&parent)?;
            let file = parent.join("policy.json");
            let mut policy = policy();
            fs::write(&file, serde_json::to_vec(&policy)?)?;
            let watched_file = if mode == "case-alias" {
                let alias = parent.join("POLICY.JSON");
                if !alias.exists() {
                    // A hard link also exercises alternate filenames on case-sensitive filesystems.
                    fs::hard_link(&file, &alias)?;
                }
                alias
            } else {
                file.clone()
            };
            let reader = if mode == "recreate" {
                RegistryWatcher::open(policy_path(&file)?, Duration::from_millis(50))?
            } else {
                // Notifications must beat the production 60-second recovery poll.
                RegistryWatcher::watch(&watched_file, None, false)?
            };
            for member in [None, Some("e"), Some("d")] {
                if mode == "recreate" {
                    fs::remove_file(&file)?;
                    fs::remove_dir(&parent)?;
                    // Windows may keep the directory pending deletion until recovery closes the watch.
                    let deadline = Instant::now() + Duration::from_secs(5);
                    while let Err(err) = fs::create_dir(&parent) {
                        if Instant::now() >= deadline
                            || !matches!(
                                err.kind(),
                                std::io::ErrorKind::AlreadyExists
                                    | std::io::ErrorKind::PermissionDenied
                            )
                        {
                            return Err(err.into());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
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

    #[cfg(unix)]
    #[test]
    fn reload_follows_retargeted_policy_parents() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let original = dir.path().join("original");
        let updated = dir.path().join("updated");
        let mut revoked = policy();
        revoked.members.clear();
        for (parent, policy) in [(&original, policy()), (&updated, revoked)] {
            fs::create_dir(parent)?;
            fs::write(parent.join("policy.json"), serde_json::to_vec(&policy)?)?;
        }
        let link = dir.path().join("current");
        std::os::unix::fs::symlink(&original, &link)?;
        let file = link.join("policy.json");
        let previous = RegistryWatcher::watch(&file, None, false)?;
        assert!(previous.allows(&"d".repeat(64)));
        fs::remove_file(&link)?;
        std::os::unix::fs::symlink(&updated, &link)?;
        let current = RegistryWatcher::watch(&file, Some(&previous), true)?;
        assert!(!current.allows(&"d".repeat(64)));
        assert!(previous.allows(&"d".repeat(64)));
        Ok(())
    }
}
