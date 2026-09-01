//! allowlist-sync
//!
//! Keeps an rnostr `[auth]` pubkey allowlist in sync with the private,
//! per-recipient registry events published by shareholder-governance-registry.
//!
//! The event is selected by its trusted author, configured kind, and recipient
//! pubkey in its `d` and `p` tags. Its NIP-44 v2 content is decrypted with the
//! recipient key and decoded as a JSON array of npubs. The effective allowlist
//! is `{event author} and {decrypted shareholders} and {local extras}`. The
//! author is retained so it can keep publishing updates to the managed relay.
//! The result is written into both `[auth.req].pubkey_whitelist` (read, NIP-42)
//! and `[auth.event].event_pubkey_whitelist` (write, by author). The winning
//! event version and decrypted allowlist are stored beside the config for
//! rollback and offline drift protection.

use std::{
    cmp::Ordering,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::{fs::MetadataExt, fs::PermissionsExt, io::AsRawFd};

use anyhow::{Context, Result};
use clap::Parser;
use nostr_sdk::prelude::*;
use tempfile::NamedTempFile;
use toml_edit::{table, value, Array, DocumentMut, TableLike};
use tracing::{info, warn};

/// Default kind used by shareholder-governance-registry.
const DEFAULT_REGISTRY_EVENT_KIND: u16 = 30617;

#[derive(Parser, Debug)]
#[command(
    name = "allowlist-sync",
    about = "Sync an rnostr [auth] allowlist from encrypted shareholder registry events."
)]
struct Cli {
    /// Registry operator pubkey to trust, as npub or 64-char hex.
    #[arg(long, env = "ALLOWLIST_AUTHORITY")]
    authority: String,

    /// File containing the stable recipient nsec used to decrypt the registry.
    #[arg(long, env = "ALLOWLIST_RECIPIENT_NSEC_FILE")]
    recipient_nsec_file: PathBuf,

    /// Addressable event kind used by the registry.
    #[arg(long, env = "ALLOWLIST_EVENT_KIND", default_value_t = DEFAULT_REGISTRY_EVENT_KIND)]
    event_kind: u16,

    /// Source relay(s) to fetch the encrypted registry snapshot from (repeatable).
    #[arg(
        long = "relay",
        env = "ALLOWLIST_RELAYS",
        value_delimiter = ',',
        required = true
    )]
    relays: Vec<String>,

    /// Extra pubkey(s) to always allow, in addition to the registry set
    /// (repeatable). Accepts npub or 64-char hex.
    #[arg(
        long = "extra-pubkey",
        env = "ALLOWLIST_EXTRA_PUBKEYS",
        value_delimiter = ','
    )]
    extra_pubkeys: Vec<String>,

    /// Path to the rnostr.toml to update.
    #[arg(long, env = "ALLOWLIST_CONFIG", default_value = "./config/rnostr.toml")]
    config: PathBuf,

    /// Fetch once, update, and exit (no live subscription).
    #[arg(long)]
    once: bool,

    /// Timeout for each relay fetch.
    #[arg(long, default_value = "10s", value_parser = humantime_secs)]
    fetch_timeout: Duration,

    /// How often to refetch the latest snapshot, including after transient failures.
    #[arg(long, env = "ALLOWLIST_RESYNC_INTERVAL", default_value = "60s", value_parser = humantime_secs)]
    resync_interval: Duration,
}

fn humantime_secs(s: &str) -> Result<Duration, String> {
    // Tiny parser supporting plain seconds ("10") and "<n>s".
    let trimmed = s.trim();
    let seconds = trimmed.strip_suffix('s').unwrap_or(trimmed);
    let duration = seconds
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("invalid duration: {s} (use e.g. 10 or 10s)"))?;
    if duration.is_zero() {
        return Err("duration must be greater than zero".to_owned());
    }
    Ok(duration)
}

fn read_recipient_keys(path: &Path) -> Result<Keys> {
    #[cfg(unix)]
    {
        let mode = fs::metadata(path)
            .with_context(|| format!("cannot inspect recipient nsec file {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "recipient nsec file {} is accessible by group or others; set its mode to 0600",
                path.display()
            );
        }
    }

    let nsec = fs::read_to_string(path)
        .with_context(|| format!("cannot read recipient nsec file {}", path.display()))?;
    Keys::parse(nsec.trim())
        .with_context(|| format!("invalid recipient nsec in {}", path.display()))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let authority = PublicKey::parse(&cli.authority)
        .with_context(|| format!("invalid authority pubkey: {}", cli.authority))?;
    let recipient_keys = read_recipient_keys(&cli.recipient_nsec_file)?;
    let recipient = recipient_keys.public_key();
    if recipient != authority {
        anyhow::bail!(
            "recipient nsec {} does not belong to registry authority {}; \
             the registry's always-published self-copy requires the authority nsec",
            cli.recipient_nsec_file.display(),
            authority.to_hex()
        );
    }
    let kind = Kind::from(cli.event_kind);
    if !kind.is_addressable() {
        anyhow::bail!(
            "registry event kind {} is not in the addressable range",
            cli.event_kind
        );
    }
    let extras = parse_extra_pubkeys(&cli.extra_pubkeys)?;
    info!(
        authority = %authority.to_hex(),
        recipient = %recipient.to_hex(),
        kind = cli.event_kind,
        extras = extras.len(),
        "starting allowlist-sync"
    );

    // Use the stable recipient identity for NIP-42 too. This lets an operator
    // explicitly allow the sidecar on an authenticated source relay.
    let opts = ClientOptions::new()
        .automatic_authentication(true)
        .verify_subscriptions(true)
        .ban_relay_on_mismatch(true);
    let client = Client::builder()
        .signer(recipient_keys.clone())
        .opts(opts)
        .build();

    for relay in &cli.relays {
        client
            .add_relay(relay)
            .await
            .with_context(|| format!("failed to add relay {relay}"))?;
    }
    client.connect().await;

    let filter = Filter::new()
        .author(authority)
        .kind(kind)
        .identifier(recipient.to_hex())
        .pubkey(recipient);
    let source = RegistrySource {
        filter: &filter,
        recipient_keys: &recipient_keys,
    };

    // Persist the full NIP-01 replacement version so a stale relay cannot roll
    // the allowlist back after this process restarts.
    let version_store =
        EventVersionStore::for_config(&cli.config, authority, recipient, cli.event_kind)?;
    let mut last_applied = version_store.load()?;
    if let Some(state) = last_applied.as_ref() {
        info!(
            created_at = state.version.created_at,
            event_id = %state.version.id.to_hex(),
            count = state.allowed.len(),
            "loaded last applied registry snapshot version"
        );
    }

    // Initial sync: fetch the current snapshot and apply it. One-shot mode
    // must report a missing snapshot or fetch failure to its caller, while
    // live mode continues into its subscription and periodic retry loop.
    let initial_sync = sync_latest(
        &client,
        &source,
        cli.fetch_timeout,
        &cli.config,
        &extras,
        &version_store,
        &mut last_applied,
    )
    .await;
    handle_initial_sync_result(initial_sync, cli.once)?;

    if cli.once {
        return Ok(());
    }

    // Live mode: subscribe and re-apply whenever a newer snapshot arrives.
    // Subscribe to notifications before opening the live subscription so an
    // event cannot arrive in between those operations and be missed.
    let mut notifications = client.notifications();
    let subscription_id = client
        .subscribe(filter.clone(), None)
        .await
        .context("subscribe failed")?
        .val;
    info!("subscribed; watching for registry updates (Ctrl-C to stop)");

    let mut resync = tokio::time::interval(cli.resync_interval);
    resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first interval tick fires immediately; the initial fetch above has
    // already done that work.
    resync.tick().await;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested");
                break;
            }
            _ = resync.tick() => {
                if let Err(err) = sync_latest(
                    &client,
                    &source,
                    cli.fetch_timeout,
                    &cli.config,
                    &extras,
                    &version_store,
                    &mut last_applied,
                ).await {
                    warn!(error = %err, "periodic allowlist resync failed; will retry");
                }
            }
            notification = notifications.recv() => {
                match notification {
                    Ok(RelayPoolNotification::Event {
                        subscription_id: event_subscription,
                        event,
                        ..
                    }) if event_subscription == subscription_id => {
                        if let Err(err) = process_event(
                            &event,
                            &filter,
                            &recipient_keys,
                            &cli.config,
                            &extras,
                            &version_store,
                            &mut last_applied,
                        ) {
                            warn!(error = %err, "failed to apply registry update; periodic resync will retry");
                        }
                    }
                    Ok(RelayPoolNotification::Shutdown) => break,
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(skipped, "notification receiver lagged; refetching latest registry snapshot");
                        if let Err(err) = sync_latest(
                            &client,
                            &source,
                            cli.fetch_timeout,
                            &cli.config,
                            &extras,
                            &version_store,
                            &mut last_applied,
                        ).await {
                            warn!(error = %err, "recovery resync failed; periodic resync will retry");
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    client.shutdown().await;

    Ok(())
}

fn handle_initial_sync_result(result: Result<bool>, once: bool) -> Result<()> {
    match result {
        Ok(true) => Ok(()),
        Ok(false) if once => {
            anyhow::bail!("no matching registry event found")
        }
        Ok(false) => {
            warn!("no matching registry event found on initial fetch; will retry");
            Ok(())
        }
        Err(err) if once => Err(err).context("initial fetch failed"),
        Err(err) => {
            warn!(error = %err, "initial allowlist fetch failed; will retry");
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventVersion {
    created_at: u64,
    id: EventId,
}

impl EventVersion {
    fn new(event: &Event) -> Self {
        Self {
            created_at: event.created_at.as_secs(),
            id: event.id,
        }
    }

    fn is_newer_than(&self, current: &Self) -> bool {
        self.created_at > current.created_at
            || (self.created_at == current.created_at && self.id < current.id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AppliedEvent {
    version: EventVersion,
    allowed: Vec<String>,
}

#[derive(Debug)]
struct EventVersionStore {
    path: PathBuf,
    authority: String,
    recipient: String,
    event_kind: u16,
}

impl EventVersionStore {
    fn for_config(
        config: &Path,
        authority: PublicKey,
        recipient: PublicKey,
        event_kind: u16,
    ) -> Result<Self> {
        let resolved = fs::canonicalize(config)
            .with_context(|| format!("cannot resolve {}", config.display()))?;
        let file_name = resolved
            .file_name()
            .context("config path has no file name")?;
        let mut state_file_name = file_name.to_os_string();
        state_file_name.push(".allowlist-sync-state");

        Ok(Self {
            path: resolved.with_file_name(state_file_name),
            authority: authority.to_hex(),
            recipient: recipient.to_hex(),
            event_kind,
        })
    }

    #[cfg(test)]
    fn at(path: PathBuf, authority: PublicKey, recipient: PublicKey, event_kind: u16) -> Self {
        Self {
            path,
            authority: authority.to_hex(),
            recipient: recipient.to_hex(),
            event_kind,
        }
    }

    fn load(&self) -> Result<Option<AppliedEvent>> {
        if !self
            .path
            .try_exists()
            .with_context(|| format!("cannot inspect {}", self.path.display()))?
        {
            return Ok(None);
        }

        let raw = fs::read_to_string(&self.path)
            .with_context(|| format!("cannot read {}", self.path.display()))?;
        let doc: DocumentMut = raw
            .parse()
            .with_context(|| format!("{} is not valid TOML", self.path.display()))?;
        let string_field = |key: &str| -> Result<&str> {
            doc.get(key)
                .and_then(|item| item.as_str())
                .with_context(|| format!("missing or invalid `{key}` in {}", self.path.display()))
        };

        if doc.get("recipient").is_none() && doc.get("identifier").is_some() {
            anyhow::bail!(
                "{} uses the obsolete public-announcement state format; delete it once to start tracking private registry events",
                self.path.display()
            );
        }

        let authority = string_field("authority")?;
        let recipient = string_field("recipient")?;
        let event_kind = doc
            .get("event_kind")
            .and_then(|item| item.as_integer())
            .and_then(|kind| u16::try_from(kind).ok())
            .with_context(|| {
                format!("missing or invalid `event_kind` in {}", self.path.display())
            })?;
        if authority != self.authority
            || recipient != self.recipient
            || event_kind != self.event_kind
        {
            // Refuse rather than reset: one event address's rollback floor
            // must not be inherited by another.
            anyhow::bail!(
                "{} belongs to authority {authority} recipient {recipient} kind {event_kind}, \
                 not authority {} recipient {} kind {}; delete {} to start tracking the new registry event",
                self.path.display(),
                self.authority,
                self.recipient,
                self.event_kind,
                self.path.display()
            );
        }

        let created_at = string_field("created_at")?
            .parse::<u64>()
            .with_context(|| format!("invalid `created_at` in {}", self.path.display()))?;
        let id = EventId::parse(string_field("event_id")?)
            .with_context(|| format!("invalid `event_id` in {}", self.path.display()))?;

        let allowed_values = doc
            .get("allowed")
            .and_then(|item| item.as_array())
            .with_context(|| format!("missing or invalid `allowed` in {}", self.path.display()))?;
        let mut allowed = std::collections::BTreeSet::new();
        for value in allowed_values {
            let raw = value.as_str().with_context(|| {
                format!("non-string `allowed` value in {}", self.path.display())
            })?;
            let pubkey = PublicKey::parse(raw)
                .with_context(|| format!("invalid `allowed` pubkey in {}", self.path.display()))?;
            allowed.insert(pubkey.to_hex());
        }
        if allowed.is_empty() {
            anyhow::bail!("empty `allowed` list in {}", self.path.display());
        }

        Ok(Some(AppliedEvent {
            version: EventVersion { created_at, id },
            allowed: allowed.into_iter().collect(),
        }))
    }

    fn persist(&self, state: &AppliedEvent) -> Result<()> {
        let mut doc = DocumentMut::new();
        let root = doc.as_table_mut();
        root.insert("authority", value(self.authority.as_str()));
        root.insert("recipient", value(self.recipient.as_str()));
        root.insert("event_kind", value(i64::from(self.event_kind)));
        root.insert("created_at", value(state.version.created_at.to_string()));
        root.insert("event_id", value(state.version.id.to_hex()));
        root.insert("allowed", value(hex_array(&state.allowed)));

        let parent = self
            .path
            .parent()
            .context("version-state path has no parent directory")?;
        let mut tmp = NamedTempFile::new_in(parent).with_context(|| {
            format!(
                "cannot create temporary version state in {}",
                parent.display()
            )
        })?;
        tmp.write_all(doc.to_string().as_bytes()).with_context(|| {
            format!(
                "cannot write temporary version state in {}",
                parent.display()
            )
        })?;
        tmp.as_file()
            .sync_all()
            .context("cannot flush temporary version state")?;
        tmp.persist(&self.path)
            .map_err(|err| err.error)
            .with_context(|| format!("cannot replace {}", self.path.display()))?;

        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .with_context(|| {
                format!("cannot flush version-state directory {}", parent.display())
            })?;
        Ok(())
    }
}

struct RegistrySource<'a> {
    filter: &'a Filter,
    recipient_keys: &'a Keys,
}

async fn sync_latest(
    client: &Client,
    source: &RegistrySource<'_>,
    timeout: Duration,
    config: &Path,
    extras: &[String],
    version_store: &EventVersionStore,
    last_applied: &mut Option<AppliedEvent>,
) -> Result<bool> {
    reconcile_config(config, extras, last_applied.as_ref())?;

    let events = client
        .fetch_events(source.filter.clone(), timeout)
        .await
        .context("fetch failed")?;
    let Some(event) = latest_event(events) else {
        return Ok(false);
    };
    process_event(
        &event,
        source.filter,
        source.recipient_keys,
        config,
        extras,
        version_store,
        last_applied,
    )?;
    Ok(true)
}

fn reconcile_config(
    config: &Path,
    extras: &[String],
    current: Option<&AppliedEvent>,
) -> Result<()> {
    let Some(current) = current else {
        return Ok(());
    };

    let effective = union_allowed(&current.allowed, extras);
    if apply_to_config(config, &effective)
        .with_context(|| format!("failed to reconcile {}", config.display()))?
    {
        info!(
            count = effective.len(),
            "restored persisted allowlist in {}",
            config.display()
        );
    }
    Ok(())
}

fn latest_event<I>(events: I) -> Option<Event>
where
    I: IntoIterator<Item = Event>,
{
    events.into_iter().max_by(compare_event_versions)
}

fn compare_event_versions(a: &Event, b: &Event) -> Ordering {
    a.created_at
        .cmp(&b.created_at)
        // NIP-01: the lower id wins when replaceable events have equal timestamps.
        .then_with(|| b.id.cmp(&a.id))
}

/// Apply a registry snapshot unless it is older than the persisted winner. Applying
/// the current winner again is intentional so config drift is repaired.
fn process_event(
    event: &Event,
    filter: &Filter,
    recipient_keys: &Keys,
    config: &Path,
    extras: &[String],
    version_store: &EventVersionStore,
    last_applied: &mut Option<AppliedEvent>,
) -> Result<()> {
    // Defense in depth: nostr-sdk verifies subscriptions above, but never let
    // an unrelated notification reach this security-sensitive write path.
    if !filter.match_event(event, MatchEventOptions::new()) {
        anyhow::bail!(
            "event {} does not match the configured authority/recipient",
            event.id
        );
    }

    let version = EventVersion::new(event);
    let mut persist_state = true;
    if let Some(current) = last_applied.as_ref() {
        if version == current.version {
            // Reconcile the config even for the same event. This repairs drift
            // without rewriting when the file is already correct.
            persist_state = false;
        } else if !version.is_newer_than(&current.version) {
            return Ok(());
        }
    }

    let allowed = decrypt_allowed(event, recipient_keys)?;

    let state = AppliedEvent { version, allowed };
    if persist_state {
        // Commit the version first. If the config write then fails or the
        // process crashes, the same version is still eligible for an
        // idempotent retry, while older versions remain rejected.
        version_store.persist(&state)?;
        *last_applied = Some(state.clone());
    }

    let effective = union_allowed(&state.allowed, extras);
    let changed = apply_to_config(config, &effective)
        .with_context(|| format!("failed to update {}", config.display()))?;
    if changed {
        info!(
            count = effective.len(),
            "updated allowlist in {}",
            config.display()
        );
    } else {
        info!(
            count = effective.len(),
            "allowlist already up to date; no write"
        );
    }
    Ok(())
}

/// Parse and normalize the locally configured always-allowed operator pubkeys.
fn parse_extra_pubkeys(raw: &[String]) -> Result<Vec<String>> {
    let mut set = std::collections::BTreeSet::new();
    for candidate in raw {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        let pubkey = PublicKey::parse(trimmed)
            .with_context(|| format!("invalid extra pubkey: {trimmed}"))?;
        set.insert(pubkey.to_hex());
    }
    Ok(set.into_iter().collect())
}

/// Overlay the locally configured extras on top of the registry set. Extras
/// are applied at write time only, so they are never persisted as registry
/// data.
fn union_allowed(registry: &[String], extras: &[String]) -> Vec<String> {
    if extras.is_empty() {
        return registry.to_vec();
    }
    let set: std::collections::BTreeSet<&str> = registry
        .iter()
        .chain(extras.iter())
        .map(String::as_str)
        .collect();
    set.into_iter().map(str::to_owned).collect()
}

/// Decrypt the registry snapshot and return author and shareholders as sorted,
/// deduplicated hex pubkeys. The author stays allowed so it can publish the
/// next snapshot to the managed relay even when it owns no shares itself.
fn decrypt_allowed(event: &Event, recipient_keys: &Keys) -> Result<Vec<String>> {
    let plaintext = nip44::decrypt(recipient_keys.secret_key(), &event.pubkey, &event.content)
        .with_context(|| format!("cannot decrypt registry event {}", event.id))?;
    let shareholders: Vec<String> = serde_json::from_str(&plaintext)
        .with_context(|| format!("registry event {} is not a JSON pubkey array", event.id))?;

    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    set.insert(event.pubkey.to_hex());
    for raw in shareholders {
        let pubkey = PublicKey::parse(&raw).with_context(|| {
            format!(
                "registry event {} contains invalid pubkey {raw:?}",
                event.id
            )
        })?;
        set.insert(pubkey.to_hex());
    }

    Ok(set.into_iter().collect())
}

/// Surgically set `[auth].enabled = true` and both whitelists to `hexes`,
/// preserving all other config and comments. Writes atomically (temp + rename)
/// and only when the rendered document actually changes.
///
/// Returns `true` if the file was rewritten.
fn apply_to_config(config: &Path, hexes: &[String]) -> Result<bool> {
    // Resolve symlinks before creating/replacing the sibling file. This keeps
    // deployment-managed config symlinks intact and updates the file rnostr's
    // watcher canonicalized at startup.
    let resolved =
        fs::canonicalize(config).with_context(|| format!("cannot resolve {}", config.display()))?;
    let original = fs::read_to_string(&resolved)
        .with_context(|| format!("cannot read {}", config.display()))?;
    let mut doc: DocumentMut = original
        .parse()
        .with_context(|| format!("{} is not valid TOML", config.display()))?;

    let root = doc.as_table_mut();
    let auth = ensure_table(root, "auth")?;
    auth.insert("enabled", value(true));

    let req = ensure_table(auth, "req")?;
    req.insert("pubkey_whitelist", value(hex_array(hexes)));

    let event_tbl = ensure_table(auth, "event")?;
    event_tbl.insert("event_pubkey_whitelist", value(hex_array(hexes)));
    // This waives the author check for events that `p`-tag an allowlisted
    // pubkey. Those pubkeys are public, so leaving it on makes the whitelist
    // written above a no-op for writes.
    if event_tbl
        .get("allow_mentioning_whitelisted_pubkeys")
        .and_then(|item| item.as_bool())
        == Some(true)
    {
        warn!(
            "disabling `allow_mentioning_whitelisted_pubkeys` in [auth.event]: it bypasses the event author allowlist"
        );
    }
    event_tbl.insert("allow_mentioning_whitelisted_pubkeys", value(false));

    let rendered = doc.to_string();
    if rendered == original {
        return Ok(false);
    }

    let parent = resolved
        .parent()
        .context("config path has no parent directory")?;
    let metadata = fs::metadata(&resolved)
        .with_context(|| format!("cannot inspect {}", resolved.display()))?;
    let mut tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create temporary config in {}", parent.display()))?;
    tmp.write_all(rendered.as_bytes())
        .with_context(|| format!("cannot write temporary config in {}", parent.display()))?;
    preserve_metadata(&resolved, &tmp, &metadata)?;
    // Flush after applying ownership, permissions, and xattrs so both the
    // rendered config and its metadata are durable before the rename.
    tmp.as_file()
        .sync_all()
        .context("cannot flush temporary config")?;
    tmp.persist(&resolved)
        .map_err(|err| err.error)
        .with_context(|| format!("cannot replace {}", resolved.display()))?;

    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("cannot flush config directory {}", parent.display()))?;
    Ok(true)
}

fn preserve_metadata(source: &Path, tmp: &NamedTempFile, metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        let temp_metadata = tmp.as_file().metadata()?;
        if temp_metadata.uid() != metadata.uid() || temp_metadata.gid() != metadata.gid() {
            // Refuse to replace the original if its ownership cannot be
            // retained; silently widening access would be unsafe.
            let result =
                unsafe { libc::fchown(tmp.as_file().as_raw_fd(), metadata.uid(), metadata.gid()) };
            if result != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("cannot preserve config ownership");
            }
        }
    }

    tmp.as_file()
        .set_permissions(metadata.permissions())
        .context("cannot preserve config permissions")?;

    #[cfg(unix)]
    preserve_xattrs(source, tmp.path())?;

    Ok(())
}

#[cfg(unix)]
fn preserve_xattrs(source: &Path, destination: &Path) -> Result<()> {
    let names = match xattr::list(source) {
        Ok(names) => names,
        // A config on a filesystem without xattr support has no attributes to
        // preserve. Do not make an otherwise-safe atomic update impossible.
        Err(err) if xattrs_unsupported(&err) => return Ok(()),
        Err(err) => return Err(err).context("cannot list config extended attributes"),
    };

    for name in names {
        let Some(value) =
            xattr::get(source, &name).context("cannot read config extended attribute")?
        else {
            continue;
        };

        // Security labels are commonly inherited when the temporary file is
        // created in the same directory, but an unprivileged process may not
        // be allowed to set them explicitly. Avoid the unnecessary set when
        // the destination already has the correct value.
        if xattr::get(destination, &name)
            .context("cannot read temporary config extended attribute")?
            .as_deref()
            == Some(value.as_slice())
        {
            continue;
        }

        xattr::set(destination, &name, &value)
            .context("cannot preserve config extended attribute")?;
    }

    Ok(())
}

#[cfg(unix)]
fn xattrs_unsupported(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::Unsupported
        || err
            .raw_os_error()
            .is_some_and(|code| code == libc::ENOTSUP || code == libc::EOPNOTSUPP)
}

fn ensure_table<'a>(parent: &'a mut dyn TableLike, key: &str) -> Result<&'a mut dyn TableLike> {
    if !parent.contains_key(key) {
        parent.insert(key, table());
    }

    let item = parent.get_mut(key).expect("just-inserted table");
    let item_type = item.type_name();
    item.as_table_like_mut()
        .with_context(|| format!("`{key}` must be a table, found {item_type}"))
}

fn hex_array(hexes: &[String]) -> Array {
    let mut arr = Array::new();
    for h in hexes {
        arr.push(h.as_str());
    }
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    const PK_A: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const PK_B: &str = "0000000000000000000000000000000000000000000000000000000000000002";
    const PK_C: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const NO_EXTRAS: &[String] = &[];

    fn recipient_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000004").unwrap()
    }

    fn write_tmp(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("allowlist-sync-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    fn encrypted_registry_event(keys: &Keys, created_at: Timestamp, content: &str) -> Event {
        let recipient = recipient_keys();
        let cipher = nip44::encrypt(
            keys.secret_key(),
            &recipient.public_key(),
            content,
            nip44::Version::V2,
        )
        .unwrap();
        EventBuilder::new(Kind::from(DEFAULT_REGISTRY_EVENT_KIND), cipher)
            .tags([
                Tag::identifier(recipient.public_key().to_hex()),
                Tag::public_key(recipient.public_key()),
            ])
            .custom_created_at(created_at)
            .sign_with_keys(keys)
            .unwrap()
    }

    fn registry_snapshot(keys: &Keys, created_at: Timestamp, shareholders: &[&str]) -> Event {
        let payload = serde_json::to_string(shareholders).unwrap();
        encrypted_registry_event(keys, created_at, &payload)
    }

    fn registry_filter(keys: &Keys) -> Filter {
        let recipient = recipient_keys().public_key();
        Filter::new()
            .author(keys.public_key())
            .kind(Kind::from(DEFAULT_REGISTRY_EVENT_KIND))
            .identifier(recipient.to_hex())
            .pubkey(recipient)
    }

    fn version_store(config: &Path, keys: &Keys) -> EventVersionStore {
        EventVersionStore::at(
            config.with_extension("allowlist-sync-state"),
            keys.public_key(),
            recipient_keys().public_key(),
            DEFAULT_REGISTRY_EVENT_KIND,
        )
    }

    #[test]
    fn updates_whitelists_and_preserves_other_sections() {
        let path = write_tmp(
            "preserve.toml",
            r#"[network]
host = "127.0.0.1"
port = 8080

[auth]
enabled = false

[auth.req]
pubkey_whitelist = []

[auth.event]
event_pubkey_whitelist = []
"#,
        );

        let hexes = vec![PK_A.to_string(), PK_B.to_string()];
        let changed = apply_to_config(&path, &hexes).unwrap();
        assert!(changed);

        let out = std::fs::read_to_string(&path).unwrap();
        let doc: DocumentMut = out.parse().unwrap();

        // Other sections untouched.
        assert_eq!(doc["network"]["port"].as_integer(), Some(8080));
        // enabled flipped on.
        assert_eq!(doc["auth"]["enabled"].as_bool(), Some(true));
        // Both whitelists populated with the same set.
        for path_keys in [
            ["req", "pubkey_whitelist"],
            ["event", "event_pubkey_whitelist"],
        ] {
            let arr = doc["auth"][path_keys[0]][path_keys[1]].as_array().unwrap();
            let got: Vec<_> = arr.iter().map(|v| v.as_str().unwrap()).collect();
            assert_eq!(got, vec![PK_A, PK_B]);
        }
    }

    #[test]
    fn creates_missing_auth_tables() {
        let path = write_tmp("create.toml", "[network]\nport = 9000\n");
        let hexes = vec![PK_A.to_string()];
        assert!(apply_to_config(&path, &hexes).unwrap());

        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(doc["auth"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            doc["auth"]["req"]["pubkey_whitelist"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        // Untouched section survives.
        assert_eq!(doc["network"]["port"].as_integer(), Some(9000));
    }

    #[test]
    fn preserves_inline_auth_tables_and_existing_permissions() {
        let path = write_tmp(
            "inline.toml",
            &format!(
                r#"auth = {{ enabled = false, custom = "keep", req = {{ ip_blacklist = ["127.0.0.1"], pubkey_whitelist = [] }}, event = {{ event_pubkey_blacklist = ["{PK_B}"], allow_mentioning_whitelisted_pubkeys = true }} }}
"#
            ),
        );

        assert!(apply_to_config(&path, &[PK_A.to_owned()]).unwrap());

        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.starts_with("auth = {"));
        let doc: DocumentMut = out.parse().unwrap();
        assert_eq!(doc["auth"]["custom"].as_str(), Some("keep"));
        assert_eq!(
            doc["auth"]["req"]["ip_blacklist"][0].as_str(),
            Some("127.0.0.1")
        );
        assert_eq!(
            doc["auth"]["event"]["event_pubkey_blacklist"][0].as_str(),
            Some(PK_B)
        );
        // Deliberately not preserved; see `disables_mentioning_bypass`.
        assert_eq!(
            doc["auth"]["event"]["allow_mentioning_whitelisted_pubkeys"].as_bool(),
            Some(false)
        );
        assert_eq!(
            doc["auth"]["req"]["pubkey_whitelist"][0].as_str(),
            Some(PK_A)
        );
        assert_eq!(
            doc["auth"]["event"]["event_pubkey_whitelist"][0].as_str(),
            Some(PK_A)
        );
    }

    #[test]
    fn rejects_non_table_auth_without_rewriting() {
        let path = write_tmp("invalid-auth-type.toml", "auth = \"invalid\"\n");
        let before = std::fs::read_to_string(&path).unwrap();

        let err = apply_to_config(&path, &[PK_A.to_owned()]).unwrap_err();

        assert!(err.to_string().contains("`auth` must be a table"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn disables_mentioning_bypass() {
        let enabled = "[auth.event]\nallow_mentioning_whitelisted_pubkeys = true\n";
        let path = write_tmp("mentioning.toml", enabled);

        assert!(apply_to_config(&path, &[PK_A.to_owned()]).unwrap());
        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(
            doc["auth"]["event"]["allow_mentioning_whitelisted_pubkeys"].as_bool(),
            Some(false)
        );

        // Re-enabling it out of band is reverted by the next apply.
        std::fs::write(&path, enabled).unwrap();
        assert!(apply_to_config(&path, &[PK_A.to_owned()]).unwrap());
        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(
            doc["auth"]["event"]["allow_mentioning_whitelisted_pubkeys"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn idempotent_no_rewrite_when_unchanged() {
        let path = write_tmp("idem.toml", "[auth]\nenabled = false\n");
        let hexes = vec![PK_A.to_string()];
        assert!(apply_to_config(&path, &hexes).unwrap());
        // Second apply with the same set must report no change.
        assert!(!apply_to_config(&path, &hexes).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replace_preserves_permissions_ownership_and_xattrs() {
        let path = write_tmp("metadata.toml", "[auth]\nenabled = false\n");
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&path, permissions).unwrap();
        let before = std::fs::metadata(&path).unwrap();

        let xattr_name = "user.allowlist-sync-test";
        let xattr_supported = xattr::set(&path, xattr_name, b"preserved").is_ok();
        assert!(apply_to_config(&path, &[PK_A.to_owned()]).unwrap());

        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
        assert_eq!(after.uid(), before.uid());
        assert_eq!(after.gid(), before.gid());
        if xattr_supported {
            assert_eq!(
                xattr::get(&path, xattr_name).unwrap().as_deref(),
                Some(b"preserved".as_slice())
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn recognizes_filesystems_without_xattr_support() {
        let unsupported = std::io::Error::from_raw_os_error(libc::ENOTSUP);
        assert!(xattrs_unsupported(&unsupported));

        let permission_denied = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(!xattrs_unsupported(&permission_denied));
    }

    #[cfg(unix)]
    #[test]
    fn updates_symlink_target_without_replacing_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.toml");
        let link = dir.path().join("rnostr.toml");
        std::fs::write(&target, "[auth]\nenabled = false\n").unwrap();
        symlink(&target, &link).unwrap();

        assert!(apply_to_config(&link, &[PK_A.to_owned()]).unwrap());
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let doc: DocumentMut = std::fs::read_to_string(&target).unwrap().parse().unwrap();
        assert_eq!(doc["auth"]["enabled"].as_bool(), Some(true));
    }

    #[test]
    fn decrypt_allowed_unions_author_and_shareholders() {
        let authority = Keys::generate();
        let shareholder_a = PublicKey::parse(PK_A).unwrap().to_bech32().unwrap();
        let shareholder_b = PublicKey::parse(PK_B).unwrap().to_bech32().unwrap();
        let event = registry_snapshot(
            &authority,
            Timestamp::from(10),
            &[&shareholder_a, &shareholder_b],
        );

        let allowed = decrypt_allowed(&event, &recipient_keys()).unwrap();
        let author_hex = authority.public_key().to_hex();
        assert!(allowed.contains(&author_hex));
        assert!(allowed.contains(&PK_A.to_string()));
        assert!(allowed.contains(&PK_B.to_string()));
        // Sorted + deduped.
        let mut sorted = allowed.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(allowed, sorted);
    }

    #[test]
    fn decrypt_allowed_keeps_author_for_an_empty_registry() {
        let authority = Keys::generate();
        let event = registry_snapshot(&authority, Timestamp::from(10), &[]);
        assert_eq!(
            decrypt_allowed(&event, &recipient_keys()).unwrap(),
            vec![authority.public_key().to_hex()]
        );
    }

    #[test]
    fn decrypt_allowed_rejects_wrong_recipient_and_invalid_payload() {
        let authority = Keys::generate();
        let valid = registry_snapshot(&authority, Timestamp::from(10), &[PK_A]);
        assert!(decrypt_allowed(&valid, &Keys::generate()).is_err());

        let malformed = encrypted_registry_event(&authority, Timestamp::from(11), "not json");
        assert!(decrypt_allowed(&malformed, &recipient_keys()).is_err());

        let invalid_pubkey = registry_snapshot(&authority, Timestamp::from(12), &["not-a-pubkey"]);
        assert!(decrypt_allowed(&invalid_pubkey, &recipient_keys()).is_err());
    }

    #[test]
    fn rejects_event_that_does_not_match_trusted_filter() {
        let authority = Keys::generate();
        let attacker = Keys::generate();
        let filter = registry_filter(&authority);
        let event = encrypted_registry_event(&attacker, Timestamp::from(10), "[]");
        let store = EventVersionStore::at(
            PathBuf::from("unused-for-rejected-events.state"),
            authority.public_key(),
            recipient_keys().public_key(),
            DEFAULT_REGISTRY_EVENT_KIND,
        );
        let mut last_applied = None;

        let err = process_event(
            &event,
            &filter,
            &recipient_keys(),
            Path::new("unused-for-rejected-events"),
            NO_EXTRAS,
            &store,
            &mut last_applied,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match"));
        assert!(last_applied.is_none());
    }

    #[test]
    fn lower_id_wins_equal_timestamp_tie() {
        let keys = Keys::generate();
        let timestamp = Timestamp::from(10);
        let first = encrypted_registry_event(&keys, timestamp, "first");
        let second = encrypted_registry_event(&keys, timestamp, "second");
        let expected = std::cmp::min(first.id, second.id);

        let latest = latest_event([first, second]).unwrap();
        assert_eq!(latest.id, expected);
    }

    #[test]
    fn obsolete_public_announcement_state_requires_one_time_removal() {
        let authority = Keys::generate();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("allowlist-sync.state");
        std::fs::write(
            &path,
            format!(
                "authority = {:?}\nidentifier = \"old-repository\"\n",
                authority.public_key().to_hex()
            ),
        )
        .unwrap();
        let store = EventVersionStore::at(
            path,
            authority.public_key(),
            recipient_keys().public_key(),
            DEFAULT_REGISTRY_EVENT_KIND,
        );

        assert!(store.load().unwrap_err().to_string().contains("obsolete"));
    }

    #[test]
    fn persisted_state_repairs_failed_config_without_refetch() {
        let keys = Keys::generate();
        let filter = registry_filter(&keys);
        let event = registry_snapshot(&keys, Timestamp::from(10), &[]);
        let path = write_tmp("retry.toml", "not valid toml = [");
        let store = version_store(&path, &keys);
        let mut last_applied = None;

        assert!(process_event(
            &event,
            &filter,
            &recipient_keys(),
            &path,
            NO_EXTRAS,
            &store,
            &mut last_applied,
        )
        .is_err());
        assert_eq!(
            last_applied.as_ref().map(|state| state.version.clone()),
            Some(EventVersion::new(&event))
        );
        assert_eq!(store.load().unwrap(), last_applied);

        std::fs::write(&path, "[auth]\nenabled = false\n").unwrap();
        let after_restart = store.load().unwrap();
        reconcile_config(&path, NO_EXTRAS, after_restart.as_ref()).unwrap();

        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(doc["auth"]["enabled"].as_bool(), Some(true));
    }

    #[test]
    fn same_event_repairs_config_drift() {
        let keys = Keys::generate();
        let filter = registry_filter(&keys);
        let event = registry_snapshot(&keys, Timestamp::from(10), &[PK_A]);
        let path = write_tmp("drift.toml", "[auth]\nenabled = false\n");
        let store = version_store(&path, &keys);
        let mut last_applied = None;

        process_event(
            &event,
            &filter,
            &recipient_keys(),
            &path,
            NO_EXTRAS,
            &store,
            &mut last_applied,
        )
        .unwrap();
        std::fs::write(&path, "[auth]\nenabled = false\n").unwrap();

        process_event(
            &event,
            &filter,
            &recipient_keys(),
            &path,
            NO_EXTRAS,
            &store,
            &mut last_applied,
        )
        .unwrap();

        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        assert_eq!(doc["auth"]["enabled"].as_bool(), Some(true));
        let req = doc["auth"]["req"]["pubkey_whitelist"].as_array().unwrap();
        assert!(req.iter().any(|value| value.as_str() == Some(PK_A)));
    }

    #[test]
    fn persisted_version_rejects_stale_event_after_restart() {
        let keys = Keys::generate();
        let filter = registry_filter(&keys);
        let stale = registry_snapshot(&keys, Timestamp::from(10), &[PK_A]);
        let current = registry_snapshot(&keys, Timestamp::from(20), &[PK_B]);
        let path = write_tmp("rollback.toml", "[auth]\nenabled = false\n");
        let store = version_store(&path, &keys);
        let mut last_applied = None;

        process_event(
            &current,
            &filter,
            &recipient_keys(),
            &path,
            NO_EXTRAS,
            &store,
            &mut last_applied,
        )
        .unwrap();

        let mut after_restart = store.load().unwrap();
        process_event(
            &stale,
            &filter,
            &recipient_keys(),
            &path,
            NO_EXTRAS,
            &store,
            &mut after_restart,
        )
        .unwrap();

        assert_eq!(
            after_restart.as_ref().map(|state| state.version.clone()),
            Some(EventVersion::new(&current))
        );
        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        let req = doc["auth"]["req"]["pubkey_whitelist"].as_array().unwrap();
        assert!(req.iter().any(|value| value.as_str() == Some(PK_B)));
        assert!(!req.iter().any(|value| value.as_str() == Some(PK_A)));
    }

    #[test]
    fn extra_pubkeys_are_normalized_deduped_and_validated() {
        let keys = Keys::generate();
        let npub = keys.public_key().to_bech32().unwrap();

        let parsed = parse_extra_pubkeys(&[
            PK_B.to_owned(),
            npub,
            PK_B.to_owned(),
            "  ".to_owned(),
            PK_A.to_owned(),
        ])
        .unwrap();
        assert_eq!(
            parsed,
            vec![PK_A.to_owned(), PK_B.to_owned(), keys.public_key().to_hex()]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );

        let err = parse_extra_pubkeys(&["not-a-pubkey".to_owned()]).unwrap_err();
        assert!(err.to_string().contains("invalid extra pubkey"));
    }

    #[test]
    fn extras_are_written_to_config_but_not_persisted_as_registry_data() {
        let keys = Keys::generate();
        let filter = registry_filter(&keys);
        let event = registry_snapshot(&keys, Timestamp::from(10), &[PK_A]);
        let path = write_tmp("extras.toml", "[auth]\nenabled = false\n");
        let store = version_store(&path, &keys);
        let extras = vec![PK_C.to_owned()];
        let mut last_applied = None;

        process_event(
            &event,
            &filter,
            &recipient_keys(),
            &path,
            &extras,
            &store,
            &mut last_applied,
        )
        .unwrap();

        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        for whitelist in [
            &doc["auth"]["req"]["pubkey_whitelist"],
            &doc["auth"]["event"]["event_pubkey_whitelist"],
        ] {
            let got: Vec<_> = whitelist
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect();
            assert!(got.contains(&PK_A.to_owned()));
            assert!(got.contains(&keys.public_key().to_hex()));
            assert!(got.contains(&PK_C.to_owned()));
        }

        // The state file records only what the authority announced.
        let persisted = store.load().unwrap().unwrap();
        assert!(!persisted.allowed.contains(&PK_C.to_owned()));
        assert_eq!(last_applied.unwrap().allowed, persisted.allowed);
    }

    #[test]
    fn changed_extras_apply_offline_from_persisted_state() {
        let keys = Keys::generate();
        let filter = registry_filter(&keys);
        let event = registry_snapshot(&keys, Timestamp::from(10), &[PK_A]);
        let path = write_tmp("extras-offline.toml", "[auth]\nenabled = false\n");
        let store = version_store(&path, &keys);
        let mut last_applied = None;

        process_event(
            &event,
            &filter,
            &recipient_keys(),
            &path,
            NO_EXTRAS,
            &store,
            &mut last_applied,
        )
        .unwrap();

        // Restart with a new extra key and no relay reachable: reconciling the
        // persisted registry snapshot must still pick the new extra up.
        let after_restart = store.load().unwrap();
        reconcile_config(&path, &[PK_C.to_owned()], after_restart.as_ref()).unwrap();

        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        let req = doc["auth"]["req"]["pubkey_whitelist"].as_array().unwrap();
        assert!(req.iter().any(|value| value.as_str() == Some(PK_C)));
        assert!(req.iter().any(|value| value.as_str() == Some(PK_A)));
    }

    #[test]
    fn removed_extras_are_dropped_on_the_next_write() {
        let keys = Keys::generate();
        let filter = registry_filter(&keys);
        let event = registry_snapshot(&keys, Timestamp::from(10), &[PK_A]);
        let path = write_tmp("extras-removed.toml", "[auth]\nenabled = false\n");
        let store = version_store(&path, &keys);
        let mut last_applied = None;

        let extras = vec![PK_C.to_owned()];
        process_event(
            &event,
            &filter,
            &recipient_keys(),
            &path,
            &extras,
            &store,
            &mut last_applied,
        )
        .unwrap();
        // Same event, extras dropped from the command line.
        process_event(
            &event,
            &filter,
            &recipient_keys(),
            &path,
            NO_EXTRAS,
            &store,
            &mut last_applied,
        )
        .unwrap();

        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        let req = doc["auth"]["req"]["pubkey_whitelist"].as_array().unwrap();
        assert!(!req.iter().any(|value| value.as_str() == Some(PK_C)));
        assert!(req.iter().any(|value| value.as_str() == Some(PK_A)));
    }

    #[test]
    fn extras_survive_a_superseding_snapshot() {
        let keys = Keys::generate();
        let filter = registry_filter(&keys);
        let first = registry_snapshot(&keys, Timestamp::from(10), &[PK_A]);
        let second = registry_snapshot(&keys, Timestamp::from(20), &[PK_B]);
        let path = write_tmp("extras-superseded.toml", "[auth]\nenabled = false\n");
        let store = version_store(&path, &keys);
        let extras = vec![PK_C.to_owned()];
        let mut last_applied = None;

        process_event(
            &first,
            &filter,
            &recipient_keys(),
            &path,
            &extras,
            &store,
            &mut last_applied,
        )
        .unwrap();
        process_event(
            &second,
            &filter,
            &recipient_keys(),
            &path,
            &extras,
            &store,
            &mut last_applied,
        )
        .unwrap();

        let doc: DocumentMut = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        let req = doc["auth"]["req"]["pubkey_whitelist"].as_array().unwrap();
        // The newer snapshot replaces the shareholder it dropped, but the
        // locally configured extra is not the authority's to revoke.
        assert!(req.iter().any(|value| value.as_str() == Some(PK_B)));
        assert!(!req.iter().any(|value| value.as_str() == Some(PK_A)));
        assert!(req.iter().any(|value| value.as_str() == Some(PK_C)));

        // Still absent from the state file, which tracks only the registry snapshot.
        let persisted = store.load().unwrap().unwrap();
        assert_eq!(persisted.version, EventVersion::new(&second));
        assert!(!persisted.allowed.contains(&PK_C.to_owned()));
    }

    #[test]
    fn duration_parser_rejects_zero_and_malformed_suffixes() {
        assert_eq!(humantime_secs("10s").unwrap(), Duration::from_secs(10));
        assert!(humantime_secs("0s").is_err());
        assert!(humantime_secs("10ss").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn recipient_nsec_file_must_be_private() {
        let keys = Keys::generate();
        let path = write_tmp(
            "recipient.nsec",
            &format!("{}\n", keys.secret_key().to_bech32().unwrap()),
        );

        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&path, permissions).unwrap();
        assert!(read_recipient_keys(&path)
            .unwrap_err()
            .to_string()
            .contains("mode to 0600"));

        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&path, permissions).unwrap();
        assert_eq!(
            read_recipient_keys(&path).unwrap().public_key(),
            keys.public_key()
        );
    }

    #[test]
    fn one_shot_requires_a_registry_event() {
        assert!(handle_initial_sync_result(Ok(true), true).is_ok());

        let err = handle_initial_sync_result(Ok(false), true).unwrap_err();
        assert!(err.to_string().contains("no matching registry event"));
    }

    #[test]
    fn live_mode_defers_initial_failures_to_retry_loop() {
        assert!(handle_initial_sync_result(Ok(false), false).is_ok());
        assert!(handle_initial_sync_result(Err(anyhow::anyhow!("offline")), false).is_ok());

        let err = handle_initial_sync_result(Err(anyhow::anyhow!("offline")), true).unwrap_err();
        assert_eq!(format!("{err:#}"), "initial fetch failed: offline");
    }
}
