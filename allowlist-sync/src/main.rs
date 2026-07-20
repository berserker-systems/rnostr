use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::{BTreeSet, HashMap},
    fs,
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use allowlist_policy::{compare_versions, policy_document, RegistryPolicy, RegistrySource};
use anyhow::{Context, Result};
use clap::Parser;
use nostr_sdk::prelude::*;
use tempfile::NamedTempFile;
use tracing::{debug, info, warn};

const DEFAULT_REGISTRY_EVENT_KIND: u16 = 30617;
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(5);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
const MAX_SNAPSHOT_CLOCK_SKEW: u64 = 15 * 60;

#[derive(Parser, Debug)]
#[command(
    name = "allowlist-sync",
    about = "Publish an rnostr authorization policy from encrypted registry events."
)]
struct Cli {
    /// Registry operator pubkey to trust, as npub or 64-char hex.
    #[arg(long, env = "ALLOWLIST_AUTHORITY")]
    authority: String,

    /// File containing the dedicated sync recipient nsec.
    #[arg(long, env = "ALLOWLIST_RECIPIENT_NSEC_FILE")]
    recipient_nsec_file: PathBuf,

    /// Addressable event kind used by the registry.
    #[arg(long, env = "ALLOWLIST_EVENT_KIND", default_value_t = DEFAULT_REGISTRY_EVENT_KIND)]
    event_kind: u16,

    /// Source relays requiring NIP-42 authentication (repeatable).
    #[arg(
        long = "relay",
        env = "ALLOWLIST_RELAYS",
        value_delimiter = ',',
        required_unless_present = "public_relays"
    )]
    relays: Vec<String>,

    /// Public source relays fetched without NIP-42 authentication (repeatable).
    #[arg(
        long = "public-relay",
        env = "ALLOWLIST_PUBLIC_RELAYS",
        value_delimiter = ','
    )]
    public_relays: Vec<String>,

    /// Extra pubkey(s) to always allow, in addition to the registry set
    /// (repeatable). Accepts npub or 64-char hex.
    #[arg(
        long = "extra-pubkey",
        env = "ALLOWLIST_EXTRA_PUBKEYS",
        value_delimiter = ','
    )]
    extra_pubkeys: Vec<String>,

    /// Dedicated policy file consumed by the relay via auth.registry_file.
    #[arg(long, env = "ALLOWLIST_POLICY_FILE")]
    policy_file: PathBuf,

    /// Deadline for each source to finish its response with EOSE.
    #[arg(long, default_value = "10s", value_parser = humantime_secs)]
    fetch_timeout: Duration,

    /// How often to request catch-up on the existing source connections.
    #[arg(long, env = "ALLOWLIST_RESYNC_INTERVAL", default_value = "60s", value_parser = humantime_secs)]
    resync_interval: Duration,
}

fn humantime_secs(s: &str) -> Result<Duration, String> {
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install the rustls ring CryptoProvider"))?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let cli = Cli::parse();

    let authority = PublicKey::parse(&cli.authority)
        .with_context(|| format!("invalid authority pubkey: {}", cli.authority))?;
    let recipient_keys = read_recipient_keys(&cli.recipient_nsec_file)?;
    let recipient = recipient_keys.public_key();
    let kind = Kind::from(cli.event_kind);
    if !kind.is_addressable() {
        anyhow::bail!(
            "registry event kind {} is not in the addressable range",
            cli.event_kind
        );
    }
    let extras = parse_extra_pubkeys(&cli.extra_pubkeys)?;
    let shutdown = shutdown_signal().context("cannot install shutdown handlers")?;
    info!(
        authority = %authority.to_hex(),
        recipient = %recipient.to_hex(),
        kind = cli.event_kind,
        extras = extras.len(),
        "starting allowlist-sync"
    );

    let client = registry_client(&recipient_keys);

    run_with_shutdown(
        &client,
        shutdown,
        run(&client, &cli, authority, &recipient_keys, &extras),
    )
    .await
}

fn registry_client(keys: &Keys) -> Client {
    Client::builder()
        .signer(keys.clone())
        .opts(ClientOptions::new().automatic_authentication(false))
        .build()
}

fn shutdown_signal() -> std::io::Result<impl Future<Output = std::io::Result<()>>> {
    #[cfg(unix)]
    let (mut interrupt, mut terminate) = {
        use tokio::signal::unix::{signal, SignalKind};
        (
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
        )
    };

    Ok(async move {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = interrupt.recv() => {}
                _ = terminate.recv() => {}
            }
            Ok(())
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c().await
    })
}

async fn run_with_shutdown(
    client: &Client,
    shutdown: impl Future<Output = std::io::Result<()>>,
    work: impl Future<Output = Result<()>>,
) -> Result<()> {
    let result = tokio::select! {
        biased;
        signal = shutdown => signal.context("shutdown listener failed").map(|()| {
            info!("shutdown requested");
        }),
        result = work => result,
    };
    client.shutdown().await;
    result
}

fn registry_sources(
    relays: &[String],
    public_relays: &[String],
) -> Result<HashMap<RelayUrl, bool>> {
    let mut sources = HashMap::new();
    for (entries, require_auth, option) in [
        (relays, true, "--relay/ALLOWLIST_RELAYS"),
        (
            public_relays,
            false,
            "--public-relay/ALLOWLIST_PUBLIC_RELAYS",
        ),
    ] {
        for entry in entries
            .iter()
            .map(|entry| entry.trim())
            .filter(|entry| !entry.is_empty())
        {
            let url = RelayUrl::parse(entry)
                .with_context(|| format!("invalid {option} entry {entry:?}"))?;
            if let Some(previous) = sources.insert(url.clone(), require_auth) {
                anyhow::ensure!(
                    previous == require_auth,
                    "relay {url} configured as both public and authenticated"
                );
            }
        }
    }
    anyhow::ensure!(!sources.is_empty(), "no source relays configured; set --relay/ALLOWLIST_RELAYS or --public-relay/ALLOWLIST_PUBLIC_RELAYS");
    Ok(sources)
}

async fn run(
    client: &Client,
    cli: &Cli,
    authority: PublicKey,
    recipient_keys: &Keys,
    extras: &BTreeSet<String>,
) -> Result<()> {
    let sources = registry_sources(&cli.relays, &cli.public_relays)?;
    let policy_file = allowlist_policy::policy_path(&cli.policy_file)?;
    let filter = Filter::new()
        .author(authority)
        .kind(Kind::from(cli.event_kind))
        .identifier(recipient_keys.public_key().to_hex())
        .pubkey(recipient_keys.public_key());
    let source = RegistrySource {
        authority: authority.to_hex(),
        recipient: recipient_keys.public_key().to_hex(),
        event_kind: cli.event_kind,
    };
    let syncer = Syncer {
        filter: filter.clone(),
        recipient_keys: recipient_keys.clone(),
        policy_file: policy_file.clone(),
        extras: extras.clone(),
        last_applied: load_policy(&policy_file, &source, extras)?,
        source,
    };
    let (updates, receiver) = tokio::sync::mpsc::channel(32);
    let mut sessions = tokio::task::JoinSet::new();
    let mut task_sources = HashMap::new();
    for (url, require_auth) in sources {
        let source = Source {
            url: url.clone(),
            require_auth,
            filter: filter.clone(),
            keys: recipient_keys.clone(),
            timeout: cli.fetch_timeout,
            resync_interval: cli.resync_interval,
        };
        let (client, updates) = (client.clone(), updates.clone());
        let task = sessions.spawn(async move { source.run(&client, &updates).await });
        task_sources.insert(task.id(), url);
    }
    drop(updates);
    publish_updates(syncer, receiver, sessions, task_sources).await
}

async fn publish_updates(
    mut syncer: Syncer,
    mut updates: tokio::sync::mpsc::Receiver<Event>,
    mut sessions: tokio::task::JoinSet<Result<()>>,
    mut sources: HashMap<tokio::task::Id, RelayUrl>,
) -> Result<()> {
    loop {
        tokio::select! {
            Some(event) = updates.recv() => {
                if let Err(err) = syncer.process_event(&event) {
                    retry_sync_failure(err, "failed to apply registry update")?;
                }
            },
            Some(result) = sessions.join_next_with_id() => {
                let (id, result) = match result {
                    Ok(result) => result,
                    Err(err) => (err.id(), Err(anyhow::Error::from(err).context("registry source task failed"))),
                };
                let url = sources.remove(&id).expect("registered registry source");
                anyhow::bail!("registry source {url} stopped unexpectedly: {result:?}");
            }
            else => anyhow::bail!("all registry sources stopped"),
        }
    }
}

#[derive(Debug)]
struct LocalPolicyError;
impl std::fmt::Display for LocalPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("local registry policy error")
    }
}
impl std::error::Error for LocalPolicyError {}

fn retry_sync_failure(err: anyhow::Error, message: &str) -> Result<()> {
    if err.is::<LocalPolicyError>() {
        return Err(err);
    }
    warn!(error = %format_args!("{err:#}"), "{message}; will retry");
    Ok(())
}

fn validate_snapshot_timestamp(created_at: u64) -> Result<()> {
    let now = Timestamp::now().as_secs();
    anyhow::ensure!(created_at <= now.saturating_add(MAX_SNAPSHOT_CLOCK_SKEW),
        "snapshot timestamp {created_at} is more than 15 minutes ahead of local time {now}; check the publisher and local clocks");
    Ok(())
}

fn load_policy(
    file: &Path,
    source: &RegistrySource,
    extras: &BTreeSet<String>,
) -> Result<Option<RegistryPolicy>> {
    match RegistryPolicy::read(file) {
        Ok(mut policy) => {
            anyhow::ensure!(
                policy.source == *source,
                "{} belongs to another registry source; use a separate policy file",
                file.display()
            );
            validate_snapshot_timestamp(policy.created_at)
                .with_context(|| format!("invalid saved version in policy {}", file.display()))?;
            policy.extras = extras.clone();
            publish_policy(file, &policy)?;
            Ok(Some(policy))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("cannot load policy {}", file.display())),
    }
}

struct Syncer {
    filter: Filter,
    recipient_keys: Keys,
    policy_file: PathBuf,
    extras: BTreeSet<String>,
    last_applied: Option<RegistryPolicy>,
    source: RegistrySource,
}

impl Syncer {
    fn process_event(&mut self, event: &Event) -> Result<bool> {
        anyhow::ensure!(
            self.filter.match_event(event, MatchEventOptions::new()),
            "event {} does not match the configured authority/recipient",
            event.id
        );
        event.verify().context("invalid registry event signature")?;
        let created_at = event.created_at.as_secs();
        validate_snapshot_timestamp(created_at)
            .with_context(|| format!("invalid registry event {}", event.id))?;
        let event_id = event.id.to_hex();
        if let Some(current) = &self.last_applied {
            if compare_versions(
                (created_at, &event_id),
                (current.created_at, &current.event_id),
            ) == Ordering::Less
            {
                debug!(event_id = %event.id, created_at, applied_event_id = %current.event_id, applied_created_at = current.created_at, "ignoring older registry snapshot");
                return Ok(false);
            }
        }
        let policy = RegistryPolicy {
            source: self.source.clone(),
            created_at,
            event_id,
            members: decrypt_members(event, &self.recipient_keys)?,
            extras: self.extras.clone(),
        };
        if publish_policy(&self.policy_file, &policy)? {
            info!(created_at = policy.created_at, event_id = %policy.event_id, "published registry policy");
        }
        self.last_applied = Some(policy);
        Ok(true)
    }
}

struct Source {
    url: RelayUrl,
    require_auth: bool,
    filter: Filter,
    keys: Keys,
    timeout: Duration,
    resync_interval: Duration,
}

impl Source {
    async fn run(&self, client: &Client, updates: &tokio::sync::mpsc::Sender<Event>) -> Result<()> {
        let mut retry_delay = INITIAL_RETRY_DELAY;
        loop {
            client
                .pool()
                .add_relay(
                    self.url.clone(),
                    RelayOptions::new()
                        .reconnect(false)
                        .verify_subscriptions(true)
                        .ban_relay_on_mismatch(false),
                )
                .await?;
            let relay = client.relay(self.url.clone()).await?;
            let result = self.session(&relay, updates, &mut retry_delay).await;
            client.remove_relay(self.url.clone()).await?;
            let delay = next_retry_delay(&mut retry_delay);
            if let Err(err) = result {
                warn!(relay = %self.url, error = %format_args!("{err:#}"), retry_in = ?delay, "registry source failed; reconnecting");
            }
            tokio::time::sleep(delay).await;
        }
    }

    async fn session(
        &self,
        relay: &Relay,
        updates: &tokio::sync::mpsc::Sender<Event>,
        retry_delay: &mut Duration,
    ) -> Result<()> {
        let mut request = SourceRequest::new(self.require_auth);
        let mut notifications = relay.notifications();
        relay.connect();
        relay
            .subscribe_with_id(
                request.id.clone(),
                self.filter.clone(),
                SubscribeOptions::default(),
            )
            .await?;
        let mut deadline = tokio::time::Instant::now() + self.timeout;
        let mut resync_at = deadline;
        let mut complete = false;
        loop {
            let action = tokio::select! {
                notification = notifications.recv() => request.handle(
                    notification.context("relay notifications ended or lagged")?, &self.keys, &self.url)?,
                _ = tokio::time::sleep_until(deadline), if !complete => anyhow::bail!(request.timeout_message()),
                _ = tokio::time::sleep_until(resync_at), if complete => {
                    deadline = tokio::time::Instant::now() + self.timeout;
                    request.restart()
                },
            };
            match action {
                SourceAction::Continue => {}
                SourceAction::Event(event) => updates
                    .send(*event)
                    .await
                    .context("policy publisher stopped")?,
                SourceAction::Complete => {
                    *retry_delay = INITIAL_RETRY_DELAY;
                    complete = true;
                    resync_at = tokio::time::Instant::now() + self.resync_interval;
                }
                SourceAction::Authenticate(event) => {
                    relay.send_msg(ClientMessage::Auth(Cow::Owned(*event)))?;
                    if complete {
                        deadline = tokio::time::Instant::now() + self.timeout;
                    }
                    complete = false;
                }
                SourceAction::Restart(previous) => {
                    relay.unsubscribe(&previous).await?;
                    relay
                        .subscribe_with_id(
                            request.id.clone(),
                            self.filter.clone(),
                            SubscribeOptions::default(),
                        )
                        .await?;
                    complete = false;
                }
            }
        }
    }
}

fn next_retry_delay(delay: &mut Duration) -> Duration {
    let current = *delay;
    *delay = (current * 2).min(MAX_RETRY_DELAY);
    current
}

enum SourceAction {
    Continue,
    Complete,
    Event(Box<Event>),
    Authenticate(Box<Event>),
    Restart(SubscriptionId),
}

struct SourceRequest {
    id: SubscriptionId,
    connected: bool,
    require_auth: bool,
    pending_auth: Option<EventId>,
    authenticated: bool,
}

impl SourceRequest {
    fn new(require_auth: bool) -> Self {
        Self {
            id: SubscriptionId::generate(),
            connected: false,
            require_auth,
            pending_auth: None,
            authenticated: false,
        }
    }

    fn restart(&mut self) -> SourceAction {
        SourceAction::Restart(std::mem::replace(&mut self.id, SubscriptionId::generate()))
    }

    fn timeout_message(&self) -> &'static str {
        if !self.connected {
            "relay did not connect before the fetch deadline"
        } else if self.pending_auth.is_some() {
            "fetch deadline expired waiting for NIP-42 AUTH acknowledgement"
        } else if self.require_auth && !self.authenticated {
            "fetch deadline expired waiting for NIP-42 AUTH challenge; use --public-relay only for public sources"
        } else {
            "fetch deadline expired before matching relay EOSE"
        }
    }

    fn handle(
        &mut self,
        notification: RelayNotification,
        keys: &Keys,
        url: &RelayUrl,
    ) -> Result<SourceAction> {
        match notification {
            RelayNotification::Message { message } => match message {
                RelayMessage::Auth { challenge } if self.require_auth => {
                    let event = EventBuilder::auth(challenge.into_owned(), url.clone())
                        .sign_with_keys(keys)?;
                    self.pending_auth = Some(event.id);
                    self.authenticated = false;
                    return Ok(SourceAction::Authenticate(Box::new(event)));
                }
                RelayMessage::Ok {
                    event_id,
                    status,
                    message,
                } if self.pending_auth == Some(event_id) => {
                    anyhow::ensure!(
                        status,
                        "relay authentication rejected: {}",
                        relay_text(&message)
                    );
                    self.pending_auth = None;
                    self.authenticated = true;
                    // A fresh ID excludes responses to the unauthenticated request.
                    return Ok(self.restart());
                }
                RelayMessage::Event {
                    subscription_id,
                    event,
                } if subscription_id.as_ref() == &self.id
                    && (!self.require_auth || self.authenticated) =>
                {
                    return Ok(SourceAction::Event(Box::new(event.into_owned())));
                }
                RelayMessage::EndOfStoredEvents(id)
                    if id.as_ref() == &self.id && (!self.require_auth || self.authenticated) =>
                {
                    return Ok(SourceAction::Complete)
                }
                RelayMessage::Closed {
                    subscription_id,
                    message,
                } if subscription_id.as_ref() == &self.id
                    && !(self.require_auth
                        && message.starts_with("auth-required:")
                        && !self.authenticated) =>
                {
                    anyhow::bail!("relay closed registry request: {}", relay_text(&message));
                }
                _ => {}
            },
            RelayNotification::RelayStatus {
                status: RelayStatus::Connected,
            } => self.connected = true,
            RelayNotification::AuthenticationFailed => anyhow::bail!("relay authentication failed"),
            RelayNotification::RelayStatus {
                status:
                    RelayStatus::Disconnected
                    | RelayStatus::Terminated
                    | RelayStatus::Banned
                    | RelayStatus::Sleeping,
            }
            | RelayNotification::Shutdown => anyhow::bail!("relay disconnected"),
            _ => {}
        }
        Ok(SourceAction::Continue)
    }
}

fn relay_text(message: &str) -> String {
    let mut text: String = message
        .chars()
        .take(256)
        .flat_map(char::escape_debug)
        .collect();
    if message.chars().nth(256).is_some() {
        text.push_str("...");
    }
    text
}

fn parse_extra_pubkeys(raw: &[String]) -> Result<BTreeSet<String>> {
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
    Ok(set)
}

fn decrypt_members(event: &Event, recipient_keys: &Keys) -> Result<BTreeSet<String>> {
    let plaintext = nip44::decrypt(recipient_keys.secret_key(), &event.pubkey, &event.content)
        .with_context(|| format!("cannot decrypt registry event {}", event.id))?;
    let shareholders: Vec<String> = serde_json::from_str(&plaintext)
        .with_context(|| format!("registry event {} is not a JSON pubkey array", event.id))?;

    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut invalid_keys = 0;
    for raw in shareholders {
        match PublicKey::parse(&raw) {
            Ok(pubkey) => {
                set.insert(pubkey.to_hex());
            }
            Err(_) => invalid_keys += 1,
        }
    }
    if invalid_keys > 0 {
        warn!(event_id = %event.id, invalid_keys, "skipping malformed member keys in registry snapshot");
    }
    set.remove(&event.pubkey.to_hex());
    set.remove(&recipient_keys.public_key().to_hex());

    Ok(set)
}

// Synchronous publication cannot be cancelled by the async shutdown path midway.
fn publish_policy(file: &Path, policy: &RegistryPolicy) -> Result<bool> {
    (|| -> Result<bool> {
        policy.validate()?;
        let rendered = serde_json::to_vec_pretty(policy)?;
        #[cfg(unix)]
        let permissions_match =
            fs::metadata(file).is_ok_and(|m| m.permissions().mode() & 0o777 == 0o640);
        #[cfg(not(unix))]
        let permissions_match = true;
        match policy_document(file) {
            Ok(current) if current == rendered && permissions_match => return Ok(false),
            Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                return Err(err).context("cannot read policy file")
            }
            _ => {}
        }
        let parent = file
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut tmp =
            NamedTempFile::new_in(parent).context("cannot create policy temporary file")?;
        #[cfg(unix)]
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o640))?;
        tmp.write_all(&rendered)
            .context("cannot write policy temporary file")?;
        tmp.as_file()
            .sync_all()
            .context("cannot flush policy temporary file")?;
        tmp.persist(file)
            .map_err(|err| err.error)
            .context("cannot replace policy file")?;
        #[cfg(unix)]
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .context("cannot flush policy directory")?;
        Ok(true)
    })()
    .context(LocalPolicyError)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PK_A: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const PK_B: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn recipient_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000004").unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run by the systemd CI smoke test"]
    fn systemd_policy_publication() {
        let key_file = PathBuf::from(std::env::var_os("ALLOWLIST_RECIPIENT_NSEC_FILE").unwrap());
        assert_eq!(
            read_recipient_keys(&key_file).unwrap().public_key(),
            recipient_keys().public_key()
        );
        let state = PathBuf::from(std::env::var_os("STATE_DIRECTORY").unwrap());
        let authority = Keys::generate();
        let mut syncer = syncer(&state.join("allowlist.json"), &authority);
        for (timestamp, members) in [(10, &[PK_A][..]), (20, &[][..])] {
            syncer
                .process_event(&registry_snapshot(
                    &authority,
                    Timestamp::from(timestamp),
                    members,
                ))
                .unwrap();
        }
        let policy = RegistryPolicy::read(&state.join("allowlist.json")).unwrap();
        assert_eq!(policy.created_at, 20);
        assert!(!policy.allows(PK_A));
    }

    fn write_tmp(name: &str, content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        (dir, path)
    }
    fn syncer(file: &Path, authority: &Keys) -> Syncer {
        Syncer {
            filter: registry_filter(authority),
            recipient_keys: recipient_keys(),
            policy_file: file.to_owned(),
            extras: BTreeSet::new(),
            last_applied: None,
            source: RegistrySource {
                authority: authority.public_key().to_hex(),
                recipient: recipient_keys().public_key().to_hex(),
                event_kind: DEFAULT_REGISTRY_EVENT_KIND,
            },
        }
    }

    #[test]
    fn one_document_commits_membership_and_rollback_floor_and_keeps_extras_separate() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.json");
        let keys = Keys::generate();
        let mut syncer = syncer(&file, &keys);
        let old = registry_snapshot(&keys, Timestamp::from(10), &[PK_A]);
        syncer.process_event(&old).unwrap();
        let policy = RegistryPolicy::read(&file).unwrap();
        assert!(policy.allows(PK_A));
        assert!(policy.allows(&keys.public_key().to_hex()));
        assert!(policy.allows(&recipient_keys().public_key().to_hex()));
        assert!(!publish_policy(&file, &policy).unwrap());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o640
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(publish_policy(&file, &policy).unwrap());
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o640
            );
            assert_eq!(
                fs::metadata(&file).unwrap().gid(),
                fs::metadata(dir.path()).unwrap().gid()
            );
        }

        let extras = [PK_B.to_owned()].into();
        let cached = load_policy(&file, &policy.source, &extras)
            .unwrap()
            .unwrap();
        assert_eq!(cached.members, policy.members);
        assert_eq!(cached.event_id, policy.event_id);
        assert!(RegistryPolicy::read(&file).unwrap().allows(PK_B));
        // Removing a local extra works offline too.
        assert!(!load_policy(&file, &policy.source, &BTreeSet::new())
            .unwrap()
            .unwrap()
            .allows(PK_B));

        let revoked = registry_snapshot(&keys, Timestamp::from(20), &[]);
        syncer.process_event(&revoked).unwrap();
        let mut restarted = syncer;
        restarted.last_applied = load_policy(&file, &policy.source, &BTreeSet::new()).unwrap();
        assert!(!restarted.process_event(&old).unwrap());
        let current = RegistryPolicy::read(&file).unwrap();
        assert_eq!(current.event_id, revoked.id.to_hex());
        assert!(!current.allows(PK_A));
        // Replaying the verified event repairs inconsistent cached membership.
        let mut inconsistent = current;
        inconsistent.members.insert(PK_A.to_owned());
        publish_policy(&file, &inconsistent).unwrap();
        restarted.last_applied = Some(inconsistent);
        assert!(restarted.process_event(&revoked).unwrap());
        assert!(!RegistryPolicy::read(&file).unwrap().allows(PK_A));
    }

    #[test]
    fn malformed_member_keys_do_not_prevent_revocations() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.json");
        let keys = Keys::generate();
        let mut syncer = syncer(&file, &keys);
        syncer
            .process_event(&registry_snapshot(&keys, Timestamp::from(10), &[PK_A]))
            .unwrap();
        let event = registry_snapshot(&keys, Timestamp::from(20), &["not-a-key", PK_B]);
        syncer.process_event(&event).unwrap();
        let policy = RegistryPolicy::read(&file).unwrap();
        assert!(!policy.allows(PK_A));
        assert_eq!(policy.members, [PK_B.to_owned()].into());
        assert_eq!(policy.event_id, event.id.to_hex());
        syncer
            .process_event(&registry_snapshot(&keys, Timestamp::from(30), &["bad"]))
            .unwrap();
        assert!(RegistryPolicy::read(&file).unwrap().members.is_empty());
    }

    #[test]
    fn future_snapshots_cannot_poison_the_saved_version_floor() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.json");
        let keys = Keys::generate();
        let mut syncer = syncer(&file, &keys);
        syncer
            .process_event(&registry_snapshot(&keys, Timestamp::from(10), &[PK_A]))
            .unwrap();
        let before = fs::read(&file).unwrap();
        let future = Timestamp::from(Timestamp::now().as_secs() + MAX_SNAPSHOT_CLOCK_SKEW + 3600);
        assert!(syncer
            .process_event(&registry_snapshot(&keys, future, &[]))
            .is_err());
        assert_eq!(fs::read(&file).unwrap(), before);
        assert_eq!(syncer.last_applied.as_ref().unwrap().created_at, 10);
        syncer
            .process_event(&registry_snapshot(&keys, Timestamp::now(), &[]))
            .unwrap();
        assert!(!RegistryPolicy::read(&file).unwrap().allows(PK_A));
        let mut policy = syncer.last_applied.unwrap();
        policy.created_at = u64::MAX;
        publish_policy(&file, &policy).unwrap();
        let before = fs::read(&file).unwrap();
        let error = load_policy(&file, &policy.source, &BTreeSet::new()).unwrap_err();
        assert!(format!("{error:#}").contains("ahead of local time"));
        assert_eq!(fs::read(&file).unwrap(), before);
    }

    #[test]
    fn rejects_invalid_payloads_untrusted_events_and_mismatched_cached_sources() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.json");
        let keys = Keys::generate();
        let mut syncer = syncer(&file, &keys);
        syncer
            .process_event(&registry_snapshot(&keys, Timestamp::from(10), &[PK_A]))
            .unwrap();
        let before = fs::read(&file).unwrap();
        for payload in ["not-json", "{}", "[1]"] {
            let event = encrypted_registry_event(&keys, Timestamp::from(20), payload);
            assert!(syncer.process_event(&event).is_err());
            assert_eq!(fs::read(&file).unwrap(), before);
        }
        let unrelated = registry_snapshot(&Keys::generate(), Timestamp::from(30), &[PK_B]);
        assert!(syncer.process_event(&unrelated).is_err());
        let mut forged = registry_snapshot(&keys, Timestamp::from(30), &[PK_B]);
        forged.content.push('x');
        assert!(syncer.process_event(&forged).is_err());
        let mut source = syncer.last_applied.as_ref().unwrap().source.clone();
        source.recipient = "f".repeat(64);
        assert!(load_policy(&file, &source, &BTreeSet::new()).is_err());
        assert_eq!(fs::read(&file).unwrap(), before);
        fs::write(&file, "{}").unwrap();
        assert!(load_policy(&file, &source, &BTreeSet::new()).is_err());
    }

    #[test]
    fn failed_publish_does_not_advance_memory_and_local_io_errors_exit_live_mode() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("missing").join("policy.json");
        let keys = Keys::generate();
        let mut syncer = syncer(&file, &keys);
        let event = registry_snapshot(&keys, Timestamp::from(20), &[]);
        let err = syncer.process_event(&event).unwrap_err();
        assert!(syncer.last_applied.is_none());
        assert!(retry_sync_failure(err, "sync failed").is_err());
        assert!(retry_sync_failure(anyhow::anyhow!("relay offline"), "sync failed").is_ok());
    }

    #[tokio::test]
    async fn updates_publish_before_a_source_stops() {
        for ending in ["return", "error", "panic"] {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("policy.json");
            let keys = Keys::generate();
            let mut syncer = syncer(&file, &keys);
            syncer
                .process_event(&registry_snapshot(&keys, Timestamp::from(10), &[PK_A]))
                .unwrap();
            let revoked = registry_snapshot(&keys, Timestamp::from(20), &[]);
            let (updates, receiver) = tokio::sync::mpsc::channel(1);
            let (finish, unfinished) = tokio::sync::oneshot::channel();
            let mut sessions = tokio::task::JoinSet::new();
            let source = sessions.spawn(async move {
                updates.send(revoked).await.unwrap();
                unfinished.await.unwrap();
                match ending {
                    "return" => Ok(()),
                    "error" => anyhow::bail!("source failed before EOSE"),
                    _ => panic!("source task panicked"),
                }
            });
            let sources = [(
                source.id(),
                RelayUrl::parse("wss://incomplete.example").unwrap(),
            )]
            .into();
            let publisher = tokio::spawn(publish_updates(syncer, receiver, sessions, sources));
            tokio::time::timeout(Duration::from_secs(5), async {
                while RegistryPolicy::read(&file).unwrap().allows(PK_A) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("revocation waited for the source to finish");
            assert!(!publisher.is_finished());
            finish.send(()).unwrap();
            let error = publisher.await.unwrap().unwrap_err();
            assert!(format!("{error:#}").contains("incomplete.example"));
            assert!(error.to_string().contains("stopped unexpectedly"));
            assert!(!RegistryPolicy::read(&file).unwrap().allows(PK_A));
        }
    }

    #[test]
    fn local_extra_keys_are_canonical_deduplicated_and_validated() {
        let key = Keys::generate().public_key();
        let parsed =
            parse_extra_pubkeys(&[key.to_hex(), key.to_bech32().unwrap(), " ".into()]).unwrap();
        assert_eq!(parsed, [key.to_hex()].into());
        assert!(parse_extra_pubkeys(&["bad".into()]).is_err());
    }

    #[test]
    fn lower_id_wins_equal_timestamps_in_persisted_policy() {
        let keys = Keys::generate();
        let a = registry_snapshot(&keys, Timestamp::from(10), &[PK_A]);
        let b = registry_snapshot(&keys, Timestamp::from(10), &[PK_B]);
        let (winner, loser) = if a.id < b.id { (a, b) } else { (b, a) };
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.json");
        let mut syncer = syncer(&file, &keys);
        syncer.process_event(&loser).unwrap();
        syncer.process_event(&winner).unwrap();
        assert!(!syncer.process_event(&loser).unwrap());
        assert_eq!(
            RegistryPolicy::read(&file).unwrap().event_id,
            winner.id.to_hex()
        );
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

    fn receive(request: &mut SourceRequest, wire: serde_json::Value) -> Result<SourceAction> {
        request.handle(
            RelayNotification::Message {
                message: serde_json::from_value(wire)?,
            },
            &recipient_keys(),
            &RelayUrl::parse("wss://source.example")?,
        )
    }

    #[test]
    fn auth_requires_the_current_ack_and_a_fresh_eose() {
        use serde_json::json;
        let mut request = SourceRequest::new(true);
        request.connected = true;
        let original = request.id.clone();
        let event = registry_snapshot(&Keys::generate(), Timestamp::from(10), &[PK_A]);
        assert!(matches!(
            receive(&mut request, json!(["EVENT", original, event])),
            Ok(SourceAction::Continue)
        ));
        assert!(matches!(
            receive(&mut request, json!(["EOSE", original])),
            Ok(SourceAction::Continue)
        ));
        let SourceAction::Authenticate(first) =
            receive(&mut request, json!(["AUTH", "first"])).unwrap()
        else {
            panic!("missing AUTH")
        };
        assert_eq!(first.pubkey, recipient_keys().public_key());
        assert!(first.verify().is_ok());
        assert!(request.timeout_message().contains("acknowledgement"));
        assert!(matches!(
            receive(&mut request, json!(["EOSE", original])),
            Ok(SourceAction::Continue)
        ));
        let SourceAction::Authenticate(second) =
            receive(&mut request, json!(["AUTH", "second"])).unwrap()
        else {
            panic!("missing AUTH")
        };
        // A superseded challenge or request cannot complete authentication/fetch.
        assert!(matches!(
            receive(&mut request, json!(["OK", first.id, true, ""])),
            Ok(SourceAction::Continue)
        ));
        assert!(
            matches!(receive(&mut request, json!(["OK", second.id, true, ""])), Ok(SourceAction::Restart(id)) if id == original)
        );
        assert_ne!(request.id, original);
        assert!(request.timeout_message().contains("EOSE"));
        assert!(matches!(
            receive(&mut request, json!(["EOSE", original])),
            Ok(SourceAction::Continue)
        ));
        let current = request.id.clone();
        assert!(
            matches!(receive(&mut request, json!(["EVENT", current, event])), Ok(SourceAction::Event(received)) if received.id == event.id)
        );
        let SourceAction::Restart(previous) = request.restart() else {
            panic!("missing catch-up request")
        };
        assert_eq!(previous, current);
        assert!(request.authenticated, "catch-up must reuse authentication");
        let current = request.id.clone();
        assert!(matches!(
            receive(&mut request, json!(["EOSE", current])),
            Ok(SourceAction::Complete)
        ));
        assert!(receive(
            &mut request,
            json!(["CLOSED", current, "auth-required: denied after auth"])
        )
        .is_err());
    }

    #[test]
    fn public_sources_complete_despite_optional_auth_challenges() {
        use serde_json::json;
        for rejected_ack in [false, true] {
            let mut request = SourceRequest::new(false);
            assert!(matches!(
                receive(&mut request, json!(["AUTH", "optional"])),
                Ok(SourceAction::Continue)
            ));
            assert!(request.pending_auth.is_none());
            if rejected_ack {
                assert!(matches!(
                    receive(
                        &mut request,
                        json!(["OK", EventId::all_zeros(), false, "denied"])
                    ),
                    Ok(SourceAction::Continue)
                ));
            }
            let id = request.id.clone();
            assert!(matches!(
                receive(&mut request, json!(["EOSE", id])),
                Ok(SourceAction::Complete)
            ));
            assert!(receive(&mut request, json!(["CLOSED", id, "auth-required: denied"])).is_err());
        }
    }

    #[test]
    fn timeouts_distinguish_connection_from_protocol_progress() {
        for require_auth in [false, true] {
            let mut request = SourceRequest::new(require_auth);
            assert_eq!(
                request.timeout_message(),
                "relay did not connect before the fetch deadline"
            );
            request
                .handle(
                    RelayNotification::RelayStatus {
                        status: RelayStatus::Connected,
                    },
                    &recipient_keys(),
                    &RelayUrl::parse("wss://source.example").unwrap(),
                )
                .unwrap();
            assert!(request.timeout_message().contains(if require_auth {
                "--public-relay"
            } else {
                "EOSE"
            }));
        }
    }

    #[test]
    fn diagnostics_are_bounded_and_stale_payloads_are_not_decrypted() {
        let diagnostic = relay_text(&format!("\x1b[2J\n{}", "x".repeat(10000)));
        assert!(!diagnostic.contains('\x1b') && !diagnostic.contains('\n'));
        assert!(diagnostic.len() < 2048);
        assert!(retry_sync_failure(
            std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into(),
            "network failure"
        )
        .is_ok());
        let dir = tempfile::tempdir().unwrap();
        let keys = Keys::generate();
        let mut syncer = syncer(&dir.path().join("policy.json"), &keys);
        syncer
            .process_event(&registry_snapshot(&keys, Timestamp::from(20), &[PK_A]))
            .unwrap();
        let stale = encrypted_registry_event(&keys, Timestamp::from(10), "not JSON");
        assert!(!syncer.process_event(&stale).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn publishing_rejects_file_symlinks_without_replacing_them() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        let link = dir.path().join("link.json");
        let keys = Keys::generate();
        let mut syncer = syncer(&target, &keys);
        syncer
            .process_event(&registry_snapshot(&keys, Timestamp::from(20), &[PK_A]))
            .unwrap();
        let policy = syncer.last_applied.as_ref().unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(RegistryPolicy::read(&link).is_err());
        assert!(publish_policy(&link, policy)
            .unwrap_err()
            .is::<LocalPolicyError>());
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(&RegistryPolicy::read(&target).unwrap(), policy);
    }

    #[tokio::test]
    async fn shutdown_runs_on_success_error_and_cancellation() {
        for mode in ["success", "error", "cancel", "signal-error"] {
            let client = Client::default();
            let mut notifications = client.notifications();
            let signal = async {
                match mode {
                    "cancel" => Ok(()),
                    "signal-error" => Err(std::io::Error::other("listener failure")),
                    _ => std::future::pending().await,
                }
            };
            let work = async {
                match mode {
                    "success" => Ok(()),
                    "error" => anyhow::bail!("work failure"),
                    _ => std::future::pending().await,
                }
            };
            let result = run_with_shutdown(&client, signal, work).await;
            assert_eq!(result.is_ok(), matches!(mode, "success" | "cancel"));
            if mode == "error" {
                assert!(result.unwrap_err().to_string().contains("work failure"));
            }
            assert!(
                matches!(
                    tokio::time::timeout(Duration::from_secs(1), notifications.recv()).await,
                    Ok(Ok(RelayPoolNotification::Shutdown))
                ),
                "client not shut down after {mode}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "sends process signals; run this test alone outside restricted sandboxes"]
    async fn unix_shutdown_signals_are_registered_before_polling() {
        for signal in [libc::SIGTERM, libc::SIGINT] {
            let shutdown = shutdown_signal().unwrap();
            // SAFETY: handlers are installed before raising either signal.
            assert_eq!(unsafe { libc::raise(signal) }, 0);
            tokio::time::timeout(Duration::from_secs(1), shutdown)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn source_lists_ignore_empty_entries_and_report_bad_configuration() {
        let cli = Cli::try_parse_from([
            "allowlist-sync",
            "--authority",
            "unused",
            "--recipient-nsec-file",
            "unused",
            "--policy-file",
            "unused",
            "--relay",
            " wss://source.example, ",
            "--public-relay",
            "",
        ])
        .unwrap();
        let sources = registry_sources(&cli.relays, &cli.public_relays).unwrap();
        assert_eq!(sources.len(), 1);
        assert!(sources[&RelayUrl::parse("wss://source.example").unwrap()]);
        for (private, public, option) in [
            (vec!["not-a-url".to_owned()], vec![], "ALLOWLIST_RELAYS"),
            (
                vec![],
                vec!["not-a-url".to_owned()],
                "ALLOWLIST_PUBLIC_RELAYS",
            ),
        ] {
            let error = registry_sources(&private, &public).unwrap_err().to_string();
            assert!(
                error.contains(option) && error.contains("not-a-url"),
                "{error}"
            );
        }
        let error = registry_sources(&[], &["".into(), " ".into()])
            .unwrap_err()
            .to_string();
        assert!(error.contains("no source relays configured"), "{error}");
        let same = ["wss://source.example".into()];
        assert!(registry_sources(&same, &same).is_err());
    }

    #[test]
    fn source_retry_delay_grows_and_stops_at_one_minute() {
        let mut delay = Duration::from_secs(5);
        for expected in [5, 10, 20, 40, 60, 60, 60] {
            assert_eq!(next_retry_delay(&mut delay), Duration::from_secs(expected));
        }
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
        let (_dir, path) = write_tmp(
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
}
