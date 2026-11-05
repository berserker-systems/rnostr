//! [NIP-77](https://nips.be/77) negentropy set reconciliation.
//!
//! `NEG-OPEN` snapshots the `(created_at, id)` pairs a filter matches, then
//! `NEG-MSG` rounds reconcile that snapshot against the client's own set. The
//! relay is always the non-initiator: it answers every message the client
//! sends and lets the client decide when the exchange is finished.

use actix::{ActorFutureExt as _, AsyncContext as _, WrapFuture as _};
use negentropy::{Id, Negentropy, NegentropyStorageVector};
use nostr_relay::{
    db::{Db, Filter},
    duration::NonZeroDuration,
    message::{ClientMessage, IncomingMessage, NegOpen, OutgoingMessage},
    setting::SettingWrapper,
    Error, Extension, ExtensionMessageResult, Session,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Weak,
    },
    time::{Duration, Instant},
};
use tracing::{debug, warn};

pub const NEG_OPEN: &str = "NEG-OPEN";
pub const NEG_MSG: &str = "NEG-MSG";
pub const NEG_CLOSE: &str = "NEG-CLOSE";
pub const NEG_ERR: &str = "NEG-ERR";

/// Negentropy rejects a frame size limit between 1 and 4095.
const MIN_FRAME_SIZE_LIMIT: u64 = 4096;

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct NegentropySetting {
    pub enabled: bool,

    /// Largest event set a single `NEG-OPEN` may reconcile over; a filter
    /// matching more is rejected rather than reconciled against a subset.
    pub max_records: usize,

    /// Concurrent reconciliations allowed per connection.
    pub max_sessions: usize,

    /// Relay-wide ceiling on queued and running blocking jobs. Must be
    /// positive. Scans over the limit are refused; rounds wait for a slot.
    pub max_jobs: NonZeroUsize,

    /// Maximum snapshot scan duration, also capped by `data.db_query_timeout`.
    pub scan_timeout: NonZeroDuration,

    /// Split responses larger than this many bytes across rounds; this, not
    /// `max_records`, bounds the size of one reply. `0` disables splitting;
    /// any other value must be at least 4096.
    pub frame_size_limit: u64,

    /// Drop a reconciliation this long after its last message. Reloads apply
    /// to existing reconciliations on the next sweep.
    #[serde(deserialize_with = "deserialize_idle_timeout")]
    pub idle_timeout: Option<NonZeroDuration>,

    /// Ceiling on snapshot records across every connection, where
    /// `max_records` and `max_sessions` bound only one. `0` disables it.
    pub max_total_records: usize,
}

impl Default for NegentropySetting {
    fn default() -> Self {
        Self {
            enabled: false,
            max_records: 50_000,
            max_sessions: 4,
            max_jobs: NonZeroUsize::new(4).unwrap(),
            scan_timeout: NonZeroDuration::new(Duration::from_secs(5)).unwrap(),
            frame_size_limit: 65536,
            idle_timeout: NonZeroDuration::new(Duration::from_secs(300)),
            // ~40 MiB of snapshots across the whole relay.
            max_total_records: 1_000_000,
        }
    }
}

fn deserialize_idle_timeout<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<NonZeroDuration>, D::Error> {
    #[derive(Deserialize)]
    struct Timeout(#[serde(deserialize_with = "nostr_relay::duration::deserialize")] Duration);
    Option::<Timeout>::deserialize(deserializer)
        .map(|timeout| timeout.and_then(|timeout| NonZeroDuration::new(timeout.0)))
}

/// Snapshot records held in memory across every connection.
#[derive(Clone, Default)]
struct RecordBudget(Arc<AtomicUsize>);

/// Charges `records` against the budget until dropped, so the charge is also
/// repaid on connection close, which the extension is never told about.
struct RecordLease {
    budget: Arc<AtomicUsize>,
    records: usize,
}

impl Drop for RecordLease {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.records, Ordering::Relaxed);
    }
}

impl RecordBudget {
    /// Reserve `records`, or `None` when that would exceed `max`.
    fn acquire(&self, records: usize, max: usize) -> Option<RecordLease> {
        let lease = |records| RecordLease {
            budget: self.0.clone(),
            records,
        };
        if max == 0 {
            return Some(lease(0));
        }

        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(records)?;
            if next > max {
                return None;
            }
            match self
                .0
                .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Some(lease(records)),
                Err(actual) => current = actual,
            }
        }
    }
}

/// A reconciliation in progress, keyed by its subscription id.
struct Reconciliation {
    negentropy: Negentropy<'static, NegentropyStorageVector>,
    _lease: RecordLease,
}

/// Only the entry owns a strong generation reference. Removing it cancels the
/// job logically; a running worker retains its permits and data until it exits.
struct Entry {
    generation: Arc<()>,
    last_active: Instant,
    ready: Option<Reconciliation>,
}

type JobResult = Result<(Reconciliation, OutgoingMessage), OutgoingMessage>;

/// A scan is refused when no slot is free: nothing is lost yet. A round waits
/// instead, since a `NEG-ERR` closes the reconciliation and would throw its
/// snapshot away over a passing shortage of workers.
enum Admission {
    Granted { _permit: RecordLease },
    Queued { jobs: RecordBudget, max_jobs: usize },
}

const ADMISSION_POLL: Duration = Duration::from_millis(10);

struct Job {
    id: String,
    generation: Weak<()>,
    work: Box<dyn FnOnce() -> JobResult + Send>,
    admission: Admission,
}

impl Job {
    /// Wait for a slot if admission was deferred.
    async fn admit(&mut self) -> Result<(), OutgoingMessage> {
        let Admission::Queued { jobs, max_jobs } = &self.admission else {
            return Ok(());
        };
        let permit = loop {
            if self.generation.upgrade().is_none() {
                return Err(neg_err(&self.id, "closed: reconciliation cancelled"));
            }
            if let Some(permit) = jobs.acquire(1, *max_jobs) {
                break permit;
            }
            actix_web::rt::time::sleep(ADMISSION_POLL).await;
        };
        self.admission = Admission::Granted { _permit: permit };
        Ok(())
    }

    fn run(self) -> JobResult {
        let Self {
            id,
            generation,
            work,
            admission: _permit,
        } = self;
        if generation.upgrade().is_none() {
            return Err(neg_err(&id, "closed: reconciliation cancelled"));
        }
        work()
    }
}

/// Per-connection reconciliation state, stored on the session.
#[derive(Default)]
struct Sessions {
    open: HashMap<String, Entry>,
    idle_sweep_started: bool,
}

#[derive(Clone)]
pub struct Negentropies {
    setting: NegentropySetting,
    db: Arc<Db>,
    budget: RecordBudget,
    // The same RAII counter also charges one unit for each admitted job.
    jobs: RecordBudget,
}

impl Negentropies {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            setting: NegentropySetting::default(),
            db,
            budget: RecordBudget::default(),
            jobs: RecordBudget::default(),
        }
    }

    /// Snapshot the filter as sealed negentropy storage plus its record count,
    /// or `None` when it matches more than `max_records` events. Sealing sorts
    /// by `(timestamp, id)`, the protocol's order, which differs from rnostr's
    /// own index order for events sharing a timestamp.
    fn snapshot(
        &self,
        filter: &Filter,
        timeout: Duration,
        generation: &Weak<()>,
    ) -> Result<Option<(NegentropyStorageVector, usize)>, Error> {
        let reader = self.db.reader()?;
        let mut iter = self.db.iter::<Vec<u8>, _>(&reader, filter)?;
        iter.scan_time(timeout, 256);
        let (pairs, complete, _) = iter.index_pairs(self.setting.max_records)?;
        if generation.upgrade().is_none() {
            return Err(Error::Str("reconciliation cancelled"));
        }
        if !complete {
            return Ok(None);
        }
        let records = pairs.len();
        let mut storage = NegentropyStorageVector::with_capacity(records);
        for (created_at, id) in pairs {
            storage
                .insert(created_at, Id::from_byte_array(id))
                .map_err(|err| Error::Message(err.to_string()))?;
        }
        storage
            .seal()
            .map_err(|err| Error::Message(err.to_string()))?;
        Ok(Some((storage, records)))
    }

    /// The relay has validated the message and the Search extension has built
    /// the filter's keywords, exactly as for a REQ.
    fn open(&self, session: &mut Session, open: &NegOpen) -> Result<Job, OutgoingMessage> {
        let sub_id = open.id.as_str();
        let timeout = self.effective_scan_timeout(session.app.setting.read().data.db_query_timeout);
        let sessions = sessions_mut(session);
        sessions.open.remove(sub_id);
        let initial = decode_hex(Some(&open.message)).map_err(|reason| neg_err(sub_id, &reason))?;
        if sessions.open.len() >= self.setting.max_sessions {
            return Err(neg_err(
                sub_id,
                "blocked: too many concurrent reconciliations",
            ));
        }
        let permit = self
            .jobs
            .acquire(1, self.setting.max_jobs.get())
            .ok_or_else(|| neg_err(sub_id, "blocked: reconciliation work limit reached"))?;
        let generation = Arc::new(());
        let weak = Arc::downgrade(&generation);
        sessions.open.insert(
            sub_id.to_owned(),
            Entry {
                generation,
                last_active: Instant::now(),
                ready: None,
            },
        );
        let worker = self.clone();
        let id = sub_id.to_owned();
        let cancelled = weak.clone();
        let filter = open.filter.clone();
        Ok(Job {
            id: id.clone(),
            generation: weak,
            admission: Admission::Granted { _permit: permit },
            work: Box::new(move || {
                let snapshot = worker
                    .snapshot(&filter, timeout, &cancelled)
                    .map_err(|err| match err {
                        Error::Db(nostr_relay::db::Error::ScanTimeout) => {
                            neg_err(&id, "blocked: reconciliation scan timed out")
                        }
                        _ => neg_err(&id, &format!("error: {err}")),
                    })?;
                let Some((storage, records)) = snapshot else {
                    let reason = format!(
                        "blocked: too many records for reconciliation (max {})",
                        worker.setting.max_records
                    );
                    return Err(neg_err(&id, &reason));
                };
                let lease = worker
                    .budget
                    .acquire(records, worker.setting.max_total_records)
                    .ok_or_else(|| {
                        neg_err(&id, "blocked: relay is at its reconciliation memory limit")
                    })?;
                let mut negentropy = Negentropy::owned(storage, worker.setting.frame_size_limit)
                    .map_err(|err| neg_err(&id, &format!("error: {err}")))?;
                let out = negentropy
                    .reconcile(&initial)
                    .map_err(|err| neg_err(&id, &format!("invalid: {err}")))?;
                Ok((
                    Reconciliation {
                        negentropy,
                        _lease: lease,
                    },
                    neg_msg(&id, &out),
                ))
            }),
        })
    }

    fn effective_scan_timeout(&self, db_timeout: Option<NonZeroDuration>) -> Duration {
        Duration::from(db_timeout.map_or(self.setting.scan_timeout, |timeout| {
            timeout.min(self.setting.scan_timeout)
        }))
    }

    fn reconcile(
        &self,
        session: &mut Session,
        sub_id: &str,
        values: &[Value],
    ) -> Result<Job, OutgoingMessage> {
        let sessions = sessions_mut(session);
        let Some(entry) = sessions.open.get_mut(sub_id) else {
            return Err(neg_err(sub_id, "closed: no such reconciliation"));
        };
        // Protocol errors close the reconciliation.
        let Some(mut reconciliation) = entry.ready.take() else {
            sessions.open.remove(sub_id);
            return Err(neg_err(sub_id, "blocked: reconciliation is busy"));
        };
        let query = match decode_hex(values.get(1).and_then(Value::as_str)) {
            Ok(query) => query,
            Err(reason) => {
                sessions.open.remove(sub_id);
                return Err(neg_err(sub_id, &reason));
            }
        };
        entry.last_active = Instant::now();
        let generation = Arc::downgrade(&entry.generation);
        let id = sub_id.to_owned();
        Ok(Job {
            id: id.clone(),
            generation,
            admission: Admission::Queued {
                jobs: self.jobs.clone(),
                max_jobs: self.setting.max_jobs.get(),
            },
            work: Box::new(move || {
                let out = reconciliation
                    .negentropy
                    .reconcile(&query)
                    .map_err(|err| neg_err(&id, &format!("invalid: {err}")))?;
                Ok((reconciliation, neg_msg(&id, &out)))
            }),
        })
    }

    fn schedule(mut job: Job, session: &mut Session, ctx: &mut <Session as actix::Actor>::Context) {
        let id = job.id.clone();
        let generation = job.generation.clone();
        let future = async move {
            match job.admit().await {
                Ok(()) => actix_web::rt::task::spawn_blocking(move || job.run()).await,
                Err(out) => Ok(Err(out)),
            }
        }
        .into_actor(session)
        .map(move |result, session, ctx| {
            let result = result.unwrap_or_else(|err| {
                Err(neg_err(
                    &id,
                    &format!("error: reconciliation worker failed: {err}"),
                ))
            });
            let ready = result.is_ok();
            if let Some(out) = Self::complete(session, &id, &generation, result) {
                if ready {
                    Self::start_idle_sweep(session, ctx);
                }
                ctx.text(out.0);
            }
        });
        ctx.spawn(future);
    }

    fn complete(
        session: &mut Session,
        id: &str,
        generation: &Weak<()>,
        result: JobResult,
    ) -> Option<OutgoingMessage> {
        let sessions = session.get_mut::<Sessions>()?;
        let entry = sessions.open.get_mut(id)?;
        if !generation.ptr_eq(&Arc::downgrade(&entry.generation)) {
            return None;
        }
        match result {
            Ok((reconciliation, out)) => {
                entry.ready = Some(reconciliation);
                entry.last_active = Instant::now();
                Some(out)
            }
            Err(out) => {
                sessions.open.remove(id);
                Some(out)
            }
        }
    }

    /// Start one watcher per connection on first use, even if expiry is
    /// currently disabled, so a reload can enable it on a quiet connection.
    /// It polls every second so reloaded timeouts take effect promptly.
    fn start_idle_sweep(session: &mut Session, ctx: &mut <Session as actix::Actor>::Context) {
        if std::mem::replace(&mut sessions_mut(session).idle_sweep_started, true) {
            return;
        }
        ctx.run_interval(Duration::from_secs(1), |session, ctx| {
            if session.get::<Sessions>().is_none_or(|s| s.open.is_empty()) {
                return;
            }
            let timeout = session
                .app
                .setting
                .read()
                .get_extension::<NegentropySetting>()
                .and_then(|setting| setting.idle_timeout);
            if let Some(timeout) = timeout {
                expire_idle(session, ctx, timeout.into());
            }
        });
    }
}

/// Drop reconciliations idle longer than `timeout`, telling the client which
/// went away so it does not wait on a session the relay has forgotten.
fn expire_idle(
    session: &mut Session,
    ctx: &mut <Session as actix::Actor>::Context,
    timeout: Duration,
) {
    let Some(sessions) = session.get_mut::<Sessions>() else {
        return;
    };
    let now = Instant::now();
    let expired: Vec<String> = sessions
        .open
        .iter()
        .filter(|(_, reconciliation)| now.duration_since(reconciliation.last_active) > timeout)
        .map(|(sub_id, _)| sub_id.clone())
        .collect();
    for sub_id in expired {
        sessions.open.remove(&sub_id);
        debug!(sub_id, "reconciliation timed out");
        ctx.text(neg_err(&sub_id, "closed: reconciliation timed out").0);
    }
}

fn sessions_mut(session: &mut Session) -> &mut Sessions {
    if session.get::<Sessions>().is_none() {
        session.set(Sessions::default());
    }
    session
        .get_mut::<Sessions>()
        .expect("just-inserted session state")
}

/// Also used when authentication rejects a replacement NEG-OPEN before this
/// extension receives it: NEG-ERR always closes the named reconciliation.
pub(crate) fn close(session: &mut Session, sub_id: &str) {
    if let Some(sessions) = session.get_mut::<Sessions>() {
        sessions.open.remove(sub_id);
    }
}

fn neg_msg(sub_id: &str, message: &[u8]) -> OutgoingMessage {
    OutgoingMessage(json!([NEG_MSG, sub_id, hex::encode(message)]).to_string())
}

fn neg_err(sub_id: &str, reason: &str) -> OutgoingMessage {
    OutgoingMessage::neg_err(sub_id, reason)
}

fn decode_hex(raw: Option<&str>) -> Result<Vec<u8>, String> {
    let raw = raw.ok_or_else(|| "invalid: missing negentropy message".to_owned())?;
    let decoded =
        hex::decode(raw).map_err(|err| format!("invalid: malformed negentropy message: {err}"))?;
    input::validate(&decoded)
        .map_err(|err| format!("invalid: malformed negentropy message: {err}"))?;
    Ok(decoded)
}

impl Extension for Negentropies {
    fn name(&self) -> &'static str {
        "negentropy"
    }

    fn setting(&mut self, setting: &SettingWrapper) {
        let mut w = setting.write();
        let mut parsed: NegentropySetting = w.parse_extension(self.name());

        if parsed.frame_size_limit != 0 && parsed.frame_size_limit < MIN_FRAME_SIZE_LIMIT {
            warn!(
                frame_size_limit = parsed.frame_size_limit,
                "negentropy frame_size_limit must be 0 or at least {MIN_FRAME_SIZE_LIMIT}; raising it"
            );
            parsed.frame_size_limit = MIN_FRAME_SIZE_LIMIT;
        }

        self.setting = parsed;
        // The idle sweep reads the current timeout from the shared settings.
        w.set_extension(self.setting.clone());
        if self.setting.enabled {
            w.add_nip(77);
        }
    }

    fn message(
        &self,
        msg: ClientMessage,
        session: &mut Session,
        ctx: &mut <Session as actix::Actor>::Context,
    ) -> ExtensionMessageResult {
        if !self.setting.enabled {
            return ExtensionMessageResult::Continue(msg);
        }

        let job = match &msg.msg {
            IncomingMessage::NegOpen(open) => self.open(session, open),
            IncomingMessage::Unknown(command, values) => {
                if !matches!(command.as_str(), NEG_MSG | NEG_CLOSE) {
                    return ExtensionMessageResult::Continue(msg);
                }
                let Some(id) = values.first().and_then(Value::as_str) else {
                    return OutgoingMessage::notice(
                        "invalid: NEG message requires a subscription id",
                    )
                    .into();
                };
                if command == NEG_CLOSE {
                    close(session, id);
                    return ExtensionMessageResult::Ignore;
                }
                self.reconcile(session, id, values)
            }
            _ => return ExtensionMessageResult::Continue(msg),
        };
        match job {
            Ok(job) => {
                Self::schedule(job, session, ctx);
                ExtensionMessageResult::Ignore
            }
            Err(out) => out.into(),
        }
    }
}

mod input {
    //! Validate V1 framing before handing untrusted input to negentropy 0.5.
    //! Its ID-list decoder reserves memory from the declared count before checking
    //! the payload length. This allocation-free pass bounds that count by bytes
    //! actually present, independently of snapshot and response size limits.

    use negentropy::{FINGERPRINT_SIZE, ID_SIZE, PROTOCOL_VERSION};

    pub(super) fn validate(mut input: &[u8]) -> Result<(), &'static str> {
        let version = take(&mut input, 1)?[0];
        if u64::from(version) != PROTOCOL_VERSION {
            // Let the library handle invalid versions and version negotiation;
            // neither path decodes ranges or allocates from a client count.
            return Ok(());
        }

        while !input.is_empty() {
            varint(&mut input)?; // Timestamp delta.
            let prefix_len = varint(&mut input)?;
            if prefix_len > ID_SIZE as u64 {
                return Err("ID prefix is too long");
            }
            take(&mut input, prefix_len as usize)?;
            match varint(&mut input)? {
                0 => {} // Skip.
                1 => {
                    take(&mut input, FINGERPRINT_SIZE)?;
                }
                2 => {
                    let count = varint(&mut input)?;
                    if count > (input.len() / ID_SIZE) as u64 {
                        return Err("ID count exceeds the remaining message");
                    }
                    // The length check also makes the cast and product safe.
                    take(&mut input, count as usize * ID_SIZE)?;
                }
                _ => return Err("unknown range mode"),
            }
        }
        Ok(())
    }

    fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], &'static str> {
        if count > input.len() {
            return Err("message ends prematurely");
        }
        let (head, tail) = input.split_at(count);
        *input = tail;
        Ok(head)
    }

    fn varint(input: &mut &[u8]) -> Result<u64, &'static str> {
        let mut value = 0u64;
        loop {
            let byte = take(input, 1)?[0];
            value = value
                .checked_mul(128)
                .and_then(|value| value.checked_add(u64::from(byte & 0x7f)))
                .ok_or("varint overflows u64")?;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_counts_without_corresponding_ids() {
            // Previously this nine-byte frame attempted a 17.7 GB allocation.
            assert!(validate(&[0x61, 0, 0, 2, 0x81, 0x80, 0x80, 0x80, 0]).is_err());
            assert!(validate(&[0x61, 0, 0, 2, 1]).is_err());
            let mut short_id = vec![0x61, 0, 0, 2, 1];
            short_id.extend([0; ID_SIZE - 1]);
            assert!(validate(&short_id).is_err());
        }

        #[test]
        fn rejects_truncated_and_overflowing_fields() {
            for query in [
                &[][..],
                &[0x61, 0x80],
                &[0x61, 0, 0x80],
                &[0x61, 0, 33],
                &[0x61, 0, 1],
                &[0x61, 0, 0],
                &[0x61, 0, 0, 1],
                &[0x61, 0, 0, 2, 0x80],
                &[0x61, 0, 0, 3],
            ] {
                assert!(validate(query).is_err(), "accepted {query:?}");
            }
            let mut overflow = vec![0x61, 0, 0, 2];
            overflow.extend([0xff; 10]);
            overflow.push(0x7f);
            assert!(validate(&overflow).is_err());
        }

        #[test]
        fn accepts_valid_ranges_and_checks_later_counts() {
            let mut query = vec![0x61, 1, 0, 0, 1, 0, 1];
            query.extend([0; FINGERPRINT_SIZE]);
            query.extend([0, 0, 2, 1]);
            query.extend([0; ID_SIZE]);
            assert!(validate(&query).is_ok());
            query.extend([0, 0, 2, 1]);
            assert!(validate(&query).is_err());
            assert!(validate(&[0x61]).is_ok());
            assert!(validate(&[0x61, 0, 0, 2, 0]).is_ok());
            assert!(validate(&[0x62, 0xff]).is_ok());
        }

        #[test]
        fn validates_multi_round_library_messages() {
            use negentropy::{Id, Negentropy, NegentropyStorageVector};

            let storage = |range: std::ops::Range<u64>| {
                let mut storage = NegentropyStorageVector::new();
                for index in range {
                    let mut id = [0; ID_SIZE];
                    id[24..].copy_from_slice(&index.to_be_bytes());
                    // Shared timestamps force ID prefixes in range boundaries.
                    storage.insert(index / 3, Id::from_byte_array(id)).unwrap();
                }
                storage.seal().unwrap();
                storage
            };
            let mut relay = Negentropy::owned(storage(0..300), 4096).unwrap();
            let mut client = Negentropy::owned(storage(100..400), 4096).unwrap();
            let mut query = client.initiate().unwrap();
            let mut have = Vec::new();
            let mut need = Vec::new();
            let mut rounds = 0;
            loop {
                rounds += 1;
                assert!(rounds < 100, "reconciliation did not converge");
                validate(&query).unwrap();
                let reply = relay.reconcile(&query).unwrap();
                validate(&reply).unwrap();
                match client
                    .reconcile_with_ids(&reply, &mut have, &mut need)
                    .unwrap()
                {
                    Some(next) => query = next,
                    None => break,
                }
            }
            assert!(rounds > 1);
            assert_eq!(have.len(), 100);
            assert_eq!(need.len(), 100);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_test_app;
    use actix_web::web;
    use actix_web_actors::ws;
    use anyhow::Result;
    use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
    use negentropy::NegentropyStorageVector;
    use nostr_relay::create_web_app;
    use nostr_relay::db::{
        now,
        secp256k1::{rand::thread_rng, Keypair},
        Event,
    };

    /// A client-side WebSocket, as `TestServer::ws_at` returns it.
    trait Ws:
        Sink<ws::Message, Error = ws::ProtocolError>
        + Stream<Item = std::result::Result<ws::Frame, ws::ProtocolError>>
        + Unpin
    {
    }
    impl<T> Ws for T where
        T: Sink<ws::Message, Error = ws::ProtocolError>
            + Stream<Item = std::result::Result<ws::Frame, ws::ProtocolError>>
            + Unpin
    {
    }

    /// `["NEG-MSG"|"NEG-ERR", sub_id, payload]`.
    type Reply = (String, String, String);

    async fn send(framed: &mut impl Ws, msg: Value) -> Result<()> {
        Ok(framed
            .send(ws::Message::Text(msg.to_string().into()))
            .await?)
    }

    async fn recv<T: serde::de::DeserializeOwned>(framed: &mut impl Ws) -> Result<T> {
        match framed.next().await.unwrap()? {
            ws::Frame::Text(text) => Ok(serde_json::from_slice(&text)?),
            frame => Err(anyhow::anyhow!("invalid frame type: {frame:?}")),
        }
    }

    /// Open `sub` over `filter` and run rounds until `client` is satisfied.
    /// Returns the sorted ids only the client has, the sorted ids only the
    /// relay has, and the byte size of every relay reply.
    async fn drive(
        framed: &mut impl Ws,
        sub: &str,
        filter: Value,
        client: &mut Negentropy<'static, NegentropyStorageVector>,
    ) -> Result<(Vec<Id>, Vec<Id>, Vec<usize>)> {
        let initial = client.initiate()?;
        send(framed, json!([NEG_OPEN, sub, filter, hex::encode(initial)])).await?;
        let (mut have, mut need, mut sizes) = (Vec::new(), Vec::new(), Vec::new());
        loop {
            let res: Reply = recv(framed).await?;
            assert_eq!(res.0, NEG_MSG, "unexpected message: {res:?}");
            assert_eq!(res.1, sub);
            let reply = hex::decode(&res.2)?;
            sizes.push(reply.len());
            match client.reconcile_with_ids(&reply, &mut have, &mut need)? {
                Some(next) => send(framed, json!([NEG_MSG, sub, hex::encode(next)])).await?,
                None => break,
            }
        }
        have.sort();
        need.sort();
        Ok((have, need, sizes))
    }

    fn ids(events: &[Event]) -> Vec<Id> {
        let mut ids: Vec<Id> = events
            .iter()
            .map(|e| Id::from_byte_array(*e.id()))
            .collect();
        ids.sort();
        ids
    }

    /// The next frame an actor under test writes, raw.
    async fn next_frame<B: AsRef<[u8]>, E: std::fmt::Debug>(
        stream: &mut (impl Stream<Item = std::result::Result<B, E>> + Unpin),
    ) -> Result<Vec<u8>> {
        let frame = actix_rt::time::timeout(Duration::from_secs(5), stream.next()).await?;
        Ok(frame.unwrap().unwrap().as_ref().to_vec())
    }

    fn contains(frame: &[u8], needle: &str) -> bool {
        frame
            .windows(needle.len())
            .any(|part| part == needle.as_bytes())
    }

    fn neg_open(sub: &str, filter: Value, message: &str) -> NegOpen {
        NegOpen {
            id: sub.to_owned(),
            filter: serde_json::from_value(filter).unwrap(),
            message: message.to_owned(),
        }
    }

    async fn spawn(mut job: Job) -> Result<JobResult> {
        job.admit().await.expect("open reconciliation");
        Ok(actix_web::rt::task::spawn_blocking(move || job.run()).await?)
    }

    async fn run_job(
        session: &mut Session,
        job: Result<Job, OutgoingMessage>,
    ) -> Result<OutgoingMessage> {
        let job = match job {
            Ok(job) => job,
            Err(out) => return Ok(out),
        };
        let id = job.id.clone();
        let generation = job.generation.clone();
        let result = spawn(job).await?;
        Ok(Negentropies::complete(session, &id, &generation, result).expect("current generation"))
    }

    #[actix_rt::test]
    async fn toml_zero_disables_expiry_without_disabling_negentropy() -> Result<()> {
        use std::io::Write as _;
        let app = create_test_app("neg-toml")?;
        let mut extension = Negentropies::new(app.db.clone());
        for (line, expected) in [
            ("idle_timeout = 0", None),
            ("idle_timeout = \"0s\"", None),
            ("idle_timeout = \"2s\"", Some(Duration::from_secs(2))),
            ("", Some(Duration::from_secs(300))),
        ] {
            let mut file = tempfile::Builder::new().suffix(".toml").tempfile()?;
            writeln!(file, "[negentropy]\nenabled = true\n{line}")?;
            let setting: SettingWrapper = nostr_relay::Setting::read(file.path(), None)?.into();
            extension.setting(&setting);
            assert!(extension.setting.enabled, "{line}");
            assert_eq!(extension.setting.idle_timeout.map(Duration::from), expected);
            assert!(setting.read().information.supported_nips.contains(&77));
        }
        let setting: NegentropySetting = serde_json::from_value(json!({"idle_timeout": null}))?;
        assert!(setting.idle_timeout.is_none());
        assert!(serde_json::from_value::<NegentropySetting>(json!({"max_jobs": 0})).is_err());
        assert!(serde_json::from_value::<NegentropySetting>(json!({"scan_timeout": 0})).is_err());
        Ok(())
    }

    #[actix_rt::test]
    async fn job_admission_is_global_and_pending_opens_count_toward_limits() -> Result<()> {
        let app = create_test_app("neg-jobs")?;
        let mut extension = Negentropies::new(app.db.clone());
        extension.setting.max_jobs = NonZeroUsize::new(1).unwrap();
        extension.setting.max_sessions = 1;
        let app = web::Data::new(app);
        let mut first = Session::new("first".to_owned(), app.clone());
        let mut second = Session::new("second".to_owned(), app);
        let values = neg_open("x", json!({}), "61");
        let job = extension.open(&mut first, &values).unwrap();
        let blocked = extension.open(&mut second, &values).err().unwrap();
        assert!(blocked.0.contains("work limit"));
        let blocked = extension
            .open(&mut first, &neg_open("y", json!({}), "61"))
            .err()
            .unwrap();
        assert!(blocked.0.contains("concurrent reconciliations"));
        close(&mut first, "x");
        assert!(extension.open(&mut second, &values).is_err());
        drop(job);
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        let job = extension.open(&mut second, &values);
        assert!(run_job(&mut second, job).await?.0.contains(NEG_MSG));
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        // Reloaded limits apply to admission, without losing existing charges.
        extension.setting.max_jobs = NonZeroUsize::new(2).unwrap();
        let one = extension.open(&mut first, &values).unwrap();
        let two = extension.open(&mut second, &values).unwrap();
        extension.setting.max_jobs = NonZeroUsize::new(1).unwrap();
        drop(one);
        assert!(extension.open(&mut first, &values).is_err());
        drop(two);
        assert!(extension.open(&mut first, &values).is_ok());
        Ok(())
    }

    #[actix_rt::test]
    async fn stale_completions_never_restore_replaced_or_closed_entries() -> Result<()> {
        let app = create_test_app("neg-generations")?;
        app.db.batch_put(test_events(1)?)?;
        let extension = Negentropies::new(app.db.clone());
        let mut session = Session::new("test".to_owned(), web::Data::new(app));
        let values = neg_open("x", json!({}), "61");
        let old = extension.open(&mut session, &values).unwrap();
        let generation = old.generation.clone();
        let result = spawn(old).await?;
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 1);
        let replacement = extension.open(&mut session, &values);
        assert!(Negentropies::complete(&mut session, "x", &generation, result).is_none());
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 0);
        run_job(&mut session, replacement).await?;
        let round = extension
            .reconcile(&mut session, "x", &[json!("x"), json!("61")])
            .unwrap();
        let generation = round.generation.clone();
        let result = spawn(round).await?;
        close(&mut session, "x");
        assert!(Negentropies::complete(&mut session, "x", &generation, result).is_none());
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 0);
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[actix_rt::test]
    async fn overlapping_rounds_close_the_busy_reconciliation() -> Result<()> {
        let app = create_test_app("neg-busy")?;
        app.db.batch_put(test_events(1)?)?;
        let extension = Negentropies::new(app.db.clone());
        let mut session = Session::new("test".to_owned(), web::Data::new(app));
        let opening = extension.open(&mut session, &neg_open("x", json!({}), "61"));
        run_job(&mut session, opening).await?;
        let values = [json!("x"), json!("61")];
        let round = extension.reconcile(&mut session, "x", &values).unwrap();
        let error = extension
            .reconcile(&mut session, "x", &values)
            .err()
            .unwrap();
        assert!(error.0.contains("blocked: reconciliation is busy"));
        assert!(round.generation.upgrade().is_none());
        drop(round);
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 0);
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[actix_rt::test]
    async fn sparse_scans_timeout_without_returning_a_partial_snapshot() -> Result<()> {
        let app = create_test_app("neg-scan-deadline")?;
        let key = Keypair::new_global(&mut thread_rng());
        let events = (0..300)
            .map(|i| {
                Event::create(
                    &key,
                    now(),
                    1,
                    vec![vec!["t".to_owned(), "busy".to_owned()]],
                    i.to_string(),
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        app.db.batch_put(events)?;
        let filter = json!({"#t": ["busy"], "authors": ["00".repeat(32)]});
        let parsed: Filter = serde_json::from_value(filter.clone())?;
        {
            let reader = app.db.reader()?;
            let (pairs, complete, stats) = app
                .db
                .iter::<Vec<u8>, _>(&reader, &parsed)?
                .index_pairs(1)?;
            assert!(pairs.is_empty() && complete);
            assert!(stats.scan_index >= 300);
        }
        let mut extension = Negentropies::new(app.db.clone());
        assert_eq!(
            extension.effective_scan_timeout(None),
            Duration::from_secs(5)
        );
        assert_eq!(
            extension.effective_scan_timeout(NonZeroDuration::new(Duration::from_secs(1))),
            Duration::from_secs(1)
        );
        assert_eq!(
            extension.effective_scan_timeout(NonZeroDuration::new(Duration::from_secs(60))),
            Duration::from_secs(5)
        );
        extension.setting.scan_timeout = NonZeroDuration::new(Duration::from_nanos(1)).unwrap();
        let mut session = Session::new("test".to_owned(), web::Data::new(app));
        let job = extension.open(&mut session, &neg_open("x", filter, "61"));
        let out = run_job(&mut session, job).await?;
        assert!(out.0.contains("blocked: reconciliation scan timed out"));
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 0);
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        assert!(sessions_mut(&mut session).open.is_empty());
        Ok(())
    }

    #[actix_rt::test]
    async fn blocked_worker_does_not_block_actor_or_admission_checks() -> Result<()> {
        let app = create_test_app("neg-responsive")?;
        app.db.batch_put(test_events(1)?)?;
        let mut extension = Negentropies::new(app.db.clone());
        extension.setting.max_jobs = NonZeroUsize::new(1).unwrap();
        let app = web::Data::new(app);
        let mut session = Session::new("first".to_owned(), app.clone());
        let mut other = Session::new("other".to_owned(), app);
        let values = neg_open("x", json!({}), "61");
        let mut job = extension.open(&mut session, &values).unwrap();
        let (started, running) = std::sync::mpsc::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let work = job.work;
        job.work = Box::new(move || {
            started.send(()).unwrap();
            gate.recv_timeout(Duration::from_secs(5)).unwrap();
            work()
        });
        let stream =
            ws::WebsocketContext::with_factory(futures_util::stream::pending(), move |ctx| {
                Negentropies::schedule(job, &mut session, ctx);
                let mut notified = false;
                ctx.run_interval(Duration::from_millis(5), move |_, ctx| {
                    if !notified && running.try_recv().is_ok() {
                        notified = true;
                        ctx.text("worker running; actor responsive");
                    }
                });
                session
            });
        futures_util::pin_mut!(stream);
        let frame = next_frame(&mut stream).await?;
        assert!(contains(&frame, "actor responsive"));
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 1);
        let error = extension
            .open(&mut other, &neg_open("other", json!({}), "61"))
            .err()
            .unwrap();
        assert!(error.0.contains("work limit"));
        release.send(())?;
        let frame = next_frame(&mut stream).await?;
        assert!(contains(&frame, NEG_MSG));
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        Ok(())
    }

    /// A completed reconciliation "x" on the returned session, a scan from
    /// another connection holding the relay's only job slot, and a round on
    /// "x" queued behind it.
    async fn queued_round(name: &str) -> Result<(Negentropies, Session, Job, Job)> {
        let app = create_test_app(name)?;
        app.db.batch_put(test_events(1)?)?;
        let mut extension = Negentropies::new(app.db.clone());
        extension.setting.max_jobs = NonZeroUsize::new(1).unwrap();
        let app = web::Data::new(app);
        let mut session = Session::new("first".to_owned(), app.clone());
        let mut other = Session::new("other".to_owned(), app);
        let opening = extension.open(&mut session, &neg_open("x", json!({}), "61"));
        assert!(run_job(&mut session, opening).await?.0.contains(NEG_MSG));
        let scan = extension
            .open(&mut other, &neg_open("x", json!({}), "61"))
            .unwrap();
        let round = extension
            .reconcile(&mut session, "x", &[json!("x"), json!("61")])
            .unwrap();
        assert!(matches!(round.admission, Admission::Queued { .. }));
        Ok((extension, session, scan, round))
    }

    #[actix_rt::test]
    async fn rounds_wait_for_a_job_slot_instead_of_closing() -> Result<()> {
        let (extension, mut session, scan, round) = queued_round("neg-queued-round").await?;
        let stream =
            ws::WebsocketContext::with_factory(futures_util::stream::pending(), move |ctx| {
                Negentropies::schedule(round, &mut session, ctx);
                session
            });
        futures_util::pin_mut!(stream);
        assert!(
            actix_rt::time::timeout(Duration::from_millis(100), stream.next())
                .await
                .is_err()
        );
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 1);
        drop(scan);
        let frame = next_frame(&mut stream).await?;
        assert!(contains(&frame, NEG_MSG));
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[actix_rt::test]
    async fn a_queued_round_is_dropped_once_its_reconciliation_closes() -> Result<()> {
        let (extension, mut session, scan, round) = queued_round("neg-queued-cancel").await?;
        let stream =
            ws::WebsocketContext::with_factory(futures_util::stream::pending(), move |ctx| {
                Negentropies::schedule(round, &mut session, ctx);
                close(&mut session, "x");
                session
            });
        futures_util::pin_mut!(stream);
        drop(scan);
        assert!(
            actix_rt::time::timeout(Duration::from_millis(100), stream.next())
                .await
                .is_err()
        );
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[actix_rt::test]
    async fn worker_panic_releases_job_and_snapshot_and_reports_error() -> Result<()> {
        let app = create_test_app("neg-worker-panic")?;
        app.db.batch_put(test_events(1)?)?;
        let extension = Negentropies::new(app.db.clone());
        let mut session = Session::new("test".to_owned(), web::Data::new(app));
        let opening = extension.open(&mut session, &neg_open("x", json!({}), "61"));
        run_job(&mut session, opening).await?;
        let mut round = extension
            .reconcile(&mut session, "x", &[json!("x"), json!("61")])
            .unwrap();
        let work = round.work;
        round.work = Box::new(move || {
            // Retain the snapshot until unwinding, just as a panicking decoder would.
            let _snapshot = work;
            panic!("controlled worker failure");
        });
        let stream =
            ws::WebsocketContext::with_factory(futures_util::stream::pending(), move |ctx| {
                Negentropies::schedule(round, &mut session, ctx);
                session
            });
        futures_util::pin_mut!(stream);
        let frame = next_frame(&mut stream).await?;
        assert!(contains(&frame, NEG_ERR));
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[actix_rt::test]
    async fn expiry_auth_rejection_and_disconnect_invalidate_pending_results() -> Result<()> {
        for auth in [false, true] {
            let app = create_test_app("neg-pending-close")?;
            app.db.batch_put(test_events(1)?)?;
            let extension = Negentropies::new(app.db.clone());
            let mut session = Session::new("test".to_owned(), web::Data::new(app));
            let job = extension
                .open(&mut session, &neg_open("x", json!({}), "61"))
                .unwrap();
            let generation = job.generation.clone();
            let result = spawn(job).await?;
            let budget = extension.budget.clone();
            let _stream =
                ws::WebsocketContext::with_factory(futures_util::stream::pending(), move |ctx| {
                    if auth {
                        session.app.setting.write().extra.insert(
                            "auth".to_owned(),
                            json!({"enabled": true, "req": {"pubkey_whitelist": []}}),
                        );
                        let mut auth = crate::Auth::new();
                        auth.setting(&session.app.setting);
                        let text = r#"["NEG-OPEN","x",{},"61"]"#;
                        let out = auth.message(
                            ClientMessage::new(
                                0,
                                text.to_owned(),
                                serde_json::from_str(text).unwrap(),
                            ),
                            &mut session,
                            ctx,
                        );
                        assert!(matches!(out, ExtensionMessageResult::Stop(_)));
                    } else {
                        sessions_mut(&mut session)
                            .open
                            .get_mut("x")
                            .unwrap()
                            .last_active = Instant::now() - Duration::from_secs(5);
                        expire_idle(&mut session, ctx, Duration::from_secs(1));
                    }
                    assert!(
                        Negentropies::complete(&mut session, "x", &generation, result).is_none()
                    );
                    assert_eq!(budget.0.load(Ordering::Relaxed), 0);
                    session
                });
        }
        let app = create_test_app("neg-pending-disconnect")?;
        app.db.batch_put(test_events(1)?)?;
        let extension = Negentropies::new(app.db.clone());
        let mut session = Session::new("test".to_owned(), web::Data::new(app));
        let opening = extension.open(&mut session, &neg_open("x", json!({}), "61"));
        run_job(&mut session, opening).await?;
        let mut job = extension
            .reconcile(&mut session, "x", &[json!("x"), json!("61")])
            .unwrap();
        drop(session);
        assert!(job.generation.upgrade().is_none());
        assert!(job.admit().await.is_err());
        drop(job);
        assert_eq!(extension.jobs.0.load(Ordering::Relaxed), 0);
        assert_eq!(extension.budget.0.load(Ordering::Relaxed), 0);
        Ok(())
    }

    /// Build the client side of a reconciliation over `events`.
    fn client(events: &[Event]) -> Result<Negentropy<'static, NegentropyStorageVector>> {
        let mut storage = NegentropyStorageVector::new();
        for event in events {
            storage.insert(event.created_at(), Id::from_byte_array(*event.id()))?;
        }
        storage.seal()?;
        // `initiate()` marks this side as the initiator.
        Ok(Negentropy::owned(storage, 0)?)
    }

    fn test_events(count: u64) -> Result<Vec<Event>> {
        let mut rng = thread_rng();
        let key_pair = Keypair::new_global(&mut rng);
        let start = now();
        (0..count)
            .map(|index| {
                Ok(Event::create(
                    &key_pair,
                    start + index,
                    1000,
                    vec![],
                    format!("test {index}"),
                )?)
            })
            .collect()
    }

    /// Start a relay holding `events`, written straight to the database: a
    /// per-event EVENT/OK round trip would dominate these tests' runtime.
    async fn start_relay(
        name: &str,
        setting: &str,
        events: &[Event],
    ) -> Result<actix_test::TestServer> {
        let app = create_test_app(name)?;
        {
            let mut w = app.setting.write();
            w.extra = serde_json::from_str(setting)?;
        }
        let db = app.db.clone();
        db.batch_put(events.to_vec())?;
        // Search must precede Negentropies, as in the binary.
        #[cfg(feature = "search")]
        let app = app.add_extension(crate::Search::new());
        let app = app.add_extension(Negentropies::new(db));
        let app = web::Data::new(app);
        Ok(actix_test::start(move || create_web_app(app.clone())))
    }

    #[actix_rt::test]
    async fn idle_sweep_starts_only_after_successful_open() -> Result<()> {
        let app = create_test_app("neg-lazy-sweep")?;
        let mut extension = Negentropies::new(app.db.clone());
        extension.setting.idle_timeout = None;
        let app = web::Data::new(app);
        let stream =
            ws::WebsocketContext::with_factory(futures_util::stream::pending(), move |ctx| {
                let mut session = Session::new("127.0.0.1".to_owned(), app);
                extension.connected(&mut session, ctx);
                expire_idle(&mut session, ctx, Duration::from_secs(1));
                assert!(session.get::<Sessions>().is_none());
                let text = r#"["NEG-OPEN","sync",{},"61"]"#;
                assert!(matches!(
                    extension.message(
                        ClientMessage::new(0, text.to_owned(), serde_json::from_str(text).unwrap()),
                        &mut session,
                        ctx
                    ),
                    ExtensionMessageResult::Continue(_)
                ));
                assert!(session.get::<Sessions>().is_none());
                extension.setting.enabled = true;
                assert!(extension
                    .open(&mut session, &neg_open("bad", json!({}), "zz"))
                    .is_err());
                assert!(!session.get::<Sessions>().unwrap().idle_sweep_started);
                let job = extension
                    .open(&mut session, &neg_open("sync", json!({}), "61"))
                    .unwrap();
                assert!(!session.get::<Sessions>().unwrap().idle_sweep_started);
                Negentropies::schedule(job, &mut session, ctx);
                // Observing completion through the output below drives this actor.
                ctx.run_interval(Duration::from_millis(1), |session, ctx| {
                    if session
                        .get::<Sessions>()
                        .is_some_and(|s| s.open.get("sync").is_some_and(|e| e.ready.is_some()))
                    {
                        assert!(session.get::<Sessions>().unwrap().idle_sweep_started);
                        ctx.text("watcher started");
                    }
                });
                session
            });
        futures_util::pin_mut!(stream);
        let first = next_frame(&mut stream).await?;
        assert!(contains(&first, NEG_MSG));
        let next = next_frame(&mut stream).await?;
        assert!(contains(&next, "watcher started"));
        Ok(())
    }

    #[actix_rt::test]
    async fn enabling_negentropy_on_an_existing_connection_starts_expiry() -> Result<()> {
        let app = create_test_app("neg-enable-expiry")?;
        app.db.batch_put(test_events(1)?)?;
        let mut extension = Negentropies::new(app.db.clone());
        let budget = extension.budget.clone();
        let stream =
            ws::WebsocketContext::with_factory(futures_util::stream::pending(), move |ctx| {
                let mut session = Session::new("127.0.0.1".to_owned(), web::Data::new(app));
                extension.connected(&mut session, ctx);
                assert!(session.get::<Sessions>().is_none());

                // Reload after the connection hook, then open via the same
                // extension callback used by incoming WebSocket messages.
                session.app.setting.write().extra.insert(
                    "negentropy".to_owned(),
                    json!({"enabled": true, "idle_timeout": "1s"}),
                );
                extension.setting(&session.app.setting);
                let text = r#"["NEG-OPEN","sync",{},"61"]"#;
                let out = extension.message(
                    ClientMessage::new(0, text.to_owned(), serde_json::from_str(text).unwrap()),
                    &mut session,
                    ctx,
                );
                assert!(matches!(out, ExtensionMessageResult::Ignore));
                session
            });
        futures_util::pin_mut!(stream);
        let opening = next_frame(&mut stream).await?;
        assert!(contains(&opening, NEG_MSG));
        assert_eq!(budget.0.load(Ordering::Relaxed), 1);
        // Drive the actor without a listener or any further client traffic.
        let frame = next_frame(&mut stream).await?;
        let expected = neg_err("sync", "closed: reconciliation timed out").0;
        // A short, unmasked text frame has a two-byte WebSocket header.
        assert_eq!(&frame[2..], expected.as_bytes());
        assert_eq!(budget.0.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[actix_rt::test]
    async fn enabling_idle_timeout_expires_existing_snapshots() -> Result<()> {
        check_idle_timeout_reload(Value::Null, json!("1s"), true).await
    }

    #[actix_rt::test]
    async fn disabling_idle_timeout_preserves_existing_snapshots() -> Result<()> {
        check_idle_timeout_reload(json!("1s"), Value::Null, false).await
    }

    #[actix_rt::test]
    async fn shortening_idle_timeout_expires_existing_snapshots() -> Result<()> {
        check_idle_timeout_reload(json!("60s"), json!("1s"), true).await
    }

    #[actix_rt::test]
    async fn lengthening_idle_timeout_preserves_existing_snapshots() -> Result<()> {
        check_idle_timeout_reload(json!("1s"), json!("60s"), false).await
    }

    async fn check_idle_timeout_reload(
        initial: Value,
        updated: Value,
        should_expire: bool,
    ) -> Result<()> {
        let app = create_test_app("neg-timeout-reload")?;
        app.db.batch_put(test_events(1)?)?;
        app.setting.write().extra.insert(
            "negentropy".to_owned(),
            json!({"enabled": true, "idle_timeout": initial}),
        );
        let extension = Negentropies::new(app.db.clone());
        let budget = extension.budget.clone();
        let app = web::Data::new(app.add_extension(extension));
        let actor_app = app.clone();
        let stream =
            ws::WebsocketContext::with_factory(futures_util::stream::pending(), move |ctx| {
                let mut session = Session::new("127.0.0.1".to_owned(), actor_app.clone());
                let text = r#"["NEG-OPEN","sync",{},"61"]"#;
                let out = actor_app.extensions.read().call_message(
                    ClientMessage::new(0, text.to_owned(), serde_json::from_str(text).unwrap()),
                    &mut session,
                    ctx,
                );
                assert!(matches!(out, ExtensionMessageResult::Ignore));
                session
                    .get_mut::<Sessions>()
                    .unwrap()
                    .open
                    .get_mut("sync")
                    .unwrap()
                    .last_active = Instant::now() - Duration::from_secs(5);
                session
            });
        futures_util::pin_mut!(stream);
        let opening = next_frame(&mut stream).await?;
        assert!(contains(&opening, NEG_MSG));
        assert_eq!(budget.0.load(Ordering::Relaxed), 1);
        // Poll the actor before reloading; no additional NEG messages arrive.
        assert!(
            actix_rt::time::timeout(Duration::from_millis(50), stream.next())
                .await
                .is_err()
        );
        let reload = |timeout: Value| {
            app.setting.write().extra.insert(
                "negentropy".to_owned(),
                json!({"enabled": true, "idle_timeout": timeout}),
            );
            app.extensions.write().call_setting(&app.setting);
        };
        reload(updated);
        if !should_expire {
            // Let two sweep ticks pass. Neither may use the old 1s timeout.
            assert!(
                actix_rt::time::timeout(Duration::from_millis(2100), stream.next())
                    .await
                    .is_err()
            );
            assert_eq!(budget.0.load(Ordering::Relaxed), 1);
            // The watcher must remain alive so expiry can be enabled again.
            reload(json!("1s"));
        }
        let frame = next_frame(&mut stream).await?;
        let expected = neg_err("sync", "closed: reconciliation timed out").0;
        assert_eq!(&frame[2..], expected.as_bytes());
        assert_eq!(budget.0.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[actix_rt::test]
    async fn malformed_requests_close_sessions_and_release_the_budget() -> Result<()> {
        let app = create_test_app("neg-invalid-cleanup")?;
        app.db.batch_put(test_events(1)?)?;
        let mut extension = Negentropies::new(app.db.clone());
        extension.setting.max_sessions = 1;
        extension.setting.max_total_records = 1;
        let mut session = Session::new("127.0.0.1".to_owned(), web::Data::new(app));
        // Missing or malformed filters are parse errors and never get this far.
        let malformed_rounds = [
            json!(["sync"]),
            json!(["sync", "not hex"]),
            json!(["sync", "00"]),
            json!(["sync", "610000028180808000"]),
        ];
        let malformed_opens = ["not hex", "00", "610000028180808000"];
        let malformed = malformed_rounds
            .iter()
            .map(|values| (NEG_MSG, values.clone()))
            .chain(
                malformed_opens
                    .iter()
                    .map(|message| (NEG_OPEN, json!(message))),
            );
        let open = neg_open("sync", json!({}), "61");
        let query = json!(["sync", "61"]);
        for payload in ["61", "zz"] {
            let values = json!(["ghost", payload]);
            let job = extension.reconcile(&mut session, "ghost", values.as_array().unwrap());
            let out = run_job(&mut session, job).await?;
            let res: Value = serde_json::from_str(&out.0)?;
            assert_eq!(res[0], NEG_ERR);
            assert_eq!(res[2], "closed: no such reconciliation");
        }
        for (command, request) in malformed {
            let job = extension.open(&mut session, &open);
            let out = run_job(&mut session, job).await?;
            let res: Value = serde_json::from_str(&out.0)?;
            assert_eq!(
                res[0], NEG_MSG,
                "opening before {command} {request}: {res:?}"
            );

            let job = if command == NEG_OPEN {
                let message = request.as_str().unwrap();
                extension.open(&mut session, &neg_open("sync", json!({}), message))
            } else {
                extension.reconcile(&mut session, "sync", request.as_array().unwrap())
            };
            let out = run_job(&mut session, job).await?;
            let res: Value = serde_json::from_str(&out.0)?;
            assert_eq!(res[0], NEG_ERR, "{command} {request}: {res:?}");
            assert!(res[2].as_str().unwrap().starts_with("invalid:"));

            let job = extension.reconcile(&mut session, "sync", query.as_array().unwrap());
            let out = run_job(&mut session, job).await?;
            let res: Value = serde_json::from_str(&out.0)?;
            assert_eq!(res[0], NEG_ERR);
            assert_eq!(res[2], "closed: no such reconciliation");

            // A different id proves both the session slot and its one-record
            // budget were released, rather than reclaimed by a replacement.
            let job = extension.open(&mut session, &neg_open("released", json!({}), "61"));
            let out = run_job(&mut session, job).await?;
            let res: Value = serde_json::from_str(&out.0)?;
            assert_eq!(res[0], NEG_MSG, "budget after {request}: {res:?}");
            close(&mut session, "released");
        }
        Ok(())
    }

    #[cfg(feature = "search")]
    #[actix_rt::test]
    async fn search_snapshot_contains_only_matching_events() -> Result<()> {
        let app = create_test_app("neg-search-snapshot")?;
        let key_pair = Keypair::new_global(&mut thread_rng());
        let mut events = Vec::new();
        for content in ["nostr alpha", "unrelated", "nostr beta"] {
            let mut event = Event::create(&key_pair, now(), 1, vec![], content.to_owned())?;
            event.build_note_words();
            events.push(event);
        }
        let expected = vec![
            Id::from_byte_array(*events[0].id()),
            Id::from_byte_array(*events[2].id()),
        ];
        app.db.batch_put(events)?;
        let extension = Negentropies::new(app.db.clone());
        let mut session = Session::new("127.0.0.1".to_owned(), web::Data::new(app));
        let mut client = client(&[])?;
        let mut open = neg_open(
            "sync",
            json!({"search": "nostr", "kinds": [1]}),
            &hex::encode(client.initiate()?),
        );
        open.filter.build_words();
        let job = extension.open(&mut session, &open);
        let out = run_job(&mut session, job).await?;
        let res: Reply = serde_json::from_str(&out.0)?;
        assert_eq!(res.0, NEG_MSG);
        let mut have = Vec::new();
        let mut need = Vec::new();
        assert!(client
            .reconcile_with_ids(&hex::decode(res.2)?, &mut have, &mut need)?
            .is_none());
        assert!(have.is_empty());
        let mut expected = expected;
        expected.sort();
        need.sort();
        assert_eq!(need, expected);
        Ok(())
    }

    #[cfg(feature = "search")]
    #[actix_rt::test]
    async fn search_reconciles_the_same_events_as_req() -> Result<()> {
        let key_pair = Keypair::new_global(&mut thread_rng());
        let mut events = Vec::new();
        for content in ["nostr alpha", "unrelated", "nostr beta"] {
            let mut event = Event::create(&key_pair, now(), 1, vec![], content.to_owned())?;
            event.build_note_words();
            events.push(event);
        }
        for (enabled, matching) in [(true, 2), (false, 0)] {
            let mut srv = start_relay(
                &format!("neg-search-{enabled}"),
                &format!(
                    r#"{{"negentropy": {{"enabled": true}}, "search": {{"enabled": {enabled}}}}}"#
                ),
                &events,
            )
            .await?;
            let mut framed = srv.ws_at("/").await.unwrap();
            let filter = json!({"search": "nostr", "kinds": [1]});
            send(&mut framed, json!(["REQ", "read", filter])).await?;
            let mut expected = Vec::new();
            loop {
                let res: Value = recv(&mut framed).await?;
                if res[0] == "EOSE" {
                    break;
                }
                assert_eq!(res[0], "EVENT");
                let event: Event = serde_json::from_value(res[2].clone())?;
                expected.push(Id::from_byte_array(*event.id()));
            }
            assert_eq!(expected.len(), matching, "search enabled: {enabled}");

            let (have, need, _) = drive(&mut framed, "sync", filter, &mut client(&[])?).await?;
            assert!(have.is_empty());
            expected.sort();
            assert_eq!(need, expected, "search enabled: {enabled}");
        }
        Ok(())
    }

    #[actix_rt::test]
    async fn neg_open_obeys_the_req_filter_limitations() -> Result<()> {
        let mut srv = start_relay(
            "neg-limitation",
            r#"{"negentropy": {"enabled": true}}"#,
            &[],
        )
        .await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        let long = "x".repeat(101);
        send(&mut framed, json!([NEG_OPEN, long, {}, "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.1, long);
        assert!(
            res.2.starts_with("invalid:") && res.2.contains("max_subid_length"),
            "got {}",
            res.2
        );

        // An id prefix is a parse error too, as it is for REQ.
        for filter in [json!({"kinds": "invalid"}), json!({"ids": ["abcd"]})] {
            send(&mut framed, json!([NEG_OPEN, "bad", filter, "61"])).await?;
            let res: (String, String) = recv(&mut framed).await?;
            assert_eq!(res.0, "NOTICE");
            assert!(res.1.starts_with("json error:"), "got {}", res.1);
        }

        send(
            &mut framed,
            json!([NEG_OPEN, "full", {"ids": ["00".repeat(32)]}, "61"]),
        )
        .await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_MSG, "got {res:?}");
        Ok(())
    }

    #[actix_rt::test]
    async fn auth_rejection_closes_an_existing_reconciliation() -> Result<()> {
        let app = create_test_app("neg-auth-cleanup")?;
        app.setting.write().extra.insert(
            "negentropy".to_owned(),
            json!({"enabled": true, "max_total_records": 1}),
        );
        let db = app.db.clone();
        db.batch_put(test_events(1)?)?;
        let app = web::Data::new(
            app.add_extension(crate::Auth::new())
                .add_extension(Negentropies::new(db)),
        );
        let server_app = app.clone();
        let mut srv = actix_test::start(move || create_web_app(server_app.clone()));
        let mut framed = srv.ws_at("/").await.unwrap();
        send(&mut framed, json!([NEG_OPEN, "sync", {}, "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_MSG);

        // A configuration reload can deny a replacement before NEG-OPEN ever
        // reaches the negentropy extension.
        app.setting.write().extra.insert(
            "auth".to_owned(),
            json!({"enabled": true, "req": {"pubkey_whitelist": []}}),
        );
        app.extensions.write().call_setting(&app.setting);
        send(&mut framed, json!([NEG_OPEN, "sync", {}, "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert!(res.2.starts_with("auth-required:"));
        send(&mut framed, json!([NEG_MSG, "sync", "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.2, "closed: no such reconciliation");

        app.setting
            .write()
            .extra
            .insert("auth".to_owned(), json!({"enabled": false}));
        app.extensions.write().call_setting(&app.setting);
        send(&mut framed, json!([NEG_OPEN, "released", {}, "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_MSG, "budget should be released: {res:?}");
        Ok(())
    }

    #[actix_rt::test]
    async fn reconciles_missing_events_both_ways() -> Result<()> {
        // The relay holds events 0..8, the client holds 4..12. Each side is
        // missing four events the other has.
        let all = test_events(12)?;
        let mut srv = start_relay(
            "neg-roundtrip",
            r#"{"negentropy": {"enabled": true}}"#,
            &all[0..8],
        )
        .await?;
        let mut framed = srv.ws_at("/").await.unwrap();
        let mut client = client(&all[4..12])?;
        let (have, need, _) =
            drive(&mut framed, "sub", json!({"kinds": [1000]}), &mut client).await?;
        // `have` is what the client holds and the relay does not (events 8..12),
        // `need` is what the relay holds and the client does not (events 0..4).
        assert_eq!(have, ids(&all[8..12]));
        assert_eq!(need, ids(&all[0..4]));
        Ok(())
    }

    #[actix_rt::test]
    async fn identical_sets_reconcile_with_no_differences() -> Result<()> {
        let all = test_events(6)?;
        let mut srv = start_relay(
            "neg-identical",
            r#"{"negentropy": {"enabled": true}}"#,
            &all,
        )
        .await?;
        let mut framed = srv.ws_at("/").await.unwrap();
        let mut client = client(&all)?;
        let (have, need, sizes) =
            drive(&mut framed, "same", json!({"kinds": [1000]}), &mut client).await?;
        assert_eq!(sizes.len(), 1, "reconciliation should finish in one round");
        assert!(have.is_empty());
        assert!(need.is_empty());
        Ok(())
    }

    #[actix_rt::test]
    async fn rejects_a_set_larger_than_max_records() -> Result<()> {
        let all = test_events(5)?;
        let mut srv = start_relay(
            "neg-max-records",
            r#"{"negentropy": {"enabled": true, "max_records": 3}}"#,
            &all,
        )
        .await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        let initial = hex::encode(client(&all)?.initiate()?);
        send(
            &mut framed,
            json!(["NEG-OPEN", "big", {"kinds": [1000]}, initial]),
        )
        .await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.1, "big");
        assert_eq!(
            res.2,
            "blocked: too many records for reconciliation (max 3)"
        );
        Ok(())
    }

    #[actix_rt::test]
    async fn unknown_and_closed_sessions_report_neg_err() -> Result<()> {
        let mut srv =
            start_relay("neg-unknown", r#"{"negentropy": {"enabled": true}}"#, &[]).await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        // NEG-MSG without a preceding NEG-OPEN.
        send(&mut framed, json!(["NEG-MSG", "ghost", "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.2, "closed: no such reconciliation");

        // An unknown id is closed regardless of its payload.
        send(&mut framed, json!(["NEG-MSG", "ghost", "zz"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.2, "closed: no such reconciliation");

        send(&mut framed, json!(["NEG-OPEN", "open", {}, "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_MSG);

        // Malformed hex for an open reconciliation reports invalid and closes it.
        send(&mut framed, json!(["NEG-MSG", "open", "zz"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert!(res.2.starts_with("invalid:"), "got {}", res.2);
        send(&mut framed, json!(["NEG-MSG", "open", "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.2, "closed: no such reconciliation");
        Ok(())
    }

    #[actix_rt::test]
    async fn neg_close_forgets_the_reconciliation() -> Result<()> {
        let all = test_events(4)?;
        let mut srv =
            start_relay("neg-close", r#"{"negentropy": {"enabled": true}}"#, &all).await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        let mut client = client(&all[0..2])?;
        let initial = client.initiate()?;
        send(
            &mut framed,
            json!(["NEG-OPEN", "bye", {"kinds": [1000]}, hex::encode(&initial)]),
        )
        .await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_MSG);

        send(&mut framed, json!(["NEG-CLOSE", "bye"])).await?;

        // The next NEG-MSG for that id must be unknown to the relay.
        send(&mut framed, json!(["NEG-MSG", "bye", "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.2, "closed: no such reconciliation");
        Ok(())
    }

    /// Expiry driven only by incoming NEG messages would pin the snapshot for
    /// the life of a quiet connection -- the case `idle_timeout` exists for.
    #[actix_rt::test]
    async fn idle_reconciliations_expire_without_client_traffic() -> Result<()> {
        let all = test_events(4)?;
        let mut srv = start_relay(
            "neg-idle",
            r#"{"negentropy": {"enabled": true, "idle_timeout": "1s"}}"#,
            &all,
        )
        .await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        let mut client = client(&all[0..2])?;
        let initial = client.initiate()?;
        send(
            &mut framed,
            json!(["NEG-OPEN", "idle", {"kinds": [1000]}, hex::encode(&initial)]),
        )
        .await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_MSG);

        // Send nothing: the sweep must close it and say so unprompted.
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.1, "idle");
        assert_eq!(res.2, "closed: reconciliation timed out");

        send(&mut framed, json!(["NEG-MSG", "idle", "61"])).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.2, "closed: no such reconciliation");
        Ok(())
    }

    /// `max_records` and `max_sessions` bound one connection; this bounds the
    /// relay.
    #[actix_rt::test]
    async fn a_snapshot_over_the_relay_budget_is_refused() -> Result<()> {
        let all = test_events(4)?;
        let mut srv = start_relay(
            "neg-budget",
            r#"{"negentropy": {"enabled": true, "max_total_records": 2}}"#,
            &all,
        )
        .await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        let initial = hex::encode(client(&all[0..2])?.initiate()?);
        let open = |sub: &str, filter: Value| json!(["NEG-OPEN", sub, filter, initial]);

        // Four events, a ceiling of two: refused rather than truncated.
        send(&mut framed, open("big", json!({"kinds": [1000]}))).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(
            res.2,
            "blocked: relay is at its reconciliation memory limit"
        );

        // One inside the ceiling is accepted...
        let one = json!({"kinds": [1000], "since": all[3].created_at()});
        send(&mut framed, open("small", one.clone())).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_MSG, "got {res:?}");

        // ...and closing it repays the budget.
        send(&mut framed, json!(["NEG-CLOSE", "small"])).await?;
        send(&mut framed, open("again", one)).await?;
        let res: Reply = recv(&mut framed).await?;
        assert_eq!(res.0, NEG_MSG, "got {res:?}");
        Ok(())
    }

    #[actix_rt::test]
    async fn disabled_extension_ignores_neg_messages() -> Result<()> {
        let mut srv =
            start_relay("neg-disabled", r#"{"negentropy": {"enabled": false}}"#, &[]).await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        send(&mut framed, json!(["NEG-OPEN", "off", {}, "61"])).await?;
        // The extension does not answer, so NEG-OPEN falls through to the core
        // as an unsupported command instead of opening a reconciliation.
        let res: (String, String) = recv(&mut framed).await?;
        assert_eq!(res.0, "NOTICE");
        assert_eq!(res.1, "Unsupported message");
        Ok(())
    }

    /// A client with an empty set opens with a five-byte message asking for
    /// every matching id; `frame_size_limit` keeps the answer from arriving as
    /// one enormous frame. The protocol minimum limit lets a small event count
    /// force several rounds.
    #[actix_rt::test]
    async fn an_empty_client_set_gets_a_bounded_response() -> Result<()> {
        let limit = MIN_FRAME_SIZE_LIMIT as usize;
        let all = test_events(300)?;
        let mut srv = start_relay(
            "neg-amplification",
            r#"{"negentropy": {"enabled": true, "frame_size_limit": 4096}}"#,
            &all,
        )
        .await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        let mut client = client(&[])?;
        let (have, need, sizes) =
            drive(&mut framed, "flood", json!({"kinds": [1000]}), &mut client).await?;
        assert!(sizes.iter().all(|size| *size <= limit), "{sizes:?}");
        // More than one round proves the response was actually split rather
        // than fitting under the limit by accident.
        assert!(sizes.len() > 1, "expected a split response, got {sizes:?}");
        assert!(have.is_empty());
        assert_eq!(need, ids(&all));
        Ok(())
    }

    #[test]
    fn frame_size_limit_below_the_protocol_minimum_is_raised() {
        let setting: SettingWrapper = nostr_relay::setting::Setting::default().into();
        {
            let mut w = setting.write();
            w.extra = serde_json::from_str(
                r#"{"negentropy": {"enabled": true, "frame_size_limit": 1024}}"#,
            )
            .unwrap();
        }

        let mut ext = Negentropies::new(Arc::new(
            nostr_relay::db::Db::open(crate::temp_data_path("neg-frame").unwrap().path()).unwrap(),
        ));
        ext.setting(&setting);
        assert_eq!(ext.setting.frame_size_limit, MIN_FRAME_SIZE_LIMIT);
        assert!(setting.read().information.supported_nips.contains(&77));
    }
}
