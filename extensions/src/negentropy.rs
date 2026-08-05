//! [NIP-77](https://nips.be/77) negentropy set reconciliation.
//!
//! `NEG-OPEN` snapshots the `(created_at, id)` pairs a filter matches, then
//! `NEG-MSG` rounds reconcile that snapshot against the client's own set. The
//! relay is always the non-initiator: it answers every message the client
//! sends and lets the client decide when the exchange is finished.

use actix::AsyncContext as _;
use negentropy::{Id, Negentropy, NegentropyStorageVector};
use nostr_relay::{
    db::{Db, Filter},
    duration::NonZeroDuration,
    message::{ClientMessage, IncomingMessage, OutgoingMessage},
    setting::SettingWrapper,
    Error, Extension, ExtensionMessageResult, Session,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
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

    /// Largest event set a single `NEG-OPEN` may reconcile over. A filter
    /// matching more than this is rejected rather than reconciled against a
    /// truncated set, which would report differences that do not exist.
    pub max_records: usize,

    /// Concurrent reconciliations allowed per connection.
    pub max_sessions: usize,

    /// Maximum length of the `NEG-OPEN` subscription id.
    pub max_subid_length: usize,

    /// Split responses larger than this many bytes across rounds.
    ///
    /// This is what bounds a response, not `max_records`: a client whose set is
    /// empty opens with a five-byte message that asks for every id the filter
    /// matches, and without a limit the relay answers in one frame (~64 bytes
    /// of hex per event). Lowering it costs extra round trips.
    ///
    /// `0` disables splitting; any other value must be at least 4096.
    pub frame_size_limit: u64,

    /// Drop a reconciliation this long after its last message.
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
            max_subid_length: 100,
            // Keeps a response well under the relay's own 512 KiB inbound
            // message ceiling no matter how large the matched set is.
            frame_size_limit: 65536,
            idle_timeout: NonZeroDuration::new(Duration::from_secs(300)),
            // ~40 MiB of snapshots across the whole relay.
            max_total_records: 1_000_000,
        }
    }
}

/// Snapshot records held in memory, across every connection: the extension is
/// a single instance behind the app's extension list.
#[derive(Clone, Default)]
struct RecordBudget(Arc<AtomicUsize>);

/// Charges `records` against the budget until dropped.
///
/// A guard rather than paired increment/decrement calls because the extension
/// is never told a session ended: this also repays on connection close, not
/// just `NEG-CLOSE`, idle expiry and re-open.
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
    last_active: Instant,
    _lease: RecordLease,
}

/// Per-connection reconciliation state, stored on the session.
#[derive(Default)]
struct Sessions {
    open: HashMap<String, Reconciliation>,
}

pub struct Negentropies {
    setting: NegentropySetting,
    db: Arc<Db>,
    budget: RecordBudget,
}

impl Negentropies {
    pub fn new(db: Arc<Db>) -> Self {
        Self {
            setting: NegentropySetting::default(),
            db,
            budget: RecordBudget::default(),
        }
    }

    /// Snapshot the filter as a sealed negentropy storage and its record count,
    /// or `None` when the filter matches more than `max_records` events.
    ///
    /// Reads the index tree only: reconciliation needs timestamps and ids, not
    /// event bodies. Sealing sorts by `(timestamp, id)`, which is the order the
    /// protocol requires and *not* the order rnostr's own indexes use for
    /// events sharing a timestamp.
    fn snapshot(
        &self,
        filter: &Filter,
        timeout: Option<NonZeroDuration>,
    ) -> Result<Option<(NegentropyStorageVector, usize)>, Error> {
        let reader = self.db.reader()?;
        let mut iter = self.db.iter::<Vec<u8>, _>(&reader, filter)?;
        if let Some(time) = timeout {
            iter.scan_time(time.into(), 2000);
        }

        let (pairs, complete, _) = iter.index_pairs(self.setting.max_records)?;
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

    fn open(
        &self,
        session: &mut Session,
        sub_id: &str,
        values: &[Value],
    ) -> Result<OutgoingMessage, Error> {
        if sub_id.len() > self.setting.max_subid_length {
            return Ok(neg_err(sub_id, "invalid: subscription id is too long"));
        }

        let filter = match values.get(1).cloned().map(serde_json::from_value::<Filter>) {
            Some(Ok(filter)) => filter,
            Some(Err(err)) => return Ok(neg_err(sub_id, &format!("invalid: {err}"))),
            None => return Ok(neg_err(sub_id, "invalid: NEG-OPEN requires a filter")),
        };
        let initial = match decode_hex(values.get(2)) {
            Ok(initial) => initial,
            Err(reason) => return Ok(neg_err(sub_id, &reason)),
        };

        // Reusing an id restarts that reconciliation, as REQ does. Dropping the
        // old one up front keeps a restart from double-charging the budget, or
        // leaving the old snapshot behind when the new one is refused.
        let sessions = sessions_mut(session);
        let reopen = sessions.open.remove(sub_id).is_some();
        if !reopen && sessions.open.len() >= self.setting.max_sessions {
            return Ok(neg_err(
                sub_id,
                "blocked: too many concurrent reconciliations",
            ));
        }

        let timeout = session.app.setting.read().data.db_query_timeout;
        let Some((storage, records)) = self.snapshot(&filter, timeout)? else {
            return Ok(OutgoingMessage(
                json!([
                    NEG_ERR,
                    sub_id,
                    "blocked: too many records for reconciliation",
                    self.setting.max_records
                ])
                .to_string(),
            ));
        };

        // Charged after building, so this bounds retained reconciliations, not
        // the peak: one snapshot per connection concurrently in NEG-OPEN.
        let Some(lease) = self.budget.acquire(records, self.setting.max_total_records) else {
            return Ok(neg_err(
                sub_id,
                "blocked: relay is at its reconciliation memory limit",
            ));
        };

        let mut negentropy = Negentropy::owned(storage, self.setting.frame_size_limit)
            .map_err(|err| Error::Message(err.to_string()))?;
        // The client initiated, so a protocol failure here is bad client input.
        let out = match negentropy.reconcile(&initial) {
            Ok(out) => out,
            Err(err) => return Ok(neg_err(sub_id, &format!("invalid: {err}"))),
        };

        sessions_mut(session).open.insert(
            sub_id.to_owned(),
            Reconciliation {
                negentropy,
                last_active: Instant::now(),
                _lease: lease,
            },
        );

        Ok(neg_msg(sub_id, &out))
    }

    fn reconcile(
        &self,
        session: &mut Session,
        sub_id: &str,
        values: &[Value],
    ) -> Result<OutgoingMessage, Error> {
        let query = match decode_hex(values.get(1)) {
            Ok(query) => query,
            Err(reason) => return Ok(neg_err(sub_id, &reason)),
        };

        let sessions = sessions_mut(session);
        let Some(reconciliation) = sessions.open.get_mut(sub_id) else {
            return Ok(neg_err(sub_id, "closed: no such reconciliation"));
        };

        match reconciliation.negentropy.reconcile(&query) {
            Ok(out) => {
                reconciliation.last_active = Instant::now();
                Ok(neg_msg(sub_id, &out))
            }
            Err(err) => {
                let reason = format!("invalid: {err}");
                sessions.open.remove(sub_id);
                Ok(neg_err(sub_id, &reason))
            }
        }
    }

    /// [`expire_idle`] at the current setting.
    fn expire(&self, session: &mut Session, ctx: &mut <Session as actix::Actor>::Context) {
        let Some(timeout) = self.setting.idle_timeout else {
            return;
        };
        expire_idle(session, ctx, timeout.into());
    }
}

/// Drop reconciliations idle longer than `timeout`, telling the client which
/// went away so it does not wait on a session the relay has forgotten.
fn expire_idle(
    session: &mut Session,
    ctx: &mut <Session as actix::Actor>::Context,
    timeout: Duration,
) {
    let sessions = sessions_mut(session);
    if sessions.open.is_empty() {
        return;
    }

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

fn neg_msg(sub_id: &str, message: &[u8]) -> OutgoingMessage {
    OutgoingMessage(json!([NEG_MSG, sub_id, hex::encode(message)]).to_string())
}

fn neg_err(sub_id: &str, reason: &str) -> OutgoingMessage {
    OutgoingMessage(json!([NEG_ERR, sub_id, reason]).to_string())
}

fn decode_hex(value: Option<&Value>) -> Result<Vec<u8>, String> {
    let raw = value
        .and_then(|value| value.as_str())
        .ok_or_else(|| "invalid: missing negentropy message".to_owned())?;
    hex::decode(raw).map_err(|err| format!("invalid: malformed negentropy message: {err}"))
}

/// The subscription id every NIP-77 message carries as its first parameter.
fn sub_id(values: &[Value]) -> Option<&str> {
    values.first().and_then(|value| value.as_str())
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
        if self.setting.enabled {
            w.add_nip(77);
        }
    }

    /// Arm the idle sweep. Without a timer nothing reclaims a snapshot on a
    /// connection that goes quiet but keeps answering pings, since `message`
    /// is the extension's only other callback.
    ///
    /// The timeout is read once because the closure cannot borrow the
    /// extension, so a reload reaches new connections only; `message` uses the
    /// live value.
    fn connected(&self, _session: &mut Session, ctx: &mut <Session as actix::Actor>::Context) {
        let Some(timeout) = self.setting.idle_timeout.map(Duration::from) else {
            return;
        };
        // Twice per timeout: outlives it by at most half, without waking often.
        let interval = (timeout / 2).max(Duration::from_secs(1));
        ctx.run_interval(interval, move |session, ctx| {
            expire_idle(session, ctx, timeout);
        });
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

        let IncomingMessage::Unknown(command, values) = &msg.msg else {
            return ExtensionMessageResult::Continue(msg);
        };
        if !matches!(command.as_str(), NEG_OPEN | NEG_MSG | NEG_CLOSE) {
            return ExtensionMessageResult::Continue(msg);
        }

        let Some(id) = sub_id(values).map(ToOwned::to_owned) else {
            return OutgoingMessage::notice("invalid: NEG message requires a subscription id")
                .into();
        };

        self.expire(session, ctx);

        let result = match command.as_str() {
            NEG_OPEN => self.open(session, &id, values),
            NEG_MSG => self.reconcile(session, &id, values),
            NEG_CLOSE => {
                sessions_mut(session).open.remove(&id);
                return ExtensionMessageResult::Ignore;
            }
            _ => unreachable!("command matched above"),
        };

        match result {
            Ok(out) => out.into(),
            Err(err) => neg_err(&id, &format!("error: {err}")).into(),
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
    use futures_util::{SinkExt as _, StreamExt as _};
    use negentropy::NegentropyStorageVector;
    use nostr_relay::create_web_app;
    use nostr_relay::db::{
        now,
        secp256k1::{rand::thread_rng, Keypair},
        Event,
    };

    fn parse_text<T: serde::de::DeserializeOwned>(frame: &ws::Frame) -> Result<T> {
        if let ws::Frame::Text(text) = &frame {
            Ok(serde_json::from_slice(text)?)
        } else {
            Err(nostr_relay::Error::Message(format!("invalid frame type: {frame:?}")).into())
        }
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

    /// Start a relay holding `events`.
    ///
    /// The events are written straight to the database rather than published
    /// over the websocket: reconciliation only reads what is stored, and a
    /// per-event EVENT/OK round trip dominates the runtime of these tests.
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
        let app = app.add_extension(Negentropies::new(db));
        let app = web::Data::new(app);
        Ok(actix_test::start(move || create_web_app(app.clone())))
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
        let initial = client.initiate()?;

        framed
            .send(ws::Message::Text(
                serde_json::json!(["NEG-OPEN", "sub", {"kinds": [1000]}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            ))
            .await?;

        let mut have: Vec<Id> = Vec::new();
        let mut need: Vec<Id> = Vec::new();
        loop {
            let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
            assert_eq!(res.0, NEG_MSG, "unexpected message: {res:?}");
            assert_eq!(res.1, "sub");

            let query = hex::decode(&res.2)?;
            match client.reconcile_with_ids(&query, &mut have, &mut need)? {
                Some(next) => {
                    framed
                        .send(ws::Message::Text(
                            serde_json::json!(["NEG-MSG", "sub", hex::encode(&next)])
                                .to_string()
                                .into(),
                        ))
                        .await?;
                }
                None => break,
            }
        }

        // `have` is what the client holds and the relay does not (events 8..12),
        // `need` is what the relay holds and the client does not (events 0..4).
        let expected_have: Vec<Id> = all[8..12]
            .iter()
            .map(|event| Id::from_byte_array(*event.id()))
            .collect();
        let expected_need: Vec<Id> = all[0..4]
            .iter()
            .map(|event| Id::from_byte_array(*event.id()))
            .collect();

        have.sort();
        need.sort();
        let mut expected_have = expected_have;
        let mut expected_need = expected_need;
        expected_have.sort();
        expected_need.sort();

        assert_eq!(have, expected_have);
        assert_eq!(need, expected_need);
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
        let initial = client.initiate()?;
        framed
            .send(ws::Message::Text(
                serde_json::json!(["NEG-OPEN", "same", {"kinds": [1000]}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            ))
            .await?;

        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_MSG);

        let mut have = Vec::new();
        let mut need = Vec::new();
        let next = client.reconcile_with_ids(&hex::decode(&res.2)?, &mut have, &mut need)?;
        assert!(next.is_none(), "reconciliation should finish in one round");
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

        let mut client = client(&all)?;
        let initial = client.initiate()?;
        framed
            .send(ws::Message::Text(
                serde_json::json!(["NEG-OPEN", "big", {"kinds": [1000]}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            ))
            .await?;

        let res: (String, String, String, usize) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.1, "big");
        assert!(res.2.starts_with("blocked:"), "got {}", res.2);
        assert_eq!(res.3, 3);
        Ok(())
    }

    #[actix_rt::test]
    async fn unknown_and_closed_sessions_report_neg_err() -> Result<()> {
        let mut srv =
            start_relay("neg-unknown", r#"{"negentropy": {"enabled": true}}"#, &[]).await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        // NEG-MSG without a preceding NEG-OPEN.
        framed
            .send(ws::Message::Text(
                r#"["NEG-MSG", "ghost", "61"]"#.to_owned().into(),
            ))
            .await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.2, "closed: no such reconciliation");

        // Malformed hex is reported rather than dropped.
        framed
            .send(ws::Message::Text(
                r#"["NEG-MSG", "ghost", "zz"]"#.to_owned().into(),
            ))
            .await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_ERR);
        assert!(res.2.starts_with("invalid:"), "got {}", res.2);
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
        framed
            .send(ws::Message::Text(
                serde_json::json!(["NEG-OPEN", "bye", {"kinds": [1000]}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            ))
            .await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_MSG);

        framed
            .send(ws::Message::Text(
                r#"["NEG-CLOSE", "bye"]"#.to_owned().into(),
            ))
            .await?;

        // The next NEG-MSG for that id must be unknown to the relay.
        framed
            .send(ws::Message::Text(
                r#"["NEG-MSG", "bye", "61"]"#.to_owned().into(),
            ))
            .await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
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
        framed
            .send(ws::Message::Text(
                serde_json::json!(["NEG-OPEN", "idle", {"kinds": [1000]}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            ))
            .await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_MSG);

        // Send nothing: the sweep must close it and say so unprompted.
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(res.1, "idle");
        assert_eq!(res.2, "closed: reconciliation timed out");

        framed
            .send(ws::Message::Text(
                r#"["NEG-MSG", "idle", "61"]"#.to_owned().into(),
            ))
            .await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
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

        let mut client = client(&all[0..2])?;
        let initial = client.initiate()?;
        let open = |sub: &str| {
            ws::Message::Text(
                serde_json::json!(["NEG-OPEN", sub, {"kinds": [1000]}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            )
        };

        // Four events, a ceiling of two: refused rather than truncated.
        framed.send(open("big")).await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_ERR);
        assert_eq!(
            res.2,
            "blocked: relay is at its reconciliation memory limit"
        );

        // One inside the ceiling is accepted...
        framed
            .send(ws::Message::Text(
                serde_json::json!(["NEG-OPEN", "small", {"kinds": [1000], "since": all[3].created_at()}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            ))
            .await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_MSG, "got {res:?}");

        // ...and closing it repays the budget.
        framed
            .send(ws::Message::Text(
                r#"["NEG-CLOSE", "small"]"#.to_owned().into(),
            ))
            .await?;
        framed
            .send(ws::Message::Text(
                serde_json::json!(["NEG-OPEN", "again", {"kinds": [1000], "since": all[3].created_at()}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            ))
            .await?;
        let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, NEG_MSG, "got {res:?}");
        Ok(())
    }

    #[actix_rt::test]
    async fn disabled_extension_ignores_neg_messages() -> Result<()> {
        let mut srv =
            start_relay("neg-disabled", r#"{"negentropy": {"enabled": false}}"#, &[]).await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        framed
            .send(ws::Message::Text(
                r#"["NEG-OPEN", "off", {}, "61"]"#.to_owned().into(),
            ))
            .await?;
        // The extension does not answer, so NEG-OPEN falls through to the core
        // as an unsupported command instead of opening a reconciliation.
        let res: (String, String) = parse_text(&framed.next().await.unwrap()?)?;
        assert_eq!(res.0, "NOTICE");
        assert_eq!(res.1, "Unsupported message");
        Ok(())
    }

    /// A client with an empty set opens with a five-byte message that asks for
    /// every id the filter matches. `frame_size_limit` is what keeps the answer
    /// from arriving as one enormous frame; without it the relay would reply
    /// with roughly 64 bytes of hex per matched event in a single message.
    ///
    /// Uses the protocol minimum limit so a small event count still forces the
    /// response across several rounds.
    #[actix_rt::test]
    async fn an_empty_client_set_gets_a_bounded_response() -> Result<()> {
        let limit = MIN_FRAME_SIZE_LIMIT as usize;
        // Enough events that the ids alone (32 bytes each) far exceed one frame.
        let all = test_events(300)?;
        let mut srv = start_relay(
            "neg-amplification",
            r#"{"negentropy": {"enabled": true, "frame_size_limit": 4096}}"#,
            &all,
        )
        .await?;
        let mut framed = srv.ws_at("/").await.unwrap();

        let mut client = client(&[])?;
        let initial = client.initiate()?;
        assert!(
            initial.len() < 32,
            "opening message is tiny: {}",
            initial.len()
        );

        framed
            .send(ws::Message::Text(
                serde_json::json!(["NEG-OPEN", "flood", {"kinds": [1000]}, hex::encode(&initial)])
                    .to_string()
                    .into(),
            ))
            .await?;

        // Every round stays inside the frame limit, and the exchange still
        // converges on the full set the relay holds.
        let mut have = Vec::new();
        let mut need = Vec::new();
        let mut rounds = 0;
        loop {
            let res: (String, String, String) = parse_text(&framed.next().await.unwrap()?)?;
            assert_eq!(res.0, NEG_MSG, "unexpected message: {res:?}");
            assert!(
                res.2.len() / 2 <= limit,
                "frame of {} bytes exceeds the {limit} byte limit",
                res.2.len() / 2
            );
            rounds += 1;

            match client.reconcile_with_ids(&hex::decode(&res.2)?, &mut have, &mut need)? {
                Some(next) => {
                    framed
                        .send(ws::Message::Text(
                            serde_json::json!(["NEG-MSG", "flood", hex::encode(&next)])
                                .to_string()
                                .into(),
                        ))
                        .await?;
                }
                None => break,
            }
        }

        // More than one round proves the response was actually split rather
        // than fitting under the limit by accident.
        assert!(
            rounds > 1,
            "expected a split response, got {rounds} round(s)"
        );
        assert!(have.is_empty());
        assert_eq!(need.len(), all.len());
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
