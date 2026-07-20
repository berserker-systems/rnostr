//! Run the actual binary against local relays, including incomplete REQs.
use allowlist_policy::RegistryPolicy;
use futures_util::{SinkExt, StreamExt};
use nostr_sdk::prelude::*;
use serde_json::{json, Value};
use std::{fs, time::Duration};
use tempfile::TempDir;
use tokio::{
    net::TcpListener,
    process::{Child, Command},
    task::JoinHandle,
};
use tokio_tungstenite::{accept_async, tungstenite::Message};

enum Reply {
    HandshakeStall,
    Eose(Option<Event>),
    Silent(Option<Event>),
    Disconnect(Option<Event>),
    Reject,
    WrongEose,
    Authenticate(Event, bool),
    CatchUp(Box<(Event, Event)>),
    Reconnect(Box<(Event, Event)>),
    EarlyEose(Event, bool),
    LateAuth(Event, bool),
    RejectAfterAuth,
    PrivateWithoutAuth(Event),
    PublicChallenge(Event),
}

struct MockRelay {
    url: String,
    task: JoinHandle<()>,
    require_auth: bool,
    accepted: tokio::sync::oneshot::Receiver<()>,
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockRelay {
    fn source(&self) -> (&str, bool) {
        (&self.url, self.require_auth)
    }

    async fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (accepted_tx, accepted) = tokio::sync::oneshot::channel();
        let require_auth = matches!(
            &reply,
            Reply::Authenticate(..)
                | Reply::CatchUp(..)
                | Reply::Reconnect(..)
                | Reply::EarlyEose(..)
                | Reply::LateAuth(..)
                | Reply::RejectAfterAuth
                | Reply::PrivateWithoutAuth(_)
        );
        let task = tokio::spawn(async move {
            let mut accepted_tx = Some(accepted_tx);
            let connections = if matches!(&reply, Reply::Reconnect(..)) {
                2
            } else {
                1
            };
            for connection in 0..connections {
                let (stream, _) = listener.accept().await.unwrap();
                if let Some(accepted_tx) = accepted_tx.take() {
                    let _ = accepted_tx.send(());
                }
                let challenge = format!("test-challenge-{connection}");
                if matches!(reply, Reply::HandshakeStall) {
                    let _connection = stream;
                    std::future::pending::<()>().await;
                    return;
                }
                let mut ws = accept_async(stream).await.unwrap();
                let mut authenticated = false;
                let mut catchups = 0;
                if matches!(
                    &reply,
                    Reply::EarlyEose(_, _)
                        | Reply::CatchUp(..)
                        | Reply::Reconnect(..)
                        | Reply::RejectAfterAuth
                        | Reply::PublicChallenge(_)
                ) {
                    ws.send(Message::Text(json!(["AUTH", challenge]).to_string().into()))
                        .await
                        .unwrap();
                }
                while let Some(Ok(message)) = ws.next().await {
                    let Message::Text(text) = message else {
                        continue;
                    };
                    let request: Value = serde_json::from_str(&text).unwrap();
                    let mut responses = Vec::new();
                    match request[0].as_str().unwrap() {
                        "REQ" => {
                            let id = request[1].as_str().unwrap();
                            match &reply {
                                Reply::HandshakeStall => unreachable!(),
                                Reply::Authenticate(_, _) if !authenticated => {
                                    responses.push(json!([
                                        "CLOSED",
                                        id,
                                        "auth-required: authenticate"
                                    ]));
                                    responses.push(json!(["AUTH", "test-challenge"]));
                                }
                                Reply::LateAuth(_, _) if !authenticated => {
                                    responses.push(json!(["EOSE", id]));
                                    responses.push(json!(["AUTH", "test-challenge"]));
                                }
                                Reply::EarlyEose(_, _)
                                | Reply::CatchUp(..)
                                | Reply::Reconnect(..)
                                    if !authenticated =>
                                {
                                    responses.push(json!(["EOSE", id]))
                                }
                                Reply::CatchUp(events) | Reply::Reconnect(events) => {
                                    let first = if matches!(&reply, Reply::Reconnect(..)) {
                                        connection == 0
                                    } else {
                                        catchups == 0
                                    };
                                    let event = if first { &events.0 } else { &events.1 };
                                    catchups += 1;
                                    responses.push(json!(["EVENT", id, event]));
                                    responses.push(json!(["EOSE", id]));
                                }
                                Reply::RejectAfterAuth => {
                                    responses.push(json!(["CLOSED", id, "auth-required: denied"]))
                                }
                                Reply::PrivateWithoutAuth(event)
                                | Reply::PublicChallenge(event) => {
                                    responses.push(json!(["EVENT", id, event]));
                                    responses.push(json!(["EOSE", id]));
                                }
                                Reply::Eose(event)
                                | Reply::Silent(event)
                                | Reply::Disconnect(event) => {
                                    if let Some(event) = event {
                                        responses.push(json!(["EVENT", id, event]));
                                    }
                                    if matches!(&reply, Reply::Eose(_)) {
                                        responses.push(json!(["EOSE", id]));
                                    }
                                }
                                Reply::Authenticate(event, _)
                                | Reply::EarlyEose(event, _)
                                | Reply::LateAuth(event, _) => {
                                    responses.push(json!(["EVENT", id, event]));
                                    responses.push(json!(["EOSE", id]));
                                }
                                Reply::Reject => {
                                    responses.push(json!(["CLOSED", id, "restricted: denied"]))
                                }
                                Reply::WrongEose => {
                                    responses.push(json!(["EOSE", "unrelated-request"]))
                                }
                            }
                        }
                        "AUTH" => {
                            if matches!(&reply, Reply::CatchUp(..)) {
                                assert!(!authenticated, "catch-up repeated AUTH");
                            }
                            if let Reply::Reconnect(events) = &reply {
                                let auth: Event =
                                    serde_json::from_value(request[1].clone()).unwrap();
                                auth.verify().unwrap();
                                assert_eq!(
                                    auth.pubkey.to_hex(),
                                    events.0.tags.identifier().unwrap()
                                );
                                assert!(
                                    request[1]["tags"]
                                        .as_array()
                                        .unwrap()
                                        .contains(&json!(["challenge", challenge])),
                                    "AUTH did not answer this connection's challenge"
                                );
                            }
                            authenticated = matches!(
                                &reply,
                                Reply::Authenticate(_, true)
                                    | Reply::CatchUp(..)
                                    | Reply::Reconnect(..)
                                    | Reply::EarlyEose(_, true)
                                    | Reply::LateAuth(_, true)
                                    | Reply::RejectAfterAuth
                            );
                            responses.push(json!(["OK", request[1]["id"], authenticated, ""]));
                        }
                        "CLOSE" => {}
                        _ => {}
                    }
                    for response in responses {
                        if ws
                            .send(Message::Text(response.to_string().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    if matches!(reply, Reply::Disconnect(_)) {
                        return;
                    }
                    if matches!(&reply, Reply::Reconnect(..))
                        && connection == 0
                        && authenticated
                        && request[0] == "REQ"
                    {
                        break;
                    }
                }
            }
        });
        Self {
            url,
            task,
            require_auth,
            accepted,
        }
    }
}

struct Fixture {
    dir: TempDir,
    authority: Keys,
    recipient: Keys,
    member: PublicKey,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let recipient = Keys::generate();
        let secret = dir.path().join("recipient.nsec");
        fs::write(&secret, recipient.secret_key().to_bech32().unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self {
            dir,
            authority: Keys::generate(),
            recipient,
            member: Keys::generate().public_key(),
        }
    }

    fn snapshot(&self, timestamp: u64, revoked: bool) -> Event {
        let shareholders = if revoked {
            vec![]
        } else {
            vec![self.member.to_bech32().unwrap()]
        };
        let cipher = nip44::encrypt(
            self.authority.secret_key(),
            &self.recipient.public_key(),
            serde_json::to_string(&shareholders).unwrap(),
            nip44::Version::V2,
        )
        .unwrap();
        EventBuilder::new(Kind::from(30617), cipher)
            .tags([
                Tag::identifier(self.recipient.public_key().to_hex()),
                Tag::public_key(self.recipient.public_key()),
            ])
            .custom_created_at(Timestamp::from(timestamp))
            .sign_with_keys(&self.authority)
            .unwrap()
    }

    fn start(&self, relays: &[(&str, bool)], timeout: &str, resync: &str) -> Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_allowlist-sync"));
        command
            .kill_on_drop(true)
            .args(["--authority", &self.authority.public_key().to_hex()])
            .arg("--recipient-nsec-file")
            .arg(self.dir.path().join("recipient.nsec"))
            .arg("--policy-file")
            .arg(self.dir.path().join("allowlist.json"))
            .args([
                "--event-kind",
                "30617",
                "--fetch-timeout",
                timeout,
                "--resync-interval",
                resync,
            ])
            .env("RUST_LOG", "info")
            .env_remove("ALLOWLIST_EXTRA_PUBKEYS")
            .env_remove("ALLOWLIST_PUBLIC_RELAYS")
            .env_remove("ALLOWLIST_RELAYS");
        for (relay, require_auth) in relays {
            command.args([
                if *require_auth {
                    "--relay"
                } else {
                    "--public-relay"
                },
                relay,
            ]);
        }
        let log = fs::File::create(self.dir.path().join("sync.log")).unwrap();
        command
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap()
    }

    async fn wait_for(&self, child: &mut Child, expected: Result<u64, &str>) {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                assert!(
                    child.try_wait().unwrap().is_none(),
                    "sidecar exited: {}",
                    self.log()
                );
                let ready = match expected {
                    Ok(version) => self.version() == Some(version),
                    Err(message) => self.log().contains(message),
                };
                if ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("sidecar did not make progress: {}", self.log()));
    }

    fn version(&self) -> Option<u64> {
        RegistryPolicy::read(&self.dir.path().join("allowlist.json"))
            .ok()
            .map(|policy| policy.created_at)
    }

    fn log(&self) -> String {
        fs::read_to_string(self.dir.path().join("sync.log")).unwrap()
    }

    fn member_is_allowed(&self) -> bool {
        RegistryPolicy::read(&self.dir.path().join("allowlist.json"))
            .unwrap()
            .allows(&self.member.to_hex())
    }
}

#[tokio::test]
#[ignore = "requires loopback TCP/WebSocket; run explicitly in CI"]
async fn live_catchup_reuses_the_authenticated_connection() {
    live_revocation(false).await;
}

#[tokio::test]
#[ignore = "requires loopback TCP/WebSocket; run explicitly in CI"]
async fn live_reconnect_authenticates_again_and_applies_a_newer_snapshot() {
    live_revocation(true).await;
}

async fn live_revocation(reconnect: bool) {
    let fixture = Fixture::new();
    let events = Box::new((fixture.snapshot(10, false), fixture.snapshot(20, true)));
    let reply = if reconnect {
        Reply::Reconnect(events)
    } else {
        Reply::CatchUp(events)
    };
    let source = MockRelay::start(reply).await;
    let mut child = fixture.start(
        &[source.source()],
        "10s",
        if reconnect { "60s" } else { "1s" },
    );
    fixture.wait_for(&mut child, Ok(20)).await;
    assert!(!fixture.member_is_allowed());
    child.kill().await.unwrap();
}

#[tokio::test]
#[ignore = "requires loopback TCP/WebSocket; run explicitly in CI"]
async fn handshake_timeouts_report_connection_failure_for_both_source_flags() {
    for require_auth in [false, true] {
        let fixture = Fixture::new();
        let mut source = MockRelay::start(Reply::HandshakeStall).await;
        let mut child = fixture.start(&[(&source.url, require_auth)], "1s", "60s");
        fixture
            .wait_for(&mut child, Err("registry source failed; reconnecting"))
            .await;
        assert!(
            source.accepted.try_recv().is_ok(),
            "server never accepted TCP"
        );
        let log = fixture.log();
        assert!(
            log.contains("relay did not connect before the fetch deadline"),
            "{log}"
        );
        assert!(
            !log.contains("--public-relay") && !log.contains("EOSE"),
            "{log}"
        );
        assert_eq!(fixture.version(), None);
        child.kill().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires loopback TCP/WebSocket; run explicitly in CI"]
async fn sources_publish_updates_and_report_incomplete_requests() {
    let keys = Fixture::new();
    let event = keys.snapshot(10, false);
    let failed = Err("registry source failed; reconnecting");
    for (reply, expected) in [
        (Reply::Silent(None), failed),
        (Reply::Disconnect(None), failed),
        (Reply::Reject, failed),
        (Reply::WrongEose, failed),
        (Reply::Authenticate(event.clone(), false), failed),
        (Reply::Eose(Some(event.clone())), Ok(10)),
        (Reply::PublicChallenge(event.clone()), Ok(10)),
        (Reply::Authenticate(event.clone(), true), Ok(10)),
        (Reply::EarlyEose(event.clone(), true), Ok(10)),
        (
            Reply::PrivateWithoutAuth(event.clone()),
            Err("--public-relay"),
        ),
        (Reply::EarlyEose(event.clone(), false), failed),
        (Reply::RejectAfterAuth, Err("relay closed registry request")),
    ] {
        let source = MockRelay::start(reply).await;
        let mut child = keys.start(&[source.source()], "5s", "60s");
        keys.wait_for(&mut child, expected).await;
        if expected.is_ok() {
            assert!(keys.member_is_allowed());
        } else {
            assert_eq!(keys.version(), None);
        }
        child.kill().await.unwrap();
        let policy = keys.dir.path().join("allowlist.json");
        if policy.exists() {
            fs::remove_file(policy).unwrap();
        }
    }
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let refused = format!("ws://{}", listener.local_addr().unwrap());
    drop(listener);
    let mut child = fixture.start(&[(&refused, true)], "5s", "60s");
    fixture
        .wait_for(&mut child, Err("registry source failed; reconnecting"))
        .await;
    assert_eq!(fixture.version(), None);
    child.kill().await.unwrap();
}

#[tokio::test]
#[ignore = "requires loopback TCP/WebSocket; run explicitly in CI"]
async fn failed_sources_do_not_block_available_revocations() {
    let fixture = Fixture::new();
    let stale = MockRelay::start(Reply::Eose(Some(fixture.snapshot(10, false)))).await;
    let failed = MockRelay::start(Reply::Silent(None)).await;
    let mut child = fixture.start(&[stale.source(), failed.source()], "5s", "60s");
    fixture
        .wait_for(&mut child, Err("registry source failed; reconnecting"))
        .await;
    fixture.wait_for(&mut child, Ok(10)).await;
    assert!(fixture.member_is_allowed()); // An unseen revocation cannot be inferred.
    child.kill().await.unwrap();

    for ending in ["eose", "silent", "disconnect"] {
        let fixture = Fixture::new();
        let old = MockRelay::start(Reply::Eose(Some(fixture.snapshot(10, false)))).await;
        let revoked = fixture.snapshot(20, true);
        let reply = match ending {
            "eose" => Reply::Eose(Some(revoked)),
            "silent" => Reply::Silent(Some(revoked)),
            _ => Reply::Disconnect(Some(revoked)),
        };
        let source = MockRelay::start(reply).await;
        let failed = MockRelay::start(Reply::Silent(None)).await;
        let mut child = fixture.start(
            &[old.source(), source.source(), failed.source()],
            "5s",
            "60s",
        );
        fixture.wait_for(&mut child, Ok(20)).await;
        assert!(!fixture.member_is_allowed());
        child.kill().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires loopback TCP/WebSocket; run explicitly in CI"]
async fn pre_auth_empty_eose_cannot_hide_a_revocation_behind_an_older_source() {
    for authenticated in [true, false] {
        let fixture = Fixture::new();
        let old = MockRelay::start(Reply::Eose(Some(fixture.snapshot(10, false)))).await;
        let private =
            MockRelay::start(Reply::LateAuth(fixture.snapshot(20, true), authenticated)).await;
        let mut child = fixture.start(&[old.source(), private.source()], "5s", "60s");
        if authenticated {
            fixture.wait_for(&mut child, Ok(20)).await;
            assert!(!fixture.member_is_allowed());
        } else {
            fixture
                .wait_for(&mut child, Err("relay authentication rejected"))
                .await;
            fixture.wait_for(&mut child, Ok(10)).await;
            assert!(fixture.member_is_allowed());
        }
        child.kill().await.unwrap();
    }
}
