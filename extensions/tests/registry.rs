//! Exercise real sessions and subscription delivery without binding TCP sockets.
use actix::{ActorContext, Handler, Message, StreamHandler};
use actix_web::{error::PayloadError, web};
use actix_web_actors::ws;
use futures_util::{stream, StreamExt};
use nostr_extensions::auth::{Auth, AuthState};
use nostr_relay::{
    message::{ClientMessage, IncomingMessage, OutgoingMessage},
    App, Session,
};
use serde_json::json;
use std::{
    fs,
    path::Path,
    sync::mpsc,
    time::{Duration, Instant},
};

#[derive(Message)]
#[rtype(result = "()")]
enum Command {
    Authenticate(String),
    ClearAuthentication,
    Request(String),
    Stop,
}
impl Handler<Command> for Session {
    type Result = ();
    fn handle(&mut self, msg: Command, ctx: &mut Self::Context) {
        match msg {
            Command::Authenticate(key) => self.set(AuthState::Pubkey(key)),
            Command::ClearAuthentication => self.set(AuthState::Challenge("test".into())),
            Command::Request(text) => <Self as StreamHandler<
                Result<ws::Message, ws::ProtocolError>,
            >>::handle(
                self, Ok(ws::Message::Text(text.into())), ctx
            ),
            Command::Stop => ctx.stop(),
        }
    }
}

struct Peer {
    addr: actix::Addr<Session>,
    output: mpsc::Receiver<Vec<u8>>,
    bytes: Vec<u8>,
}
impl Peer {
    async fn new(app: web::Data<App>, key: &str) -> anyhow::Result<Self> {
        let session = Session::new("127.0.0.1".into(), app);
        let (addr, output) = ws::WebsocketContext::create_with_addr(
            session,
            stream::pending::<Result<web::Bytes, PayloadError>>(),
        );
        let (tx, rx) = mpsc::channel();
        actix_rt::spawn(async move {
            futures_util::pin_mut!(output);
            while let Some(chunk) = output.next().await {
                if tx.send(chunk.unwrap().to_vec()).is_err() {
                    break;
                }
            }
        });
        // NIP-42 protocol tests cover authentication; inject the identity here.
        addr.send(Command::Authenticate(key.into())).await?;
        Ok(Self {
            addr,
            output: rx,
            bytes: Vec::new(),
        })
    }
    async fn request(&self, id: &str) -> anyhow::Result<()> {
        self.addr
            .send(Command::Request(json!(["REQ", id, {}]).to_string()))
            .await?;
        Ok(())
    }
    fn contains(&mut self, expected: &[u8]) -> bool {
        while let Ok(chunk) = self.output.try_recv() {
            self.bytes.extend(chunk);
        }
        self.bytes.windows(expected.len()).any(|w| w == expected)
    }
    async fn expect(&mut self, expected: &[u8]) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.contains(expected) {
            anyhow::ensure!(
                Instant::now() < deadline,
                "missing output {expected:?}: {:?}",
                self.bytes
            );
            actix_rt::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }
    async fn expect_denied(&mut self, id: &str) -> anyhow::Result<()> {
        let expected =
            json!(["CLOSED", id, "restricted: pubkey not in registry policy"]).to_string();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.contains(expected.as_bytes()) {
            anyhow::ensure!(Instant::now() < deadline, "policy update was not enforced");
            self.request(id).await?;
            actix_rt::time::sleep(Duration::from_millis(5)).await;
        }
        Ok(())
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.addr.do_send(Command::Stop);
    }
}
fn write_policy(path: &Path, timestamp: u64, member: bool) -> anyhow::Result<()> {
    fs::write(path, json!({
        "source": {"authority": "a".repeat(64), "recipient": "b".repeat(64), "event_kind": 30617},
        "created_at": timestamp, "event_id": "c".repeat(64),
        "members": if member { vec!["d".repeat(64)] } else { vec![] },
        "extras": ["7abf57d516b1ff7308ca3bd5650ea6a4674d469c7c5057b1d005fb13d218bfef"]
    }).to_string())?;
    Ok(())
}
fn app(dir: &Path, policy: &Path) -> anyhow::Result<App> {
    let config = dir.join("relay.json");
    fs::write(
        &config,
        json!({"thread": {"reader": 1}, "auth": {"enabled": true, "registry_file": policy}})
            .to_string(),
    )?;
    Ok(App::create(Some(config.as_path()), false, None, Some(dir))?)
}

#[actix_rt::test]
async fn revocation_closes_existing_reader_before_delivering_another_event() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let policy = dir.path().join("policy.json");
    write_policy(&policy, 10, true)?;
    let app = app(dir.path(), &policy)?;
    let auth = Auth::from_setting(&app.setting)?;
    let app = web::Data::new(app.add_extension(auth));
    let mut revoked = Peer::new(app.clone(), &"d".repeat(64)).await?;
    let mut custom = Peer::new(app.clone(), &"d".repeat(64)).await?;
    let mut allowed = Peer::new(app.clone(), &"b".repeat(64)).await?;
    revoked.request("revoked").await?;
    custom.request("custom").await?;
    allowed.request("allowed").await?;
    revoked.expect(b"\"EOSE\",\"revoked\"").await?;
    custom.expect(b"\"EOSE\",\"custom\"").await?;
    allowed.expect(b"\"EOSE\",\"allowed\"").await?;
    write_policy(&policy, 20, false)?;
    revoked.expect_denied("probe").await?;
    let note = r#"{"content":"Good morning everyone 😃","created_at":1680690006,"id":"332747c0fab8a1a92def4b0937e177be6df4382ce6dd7724f86dc4710b7d4d7d","kind":1,"pubkey":"7abf57d516b1ff7308ca3bd5650ea6a4674d469c7c5057b1d005fb13d218bfef","sig":"ef4ff4f69ac387239eb1401fb07d7a44a5d5d57127e0dc3466a0403cf7d5486b668608ebfcbe9ff1f8d3b5d710545999fe08ee767284ec0b474e4cf92537678f","tags":[["t","nostr"]]}"#;
    custom
        .addr
        .send(OutgoingMessage(format!(
            r#" [ "\u0045VENT" , "custom" , {note} ] "#
        )))
        .await?;
    custom.expect(&1008u16.to_be_bytes()).await?;
    assert!(!custom.contains(b"Good morning"));
    app.server
        .send(ClientMessage::new(
            0,
            String::new(),
            IncomingMessage::Event(serde_json::from_str(note)?),
        ))
        .await?;
    allowed.expect(b"\"EVENT\",\"allowed\"").await?;
    revoked.expect(&1008u16.to_be_bytes()).await?; // WebSocket policy violation.
    assert!(!revoked.contains(b"\"EVENT\",\"revoked\""));
    assert!(revoked
        .addr
        .send(Command::Request("[]".into()))
        .await
        .is_err());
    Ok(())
}

#[actix_rt::test]
async fn watcher_initialization_failure_aborts_startup_and_restart_can_recover(
) -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let policy = dir.path().join("policy.json");
    write_policy(&policy, 10, true)?;
    let pending = app(dir.path(), &policy)?;
    fs::remove_file(&policy)?;
    assert!(Auth::from_setting(&pending.setting).is_err());
    write_policy(&policy, 10, true)?;
    // The failed App's actors stop asynchronously, so the retry uses its own DB.
    let restarted = tempfile::tempdir()?;
    let app = app(restarted.path(), &policy)?.add_extension(Auth::new());
    let mut peer = Peer::new(web::Data::new(app), &"d".repeat(64)).await?;
    peer.request("restored").await?;
    peer.expect(b"\"EOSE\",\"restored\"").await?;
    Ok(())
}

#[actix_rt::test]
async fn membership_denials_distinguish_authentication_from_authorization() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let policy = dir.path().join("policy.json");
    write_policy(&policy, 10, true)?;
    let mut document: serde_json::Value = serde_json::from_slice(&fs::read(&policy)?)?;
    document["extras"] = json!([]);
    fs::write(&policy, document.to_string())?;
    let app = app(dir.path(), &policy)?.add_extension(Auth::new());
    app.setting.write().limitation.max_event_time_older_than_now = 0;
    let mut peer = Peer::new(web::Data::new(app), &"f".repeat(64)).await?;
    for command in ["REQ", "COUNT"] {
        peer.addr
            .send(Command::Request(json!([command, command, {}]).to_string()))
            .await?;
        peer.expect(
            json!([
                "CLOSED",
                command,
                "restricted: pubkey not in registry policy"
            ])
            .to_string()
            .as_bytes(),
        )
        .await?;
    }
    peer.addr.send(Command::ClearAuthentication).await?;
    peer.request("missing-auth").await?;
    peer.expect(
        json!([
            "CLOSED",
            "missing-auth",
            "auth-required: NIP-42 auth required"
        ])
        .to_string()
        .as_bytes(),
    )
    .await?;
    for authenticated in [false, true] {
        if authenticated {
            peer.addr
                .send(Command::Authenticate("f".repeat(64)))
                .await?;
        }
        let key = nostr_relay::db::secp256k1::Keypair::new_global(
            &mut nostr_relay::db::secp256k1::rand::thread_rng(),
        );
        let note = nostr_relay::db::Event::create(
            &key,
            nostr_relay::db::now(),
            1,
            vec![],
            format!("test-{authenticated}"),
        )?;
        peer.addr
            .send(Command::Request(format!(r#"["EVENT",{note}]"#)))
            .await?;
        peer.expect(
            json!([
                "OK",
                note.id_str(),
                false,
                "restricted: pubkey not in registry policy"
            ])
            .to_string()
            .as_bytes(),
        )
        .await?;
    }
    Ok(())
}

#[actix_rt::test]
async fn ip_denials_do_not_request_unnecessary_authentication() -> anyhow::Result<()> {
    for registry in [false, true] {
        let dir = tempfile::tempdir()?;
        let policy = dir.path().join("policy.json");
        write_policy(&policy, 10, true)?;
        let app = app(dir.path(), &policy)?;
        {
            let mut setting = app.setting.write();
            setting.extra.get_mut("auth").unwrap()["req"] = json!({"ip_whitelist":["192.0.2.1"]});
            if !registry {
                setting
                    .extra
                    .get_mut("auth")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("registry_file");
            }
        }
        let mut peer = Peer::new(
            web::Data::new(app.add_extension(Auth::new())),
            &"f".repeat(64),
        )
        .await?;
        peer.addr.send(Command::ClearAuthentication).await?;
        peer.request("ip-denied").await?;
        peer.expect(
            json!(["CLOSED", "ip-denied", "restricted: ip not in whitelist"])
                .to_string()
                .as_bytes(),
        )
        .await?;
    }
    Ok(())
}
