use super::*;
use actix_service::IntoServiceFactory;
use actix_web::{dev::ServiceFactory, web};
use actix_web_actors::ws;
use nostr_relay::{create_web_app, App};
use serde_json::{json, Value};

const CONFIG_FILE: &str = "relay.toml";
const CONFIG: &str = r#"
[thread]
http = 1
reader = 1

[event_policy]
enabled = true
allowed_kinds = [1, 5, 30023, 30078]

[event_policy.identifiers]
"30078" = ["profile", "settings", "archive"]
"#;

fn app() -> (tempfile::TempDir, App) {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join(CONFIG_FILE);
    std::fs::write(&config, CONFIG).unwrap();
    let app = App::create(Some(config.as_path()), false, None, Some(root.path())).unwrap();
    (root, app)
}

fn setting(value: Value) -> SettingWrapper {
    let mut setting = Setting::default();
    setting.extra.insert("event_policy".into(), value);
    setting.into()
}

fn policy(value: Value) -> EventPolicy {
    let mut policy = EventPolicy::new();
    policy.setting(&setting(value));
    policy
}

fn configured() -> EventPolicy {
    policy(json!({
        "enabled": true,
        "allowed_kinds": [1, 5, 30023, 30078],
        "identifiers": {
            "30078": ["profile", "settings", "archive"]
        }
    }))
}

fn event(kind: u16, author: u8, tags: Vec<Vec<String>>) -> Event {
    Event::new(
        [author; 32],
        [author; 32],
        1,
        kind,
        tags,
        String::new(),
        [0; 64],
    )
    .unwrap()
}

fn identifier(value: &str) -> Vec<Vec<String>> {
    tags(&[&["d", value]])
}

fn tags(tags: &[&[&str]]) -> Vec<Vec<String>> {
    tags.iter()
        .map(|tag| tag.iter().map(|value| value.to_string()).collect())
        .collect()
}

fn message(event: Event) -> ClientMessage {
    ClientMessage::new(1, String::new(), IncomingMessage::Event(event))
}

fn rejection(result: ExtensionMessageResult) -> (String, String) {
    let ExtensionMessageResult::Stop(response) = result else {
        panic!("expected an explicit rejection");
    };
    let (command, id, accepted, reason): (String, String, bool, String) =
        serde_json::from_str(&response.to_string()).unwrap();
    assert_eq!(command, "OK");
    assert!(!accepted);
    (id, reason)
}

#[test]
fn rejects_every_unlisted_kind() {
    let policy = configured();
    let allowed = [1, 5, 30023, 30078];
    for kind in 0..=u16::MAX {
        let event = event(kind, 1, identifier("profile"));
        assert_eq!(
            policy.check(&event).is_ok(),
            allowed.contains(&kind),
            "kind {kind}"
        );
    }
}

#[test]
fn accepts_any_author_and_all_configured_identifiers() {
    let policy = configured();
    for author in 0..20 {
        assert!(policy.check(&event(1, author, vec![])).is_ok());
        for id in ["profile", "settings", "archive"] {
            assert!(policy.check(&event(30078, author, identifier(id))).is_ok());
        }
    }
}

#[test]
fn matches_the_first_d_tag_regardless_of_position() {
    let policy = configured();
    for tags in [
        vec![],
        tags(&[&[]]),
        tags(&[&["d"]]),
        identifier(""),
        identifier("unlisted"),
        tags(&[&["d", "unlisted"], &["d", "profile"]]),
        tags(&[&["d"], &["d", "profile"]]),
    ] {
        assert!(policy.check(&event(30078, 1, tags)).is_err());
    }
    for tags in [
        tags(&[&["alt", "description"], &["d", "profile"]]),
        tags(&[&["d", "profile"], &["d"]]),
        tags(&[&["d", "profile"], &["d", "unlisted"]]),
    ] {
        assert!(policy.check(&event(30078, 1, tags)).is_ok());
    }
    assert!(policy
        .check(&event(30023, 1, identifier("any-identifier")))
        .is_ok());
}

#[test]
fn invalid_reload_preserves_policy_until_corrected() {
    for invalid in [
        json!({"enabled": true, "allowed_kinds": "all"}),
        json!({"enabled": true, "allow_kinds": [1059]}),
        json!({"enabled": true, "allowed_kinds": [65536]}),
        json!({"enabled": true, "allowed_kinds": [1], "identifiers": {"30078": ["id"]}}),
        json!({"enabled": true, "allowed_kinds": [1], "identifiers": {"1": ["id"]}}),
        json!({"enabled": true, "identifiers": {"30078": "id"}}),
        json!({"enabled": "false"}),
        json!({"enabeld": true}),
    ] {
        let invalid = setting(invalid);
        assert!(EventPolicy::new()
            .validate_setting(&invalid.read())
            .is_err());
        let mut policy = configured();
        policy.setting(&invalid);
        assert!(policy.check(&event(1, 1, vec![])).is_ok());
        assert!(policy.check(&event(1059, 1, vec![])).is_err());
        policy.setting(&setting(json!({"enabled": true, "allowed_kinds": [2]})));
        assert!(policy.check(&event(1, 1, vec![])).is_err());
        assert!(policy.check(&event(2, 1, vec![])).is_ok());
    }
}

#[test]
fn enabled_empty_allowlist_denies_all_writes() {
    let policy = policy(json!({"enabled": true}));
    assert!(policy.check(&event(1, 1, vec![])).is_err());
}

#[test]
fn missing_or_disabled_policy_preserves_existing_relay_behavior() {
    let mut missing = EventPolicy::new();
    missing.setting(&Setting::default().into());
    assert!(missing.check(&event(1059, 1, vec![])).is_ok());
    for value in [
        json!({}),
        json!({"allowed_kinds": [1]}),
        json!({"enabled": false}),
        json!({"enabled": false, "allowed_kind": [1]}),
        json!({"enabled": false, "allowed_kinds": "invalid", "identifiers": false}),
    ] {
        let setting = setting(value.clone());
        assert!(EventPolicy::new().validate_setting(&setting.read()).is_ok());
        assert!(policy(value).check(&event(1059, 1, vec![])).is_ok());
    }
}

#[test]
fn empty_identifier_matches_missing_or_empty_values() {
    let policy = policy(json!({
        "enabled": true,
        "allowed_kinds": [30078],
        "identifiers": {"30078": [""]}
    }));
    for tags in [vec![], tags(&[&["d"]]), identifier("")] {
        assert!(policy.check(&event(30078, 1, tags)).is_ok());
    }
    assert!(policy
        .check(&event(30078, 1, identifier("profile")))
        .is_err());
}

#[test]
fn non_event_commands_pass_even_with_invalid_policy() {
    let policy = policy(json!({"enabled": "invalid"}));
    for raw in [
        r#"["REQ","read",{"kinds":[1059]}]"#,
        r#"["COUNT","count",{"kinds":[1059]}]"#,
        r#"["NEG-OPEN","sync",{"kinds":[1059]},"00"]"#,
        r#"["CLOSE","read"]"#,
    ] {
        let incoming = serde_json::from_str(raw).unwrap();
        let msg = ClientMessage::new(1, raw.into(), incoming);
        assert!(matches!(
            policy.filter(msg),
            ExtensionMessageResult::Continue(_)
        ));
    }
    let auth = IncomingMessage::Auth(event(22242, 1, vec![]));
    assert!(matches!(
        policy.filter(ClientMessage::new(1, String::new(), auth)),
        ExtensionMessageResult::Continue(_)
    ));
}

#[actix_rt::test]
async fn invalid_policy_prevents_server_startup() {
    let (_root, app) = app();
    app.setting.write().extra.insert(
        "event_policy".into(),
        json!({"enabled": true, "allowed_kinds": false}),
    );
    let error = app
        .add_extension(EventPolicy::new())
        .web_server()
        .err()
        .unwrap();
    assert!(error.to_string().contains("event_policy"));
}

#[actix_rt::test]
async fn custom_app_builders_validate_policy_before_serving() {
    for direct_factory in [false, true] {
        for (value, valid) in [
            (json!({"allowed_kinds": false}), false),
            (json!({"enabled": true, "allowed_kinds": false}), false),
            (json!({"enabled": false, "allowed_kinds": false}), true),
            (json!({}), true),
        ] {
            let (_root, app) = app();
            app.setting
                .write()
                .extra
                .insert("event_policy".into(), value);
            let app = app.add_extension(EventPolicy::new());
            let initialized = if direct_factory {
                create_web_app(web::Data::new(app))
                    .into_factory()
                    .new_service(Default::default())
                    .await
                    .is_ok()
            } else {
                app.web_app()
                    .into_factory()
                    .new_service(Default::default())
                    .await
                    .is_ok()
            };
            assert_eq!(initialized, valid, "direct factory: {direct_factory}");
        }
    }
}

#[actix_rt::test]
async fn unvalidated_reload_preserves_nip11_for_the_retained_policy() {
    for enabled in [true, false] {
        let (root, app) = app();
        app.setting.write().extra.get_mut("event_policy").unwrap()["enabled"] = json!(enabled);
        let app = app.add_extension(EventPolicy::new());
        let config = root.path().join(CONFIG_FILE);
        std::fs::write(
            &config,
            CONFIG.replace(
                "allowed_kinds = [1, 5, 30023, 30078]",
                "allowed_kinds = false",
            ),
        )
        .unwrap();
        app.setting.reload(&config, None).unwrap();
        app.extensions.write().call_setting(&app.setting);
        let info: Value =
            serde_json::from_str(&app.setting.read().render_information().unwrap()).unwrap();
        assert_eq!(
            info["limitation"]["restricted_writes"]
                .as_bool()
                .unwrap_or(false),
            enabled
        );
    }
}

#[actix_rt::test]
async fn validated_reloads_preserve_settings_and_update_nip11() {
    let (root, app) = app();
    let config = root.path().join(CONFIG_FILE);
    let app = app.add_extension(EventPolicy::new());
    for (source, valid, restricted) in [
        (CONFIG.to_owned(), true, true),
        (
            CONFIG.replace(
                "allowed_kinds = [1, 5, 30023, 30078]",
                "allowed_kinds = false",
            ),
            false,
            true,
        ),
        (
            CONFIG.replace("enabled = true", "enabled = false"),
            true,
            false,
        ),
        (CONFIG.to_owned(), true, true),
        (String::new(), true, false),
    ] {
        let previous = app.setting.read().extra.clone();
        std::fs::write(&config, source).unwrap();
        let result = app.setting.reload_validated(&config, None, |candidate| {
            app.extensions.read().validate_setting(candidate)
        });
        assert_eq!(result.is_ok(), valid);
        if result.is_ok() {
            app.extensions.write().call_setting(&app.setting);
        } else {
            assert_eq!(app.setting.read().extra, previous);
        }
        let info: Value =
            serde_json::from_str(&app.setting.read().render_information().unwrap()).unwrap();
        assert_eq!(
            info["limitation"]["restricted_writes"]
                .as_bool()
                .unwrap_or(false),
            restricted
        );
    }
}

#[actix_rt::test]
async fn extension_dispatch_returns_protocol_responses() {
    let (_root, app) = app();
    {
        let mut setting = app.setting.write();
        setting.extra.insert(
            "auth".into(),
            json!({
                "enabled": true, "event": {"ip_blacklist": ["192.0.2.1"]}
            }),
        );
        #[cfg(feature = "rate_limiter")]
        setting.extra.insert(
            "rate_limiter".into(),
            json!({
                "enabled": true, "event": [{"period": "60s", "limit": 4}]
            }),
        );
    }
    let app = app.add_extension(crate::Auth::new());
    #[cfg(feature = "rate_limiter")]
    let app = app.add_extension(crate::Ratelimiter::new());
    let app = web::Data::new(app.add_extension(EventPolicy::new()));
    let stream =
        futures_util::stream::empty::<Result<bytes::Bytes, actix_web::error::PayloadError>>();
    let _context = ws::WebsocketContext::with_factory(stream, move |ctx| {
        let mut session = Session::new("192.0.2.2".into(), app.clone());
        let extensions = app.extensions.read();
        for event in [
            event(1059, 1, vec![]),
            event(30078, 2, identifier("unlisted")),
        ] {
            let id = event.id_str();
            let (response_id, reason) =
                rejection(extensions.call_message(message(event), &mut session, ctx));
            assert_eq!(response_id, id);
            assert!(reason.starts_with("blocked:"));
        }
        for event in [event(1, 1, vec![]), event(30078, 1, identifier("profile"))] {
            assert!(matches!(
                extensions.call_message(message(event), &mut session, ctx),
                ExtensionMessageResult::Continue(_)
            ));
        }
        #[cfg(feature = "rate_limiter")]
        {
            let (_, reason) = rejection(extensions.call_message(
                message(event(1059, 1, vec![])),
                &mut session,
                ctx,
            ));
            assert!(reason.starts_with("rate-limited:"));
        }
        let mut blacklisted = Session::new("192.0.2.1".into(), app.clone());
        let (_, reason) = rejection(extensions.call_message(
            message(event(1059, 1, vec![])),
            &mut blacklisted,
            ctx,
        ));
        assert_eq!(reason, "auth-required: ip in blacklist");
        session
    });
}
