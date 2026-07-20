use nostr_extensions::Auth;
use nostr_relay::App;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use tempfile::TempDir;
type Result<T = ()> = anyhow::Result<T>;

fn fixture(config: &Value, watch: bool) -> Result<(TempDir, PathBuf, App)> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("relay.json");
    fs::write(&file, config.to_string())?;
    let app = App::create(Some(file.as_path()), watch, None, Some(dir.path()))?;
    Ok((dir, file, app))
}

#[actix_rt::test]
async fn auth_edits_keep_startup_settings_while_base_edits_apply() -> Result {
    for config in [
        json!({}),
        json!({"auth":{"enabled":true,"req":{"pubkey_whitelist":["reader"]},"event":{"event_pubkey_whitelist":["writer"]}}}),
    ] {
        let enabled = config.get("auth").is_some();
        let (_dir, file, app) = fixture(&config, false)?;
        let app = app.add_extension(Auth::new());
        for changed in [
            Value::Null,
            json!({"enabled":false}),
            json!({"enabled":true}),
        ] {
            fs::write(
                &file,
                json!({"auth":changed,"information":{"name":"updated"}}).to_string(),
            )?;
            app.setting.reload(&file, None)?;
            app.extensions.write().call_setting(&app.setting);
            let current = app.setting.read();
            assert_eq!(current.extra.get("auth"), config.get("auth"));
            assert_eq!(current.information.name, "updated");
            assert_eq!(current.information.supported_nips.contains(&42), enabled);
            let info: Value = serde_json::from_str(&current.render_information()?)?;
            assert_eq!(
                info["limitation"]["restricted_writes"]
                    .as_bool()
                    .unwrap_or(false),
                enabled
            );
        }
    }
    Ok(())
}

#[actix_rt::test]
async fn checked_auth_keeps_its_settings_before_registration() -> Result {
    let (_dir, file, app) = fixture(&json!({"auth":{"enabled":true}}), false)?;
    let auth = Auth::from_setting(&app.setting)?;
    fs::write(
        &file,
        json!({"auth":{"registry_file":"missing-policy.json"},"information":{"name":"updated"}})
            .to_string(),
    )?;
    app.setting.reload(&file, None)?;
    app.extensions.write().call_setting(&app.setting);
    let app = app.add_extension(auth);
    let current = app.setting.read();
    assert_eq!(current.extra["auth"], json!({"enabled":true}));
    assert!(current.information.supported_nips.contains(&42));
    assert_eq!(current.information.name, "updated");
    Ok(())
}

#[actix_rt::test]
async fn watch_reloads_other_extensions_while_auth_stays_at_startup_settings() -> Result {
    let auth = json!({"enabled":true});
    let (_dir, file, app) = fixture(&json!({"auth":auth}), true)?;
    let configured = Auth::from_setting(&app.setting)?;
    let app = app.add_extension(configured).add_extension(LegacyNip);
    fs::write(
        &file,
        json!({"auth":{"enabled":false},"legacy_nip":{"enabled":true},"information":{"name":"changed"}})
            .to_string(),
    )?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while app.setting.read().get_extension::<bool>() != Some(&true) {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "extension reload callback did not run"
        );
        actix_rt::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let current = app.setting.read();
    assert_eq!(current.information.name, "changed");
    assert_eq!(current.extra["auth"], auth);
    assert!(current.information.supported_nips.contains(&42));
    Ok(())
}

#[actix_rt::test]
async fn invalid_auth_rejects_startup() -> Result {
    for auth in [
        json!({"enabled":"invalid"}),
        json!({"enabled":null}),
        json!({"enabled":true,"typo":true}),
        json!({"enabled":true,"req":{"pubkey_whitelst":[]}}),
        json!({"enabled":true,"registry_file":"missing-policy.json"}),
        json!({"registry_file":"missing-policy.json"}),
        json!({"enabled":false,"registry_file":"missing-policy.json"}),
    ] {
        let (_dir, _file, app) = fixture(&json!({"auth":auth}), false)?;
        assert!(Auth::from_setting(&app.setting).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            app.add_extension(Auth::new())
        }))
        .is_err());
    }
    Ok(())
}

#[actix_rt::test]
async fn non_auth_settings_keep_accepting_extra_keys_and_reload() -> Result {
    let (_dir, file, app) = fixture(
        &json!({
            "count":{"enabled":true,"extra":true},
            "search":{"enabled":true,"extra":true},
            "metrics":{"enabled":true,"extra":true},
            "rate_limiter":{"enabled":true,"extra":true,
                "event":[{"period":"1s","limit":1,"extra":true}]}
        }),
        false,
    )?;
    #[cfg(feature = "count")]
    let app = {
        let count = nostr_extensions::Count::new(app.db.clone());
        app.add_extension(count)
    };
    #[cfg(feature = "search")]
    let app = app.add_extension(nostr_extensions::Search::new());
    #[cfg(feature = "metrics")]
    let app = app.add_extension(nostr_extensions::Metrics::new());
    #[cfg(feature = "rate_limiter")]
    let app = app.add_extension(nostr_extensions::Ratelimiter::new());
    let changed = json!({
        "count":{"enabled":false}, "search":{"enabled":false},
        "metrics":{"enabled":false}, "rate_limiter":{"enabled":false},
        "information":{"name":"updated"}
    });
    fs::write(&file, changed.to_string())?;
    app.setting.reload(&file, None)?;
    app.extensions.write().call_setting(&app.setting);
    let current = app.setting.read();
    assert_eq!(current.information.name, "updated");
    #[cfg(feature = "count")]
    assert!(!current.information.supported_nips.contains(&45));
    #[cfg(feature = "search")]
    assert!(!current.information.supported_nips.contains(&50));
    #[cfg(feature = "metrics")]
    assert!(
        !current
            .get_extension::<nostr_extensions::metrics::MetricsSetting>()
            .unwrap()
            .enabled
    );
    Ok(())
}

struct LegacyNip;
impl nostr_relay::Extension for LegacyNip {
    fn name(&self) -> &'static str {
        "legacy_nip"
    }
    fn setting(&mut self, setting: &nostr_relay::setting::SettingWrapper) {
        let enabled = setting
            .read()
            .extra
            .get(self.name())
            .and_then(|value| value["enabled"].as_bool())
            .unwrap_or(false);
        let mut setting = setting.write();
        setting.set_extension(enabled);
        if enabled {
            setting.add_nip(99);
            setting.add_information("legacy_info".into(), json!(true));
            setting.add_limitation("legacy_limit".into(), json!(2));
        }
    }
}

#[actix_rt::test]
async fn reload_withdraws_extension_metadata_without_dropping_frozen_auth() -> Result {
    let (_dir, file, app) = fixture(
        &json!({"auth":{"enabled":true},"legacy_nip":{"enabled":true}}),
        false,
    )?;
    let app = app.add_extension(Auth::new()).add_extension(LegacyNip);
    assert!(app.setting.read().information.supported_nips.contains(&99));
    for enabled in [false, true, false] {
        fs::write(
            &file,
            json!({"auth":{"enabled":false},"legacy_nip":{"enabled":enabled}}).to_string(),
        )?;
        app.setting.reload(&file, None)?;
        app.extensions.write().call_setting(&app.setting);
        let current = app.setting.read();
        assert_eq!(current.information.supported_nips.contains(&99), enabled);
        assert!(current.information.supported_nips.contains(&42));
        assert!(current.information.supported_nips.contains(&1));
        let info: Value = serde_json::from_str(&current.render_information()?)?;
        assert_eq!(info.get("legacy_info").is_some(), enabled);
        assert_eq!(info["limitation"].get("legacy_limit").is_some(), enabled);
    }
    Ok(())
}
