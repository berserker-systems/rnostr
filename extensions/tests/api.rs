use nostr_extensions::auth::{Auth, AuthSetting, Permission};
use nostr_relay::{setting::SettingWrapper, Extension, Setting};
use serde_json::json;

#[test]
fn public_auth_settings_remain_compatible() {
    let _: AuthSetting = AuthSetting {
        enabled: true,
        req: Some(Permission::default()),
        event: None,
    };
    let mut setting = Setting::default();
    setting.extra.insert(
        "auth".into(),
        json!({
            "enabled":true, "registry_file":"policy.json", "future_key":true
        }),
    );
    let auth: AuthSetting = setting.parse_extension("auth");
    assert!(auth.enabled);
    setting.extra.get_mut("auth").unwrap()["enabled"] = json!("invalid");
    let auth: AuthSetting = setting.parse_extension("auth");
    assert!(!auth.enabled);
    assert!(setting.try_parse_extension::<AuthSetting>("auth").is_err());
}

#[test]
fn legacy_auth_callback_keeps_its_startup_nip() {
    let setting: SettingWrapper = Setting::default().into();
    setting
        .write()
        .extra
        .insert("auth".into(), json!({"enabled":true}));
    let mut auth = Auth::new();
    auth.setting(&setting);
    for changed in [
        json!({"enabled":true, "registry_file":"missing/policy.json"}),
        json!({"enabled":false}),
    ] {
        setting.write().extra.insert("auth".into(), changed);
        setting.write().information.supported_nips.clear();
        auth.setting(&setting);
        assert!(setting.read().information.supported_nips.contains(&42));
    }
}
