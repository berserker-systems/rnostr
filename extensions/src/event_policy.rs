//! Admission rules for new EVENT writes. Existing events remain readable.

use std::collections::{BTreeMap, BTreeSet};

use nostr_relay::{
    db::{event_identifier, Event, ADDRESSABLE_KINDS},
    message::{ClientMessage, IncomingMessage, OutgoingMessage},
    setting::SettingWrapper,
    Extension, ExtensionMessageResult, Session, Setting,
};
use serde::Deserialize;
use tracing::{error, info};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventPolicySetting {
    pub enabled: bool,
    pub allowed_kinds: BTreeSet<u16>,
    pub identifiers: BTreeMap<u16, BTreeSet<String>>,
}

impl EventPolicySetting {
    fn parse(setting: &Setting) -> Result<Self, String> {
        let Some(value) = setting.extra.get("event_policy") else {
            return Ok(Self::default());
        };
        if value.get("enabled").and_then(serde_json::Value::as_bool) == Some(false) {
            return Ok(Self::default());
        }
        let parsed: Self = serde_json::from_value(value.clone()).map_err(|err| err.to_string())?;
        if parsed.enabled {
            parsed.validate()?;
        }
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), String> {
        for kind in self.identifiers.keys() {
            if !ADDRESSABLE_KINDS.contains(kind) {
                return Err(format!("identifiers kind {kind} must be in 30000..40000"));
            }
            if !self.allowed_kinds.contains(kind) {
                return Err(format!(
                    "identifiers kind {kind} is missing from allowed_kinds"
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct EventPolicy {
    setting: Option<EventPolicySetting>,
}

impl EventPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    fn check(&self, event: &Event) -> Result<(), &'static str> {
        let Some(setting) = &self.setting else {
            return Err("blocked: event policy configuration is invalid");
        };
        if !setting.enabled {
            return Ok(());
        }
        if !setting.allowed_kinds.contains(&event.kind()) {
            return Err("blocked: event kind is not accepted by this relay");
        }
        if let Some(identifiers) = setting.identifiers.get(&event.kind()) {
            if !identifiers.contains(event_identifier(event.tags())) {
                return Err("blocked: event identifier is not accepted by this relay");
            }
        }
        Ok(())
    }

    fn filter(&self, msg: ClientMessage) -> ExtensionMessageResult {
        if let IncomingMessage::Event(event) = &msg.msg {
            if let Err(reason) = self.check(event) {
                return OutgoingMessage::ok(&event.id_str(), false, reason).into();
            }
        }
        ExtensionMessageResult::Continue(msg)
    }
}

impl Extension for EventPolicy {
    fn name(&self) -> &'static str {
        "event_policy"
    }

    fn validate_setting(&self, setting: &Setting) -> nostr_relay::Result<()> {
        EventPolicySetting::parse(setting)
            .map(|_| ())
            .map_err(|reason| nostr_relay::Error::Message(format!("event_policy: {reason}")))
    }

    fn setting(&mut self, setting: &SettingWrapper) {
        let mut setting = setting.write();
        let parsed = match EventPolicySetting::parse(&setting) {
            Ok(parsed) => parsed,
            Err(reason) => {
                setting.set_restricted_writes(
                    self.name(),
                    self.setting.as_ref().is_some_and(|setting| setting.enabled),
                );
                error!(%reason, "Invalid event_policy configuration; keeping previous policy");
                return;
            }
        };
        setting.set_restricted_writes(self.name(), parsed.enabled);
        info!(
            enabled = parsed.enabled,
            allowed_kinds = ?parsed.allowed_kinds,
            "Loaded event write policy"
        );
        self.setting = Some(parsed);
    }

    fn message(
        &self,
        msg: ClientMessage,
        _session: &mut Session,
        _ctx: &mut <Session as actix::Actor>::Context,
    ) -> ExtensionMessageResult {
        self.filter(msg)
    }
}

#[cfg(test)]
mod tests;
