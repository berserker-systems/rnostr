use crate::{
    message::{ClientMessage, IncomingMessage, OutgoingMessage, RejectionTarget},
    setting::SettingWrapper,
    Session,
};
use actix_web::web::ServiceConfig;

pub enum ExtensionMessageResult {
    /// Continue run the next extension message method, the server takes over finally.
    Continue(ClientMessage),
    /// Respond and stop dispatching.
    Stop(OutgoingMessage),
    /// Reject; the dispatcher formats the error and invalidates reconciliation state.
    Reject(Box<ClientMessage>, String),
    /// Stop run the next, does not send any messages to the client.
    Ignore,
}

impl From<OutgoingMessage> for ExtensionMessageResult {
    fn from(value: OutgoingMessage) -> Self {
        Self::Stop(value)
    }
}

impl ClientMessage {
    pub fn reject(self, reason: impl Into<String>) -> ExtensionMessageResult {
        ExtensionMessageResult::Reject(Box::new(self), reason.into())
    }
}

/// Extension for user session
pub trait Extension: Send + Sync {
    fn name(&self) -> &'static str;

    /// Execute when added to extension list and setting reload
    #[allow(unused_variables)]
    fn setting(&mut self, setting: &SettingWrapper) {}

    /// config actix web service
    #[allow(unused_variables)]
    fn config_web(&mut self, cfg: &mut ServiceConfig) {}

    /// Execute after a user connect
    #[allow(unused_variables)]
    fn connected(&self, session: &mut Session, ctx: &mut <Session as actix::Actor>::Context) {}

    /// Execute when connection lost
    #[allow(unused_variables)]
    fn disconnected(&self, session: &mut Session, ctx: &mut <Session as actix::Actor>::Context) {}

    /// Invalidate a reconciliation on replacement, closure, or rejection.
    fn close_reconciliation(&self, _id: &str, _session: &mut Session) {}

    /// Execute when message incoming
    #[allow(unused_variables)]
    fn message(
        &self,
        msg: ClientMessage,
        session: &mut Session,
        ctx: &mut <Session as actix::Actor>::Context,
    ) -> ExtensionMessageResult {
        ExtensionMessageResult::Continue(msg)
    }
}

/// extensions
#[derive(Default)]
pub struct Extensions {
    list: Vec<Box<dyn Extension>>,
}

impl Extensions {
    pub fn add<E: Extension + 'static>(&mut self, ext: E) {
        self.list.push(Box::new(ext));
    }

    pub fn call_setting(&mut self, setting: &SettingWrapper) {
        for ext in &mut self.list {
            ext.setting(setting);
        }
    }

    pub fn call_config_web(&mut self, cfg: &mut ServiceConfig) {
        for ext in &mut self.list {
            ext.config_web(cfg);
        }
    }

    pub fn call_connected(
        &self,
        session: &mut Session,
        ctx: &mut <Session as actix::Actor>::Context,
    ) {
        for ext in &self.list {
            ext.connected(session, ctx);
        }
    }

    pub fn call_disconnected(
        &self,
        session: &mut Session,
        ctx: &mut <Session as actix::Actor>::Context,
    ) {
        for ext in &self.list {
            ext.disconnected(session, ctx);
        }
    }

    /// Dispatch and respond; return only unhandled requests.
    pub fn call_message(
        &self,
        mut msg: ClientMessage,
        session: &mut Session,
        ctx: &mut <Session as actix::Actor>::Context,
    ) -> Option<ClientMessage> {
        match &msg.msg {
            IncomingMessage::NegOpen(open) => self.close_reconciliation(&open.id, session),
            IncomingMessage::NegClose(id) => self.close_reconciliation(id, session),
            _ => {}
        }
        let validation = msg.validate(&session.app.setting.read().limitation);
        if let Err(err) = validation {
            ctx.text(self.reject(&msg.msg.rejection_target(), &err.to_string(), session));
            return None;
        }
        for ext in &self.list {
            match ext.message(msg, session, ctx) {
                ExtensionMessageResult::Continue(m) => {
                    msg = m;
                }
                ExtensionMessageResult::Stop(o) => {
                    ctx.text(o);
                    return None;
                }
                ExtensionMessageResult::Reject(request, reason) => {
                    ctx.text(self.reject(&request.msg.rejection_target(), &reason, session));
                    return None;
                }
                ExtensionMessageResult::Ignore => {
                    return None;
                }
            };
        }
        if msg.msg.reconciliation_id().is_some() {
            // Valid NEG-CLOSE is silent; malformed closes retain normal error diagnostics.
            if !matches!(msg.msg, IncomingMessage::NegClose(_)) {
                ctx.text(self.reject(
                    &msg.msg.rejection_target(),
                    "closed: reconciliation unsupported",
                    session,
                ));
            }
            None
        } else {
            Some(msg)
        }
    }

    pub fn close_reconciliation(&self, id: &str, session: &mut Session) {
        for ext in &self.list {
            ext.close_reconciliation(id, session);
        }
    }

    pub(crate) fn reject(
        &self,
        target: &RejectionTarget,
        reason: &str,
        session: &mut Session,
    ) -> OutgoingMessage {
        if let RejectionTarget::Reconciliation(id) = target {
            self.close_reconciliation(id, session);
        }
        target.response(
            reason,
            session.app.setting.read().limitation.max_subid_length,
        )
    }
}
