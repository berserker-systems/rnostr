use actix::{Message, MessageResponse, Recipient};
use bytestring::ByteString;
use nostr_db::{now, CheckEventResult, Event, Filter};
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};
use std::fmt::Display;
use std::{fmt, marker::PhantomData};

use crate::{setting::Limitation, Error};

pub const NEG_OPEN: &str = "NEG-OPEN";
pub const NEG_MSG: &str = "NEG-MSG";
pub const NEG_CLOSE: &str = "NEG-CLOSE";
pub const NEG_ERR: &str = "NEG-ERR";

/// New session is created
#[derive(Message, Clone, Debug)]
#[rtype(usize)]
pub struct Connect {
    pub addr: Recipient<OutgoingMessage>,
}

/// Session is disconnected
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct Disconnect {
    pub id: usize,
}

/// Message from client
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ClientMessage {
    /// Id of the client session
    pub id: usize,
    /// text message
    pub text: String,
    /// parsed message
    pub msg: IncomingMessage,
    /// is nip70 checked
    pub nip70_checked: bool,
}

impl ClientMessage {
    pub fn new(id: usize, text: String, msg: IncomingMessage) -> Self {
        Self {
            id,
            text,
            msg,
            nip70_checked: false,
        }
    }
}

macro_rules! check_max {
    ($source:expr, $limit:expr) => {
        if $source > $limit {
            return Err(Error::Invalid(format!("{} {}", stringify!($limit), $limit)));
        }
    };
}

macro_rules! check_min {
    ($source:expr, $limit:expr) => {
        if $source < $limit {
            return Err(Error::Invalid(format!("{} {}", stringify!($limit), $limit)));
        }
    };
}

impl ClientMessage {
    pub fn validate_nip70(&self) -> Result<(), Error> {
        if !self.nip70_checked {
            if let IncomingMessage::Event(event) = &self.msg {
                for tag in event.tags() {
                    if tag.len() == 1 && tag[0] == "-" {
                        return Err(Error::Message(
                            "blocked: event marked as protected".to_owned(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn validate(&mut self, limitation: &Limitation) -> Result<(), Error> {
        check_max!(self.text.len(), limitation.max_message_length);

        match &mut self.msg {
            IncomingMessage::Event(event) => {
                check_max!(event.tags().len(), limitation.max_event_tags);
                event.validate(
                    now(),
                    limitation.max_event_time_older_than_now,
                    limitation.max_event_time_newer_than_now,
                )?;
            }

            IncomingMessage::Req(sub) => {
                check_max!(sub.filters.len(), limitation.max_filters);
                check_max!(sub.id.len(), limitation.max_subid_length);

                for f in &mut sub.filters {
                    // Fill default limit, Override the incoming limit if it is too large
                    if let Some(limit) = f.limit {
                        if limit > limitation.max_limit {
                            f.limit = Some(limitation.max_limit);
                        }
                    } else {
                        f.limit = Some(limitation.max_limit);
                    }
                    for id in f.ids.iter() {
                        check_min!(id.len(), limitation.min_prefix);
                    }
                }
            }

            IncomingMessage::NegOpen(open) => {
                check_max!(open.id.len(), limitation.max_subid_length);
                if open.filter.limit.is_some() {
                    return Err(Error::Invalid("limit is not supported".to_owned()));
                }
            }
            IncomingMessage::NegMsg(id, _) | IncomingMessage::NegClose(id) => {
                check_max!(id.len(), limitation.max_subid_length);
            }
            _ => {}
        }
        Ok(())
    }
}

// #[derive(Deserialize, Clone, Debug)]
// #[serde(rename_all = "UPPERCASE", tag = "0")]
// pub enum IncomingMessage {
//     Event {
//         event: Event,
//     },
//     Close {
//         id: String,
//     },
//     Req(Subscription),
//     #[serde(other, deserialize_with = "ignore_contents")]
//     Unknown,
// }

/// Parsed incoming messages from a client
#[derive(Clone, Debug)]
pub enum IncomingMessage {
    Event(Event),
    Close(String),
    Req(Subscription),
    /// nip-42
    Auth(Event),
    /// nip-45
    Count(Subscription),
    /// nip-77
    NegOpen(NegOpen),
    NegMsg(String, String),
    NegClose(String),
    Unknown(String, Vec<Value>),
}

impl IncomingMessage {
    pub fn reconciliation_id(&self) -> Option<&str> {
        match self {
            Self::NegOpen(open) => Some(&open.id),
            Self::NegMsg(id, _) | Self::NegClose(id) => Some(id),
            _ => None,
        }
    }

    pub fn command(&self) -> &str {
        match self {
            IncomingMessage::Event(_) => "EVENT",
            IncomingMessage::Close(_) => "CLOSE",
            IncomingMessage::Req(_) => "REQ",
            IncomingMessage::Auth(_) => "AUTH",
            IncomingMessage::Count(_) => "COUNT",
            IncomingMessage::NegOpen(_) => NEG_OPEN,
            IncomingMessage::NegMsg(..) => NEG_MSG,
            IncomingMessage::NegClose(_) => NEG_CLOSE,
            IncomingMessage::Unknown(cmd, _) => cmd,
        }
    }

    pub fn known_command(&self) -> Option<&'static str> {
        match self {
            IncomingMessage::Event(_) => Some("EVENT"),
            IncomingMessage::Close(_) => Some("CLOSE"),
            IncomingMessage::Req(_) => Some("REQ"),
            IncomingMessage::Auth(_) => Some("AUTH"),
            IncomingMessage::Count(_) => Some("COUNT"),
            IncomingMessage::NegOpen(_) => Some(NEG_OPEN),
            IncomingMessage::NegMsg(..) => Some(NEG_MSG),
            IncomingMessage::NegClose(_) => Some(NEG_CLOSE),
            IncomingMessage::Unknown(_, _) => None,
        }
    }

    pub(crate) fn rejection_target(&self) -> RejectionTarget {
        match self {
            Self::Event(event) => RejectionTarget::Event(event.id_str()),
            Self::Req(sub) => RejectionTarget::Subscription(sub.id.clone()),
            _ => self
                .reconciliation_id()
                .map_or(RejectionTarget::Notice, |id| {
                    RejectionTarget::Reconciliation(id.to_owned())
                }),
        }
    }
}

pub(crate) enum RejectionTarget {
    Event(String),
    Subscription(String),
    Reconciliation(String),
    Notice,
}

impl RejectionTarget {
    pub(crate) fn response(&self, reason: &str, max_subid_length: usize) -> OutgoingMessage {
        let bounded = || reason.chars().take(256).collect::<String>();
        match self {
            Self::Event(id) => OutgoingMessage::ok(id, false, reason),
            Self::Subscription(id) => OutgoingMessage::closed(id, reason),
            Self::Reconciliation(id) if id.len() <= max_subid_length => {
                OutgoingMessage::neg_err(id, &bounded())
            }
            Self::Reconciliation(_) | Self::Notice => OutgoingMessage::notice(&bounded()),
        }
    }
}

pub(crate) fn reconciliation_prefix(text: &str) -> Option<(&'static str, String)> {
    struct Prefix<'a>(&'a mut Option<(&'static str, String)>);
    impl<'de> Visitor<'de> for Prefix<'_> {
        type Value = ();

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a reconciliation message prefix")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            let command = match seq.next_element::<&str>()? {
                Some(NEG_OPEN) => NEG_OPEN,
                Some(NEG_MSG) => NEG_MSG,
                Some(NEG_CLOSE) => NEG_CLOSE,
                _ => return Ok(()),
            };
            if let Some(id) = seq.next_element()? {
                *self.0 = Some((command, id));
            }
            Ok(())
        }
    }
    let mut prefix = None;
    // Retain the prefix even when the remaining message is invalid.
    let _ = serde::Deserializer::deserialize_seq(
        &mut serde_json::Deserializer::from_str(text),
        Prefix(&mut prefix),
    );
    prefix
}

// https://github.com/serde-rs/serde/issues/1337

struct MessageVisitor(PhantomData<()>);

impl<'de> Visitor<'de> for MessageVisitor {
    type Value = IncomingMessage;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("sequence")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let t: &str = seq
            .next_element()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        match t {
            "EVENT" => Ok(IncomingMessage::Event(
                seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?,
            )),
            "CLOSE" => Ok(IncomingMessage::Close(
                seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?,
            )),
            "REQ" => {
                let t = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let r = Vec::<Filter>::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(IncomingMessage::Req(Subscription { id: t, filters: r }))
            }
            "AUTH" => Ok(IncomingMessage::Auth(
                seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?,
            )),
            "COUNT" => {
                let t = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let r = Vec::<Filter>::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
                Ok(IncomingMessage::Count(Subscription { id: t, filters: r }))
            }
            NEG_OPEN => {
                let id = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let filter = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let message = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;
                Ok(IncomingMessage::NegOpen(NegOpen {
                    id,
                    filter,
                    message,
                }))
            }
            NEG_MSG => {
                let id = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let message = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                Ok(IncomingMessage::NegMsg(id, message))
            }
            NEG_CLOSE => Ok(IncomingMessage::NegClose(
                seq.next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?,
            )),
            _ => Ok(IncomingMessage::Unknown(
                t.to_string(),
                Vec::<Value>::deserialize(de::value::SeqAccessDeserializer::new(seq))?,
            )),
        }
    }
}

impl<'de> Deserialize<'de> for IncomingMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(MessageVisitor(PhantomData))
    }
}

// fn ignore_contents<'de, D>(deserializer: D) -> Result<(), D::Error>
// where
//     D: Deserializer<'de>,
// {
//     // Ignore any content at this part of the json structure
//     let _ = deserializer.deserialize_ignored_any(serde::de::IgnoredAny);
//     // Return unit as our 'Unknown' variant has no args
//     Ok(())
// }

/// Subscription
#[derive(Clone, Debug)]
pub struct Subscription {
    pub id: String,
    pub filters: Vec<Filter>,
}

/// [NIP-77](https://nips.be/77) `["NEG-OPEN", <subscription id>, <filter>, <initial message>]`
#[derive(Clone, Debug)]
pub struct NegOpen {
    pub id: String,
    pub filter: Filter,
    /// The initial negentropy message, still hex-encoded.
    pub message: String,
}

// https://github.com/serde-rs/serde/issues/1337
// prefix
// impl<'de> Deserialize<'de> for Subscription {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         struct PrefixVisitor(PhantomData<()>);

//         impl<'de> Visitor<'de> for PrefixVisitor {
//             type Value = Subscription;

//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str("sequence")
//             }

//             fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
//             where
//                 A: SeqAccess<'de>,
//             {
//                 let t = seq
//                     .next_element()?
//                     .ok_or_else(|| de::Error::invalid_length(0, &self))?;
//                 let r = Vec::<Filter>::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
//                 Ok(Subscription { id: t, filters: r })
//             }
//         }

//         deserializer.deserialize_seq(PrefixVisitor(PhantomData))
//     }
// }

/// The message sent to the client
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct OutgoingMessage(pub String);

impl OutgoingMessage {
    pub fn notice(message: &str) -> Self {
        Self(json!(["NOTICE", message]).to_string())
    }

    pub fn closed(sub_id: &str, message: &str) -> Self {
        Self(json!(["CLOSED", sub_id, message]).to_string())
    }

    pub fn eose(sub_id: &str) -> Self {
        Self(format!(r#"["EOSE","{}"]"#, sub_id))
    }

    pub fn event(sub_id: &str, event: &str) -> Self {
        Self(format!(r#"["EVENT","{}",{}]"#, sub_id, event))
    }

    pub fn ok(event_id: &str, saved: bool, message: &str) -> Self {
        Self(json!(["OK", event_id, saved, message]).to_string())
    }

    /// nip-77 error; the reconciliation is closed once this is sent
    pub fn neg_err(sub_id: &str, message: &str) -> Self {
        Self(json!([NEG_ERR, sub_id, message]).to_string())
    }
}

impl Display for OutgoingMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)?;
        Ok(())
    }
}

// impl Into<ByteString> for OutgoingMessage {
//     fn into(self) -> ByteString {
//         ByteString::from(self.0)
//     }
// }

impl From<OutgoingMessage> for ByteString {
    fn from(val: OutgoingMessage) -> Self {
        ByteString::from(val.0)
    }
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct WriteEvent {
    pub id: usize,
    pub event: Event,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub enum WriteEventResult {
    Write {
        id: usize,
        event: Event,
        result: CheckEventResult,
    },
    Message {
        id: usize,
        event: Event,
        msg: OutgoingMessage,
    },
}
// pub struct WriteEventResult {
//     pub id: usize,
//     pub event: Event,
//     pub result: CheckEventResult,
// }

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ReadEvent {
    pub id: usize,
    pub subscription: Subscription,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct ReadEventResult {
    pub id: usize,
    pub sub_id: String,
    pub msg: OutgoingMessage,
}

#[derive(MessageResponse, Clone, Debug, PartialEq, Eq)]
pub enum Subscribed {
    Ok,
    Overlimit,
    InvalidIdLength,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "Subscribed")]
pub struct Subscribe {
    pub id: usize,
    pub subscription: Subscription,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct Unsubscribe {
    pub id: usize,
    pub sub_id: Option<String>,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct Dispatch {
    pub id: usize,
    pub event: Event,
}

#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct SubscribeResult {
    pub id: usize,
    pub sub_id: String,
    pub msg: OutgoingMessage,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn rejection_bounds_preserve_event_and_subscription_reasons() -> Result<()> {
        use RejectionTarget::{Event, Notice, Reconciliation, Subscription};

        let reason = format!("invalid: {}", "é".repeat(512));
        for (target, limit) in [
            (Event("event".to_owned()), usize::MAX),
            (Subscription("sub".to_owned()), usize::MAX),
            (Reconciliation("sync".to_owned()), 256),
            (Reconciliation("long".repeat(100)), 256),
            (Notice, 256),
        ] {
            let expected: String = reason.chars().take(limit).collect();
            let response: Value = serde_json::from_str(&target.response(&reason, 100).0)?;
            assert_eq!(
                response.as_array().unwrap().last().unwrap(),
                &json!(expected)
            );
        }
        Ok(())
    }

    #[test]
    fn de_incoming_message() -> Result<()> {
        // close
        let msg: IncomingMessage = serde_json::from_str(r#"["CLOSE", "sub_id1"]"#)?;
        assert!(matches!(msg, IncomingMessage::Close(ref id) if id == "sub_id1"));

        let msg = serde_json::from_str::<IncomingMessage>(r#"["CLOSE", "sub_id1", "other"]"#);
        assert!(msg.is_err());

        // event
        let msg: IncomingMessage = serde_json::from_str(
            r#"["EVENT", {
            "content": "Good morning everyone 😃",
            "created_at": 1680690006,
            "id": "332747c0fab8a1a92def4b0937e177be6df4382ce6dd7724f86dc4710b7d4d7d",
            "kind": 1,
            "pubkey": "7abf57d516b1ff7308ca3bd5650ea6a4674d469c7c5057b1d005fb13d218bfef",
            "sig": "ef4ff4f69ac387239eb1401fb07d7a44a5d5d57127e0dc3466a0403cf7d5486b668608ebfcbe9ff1f8d3b5d710545999fe08ee767284ec0b474e4cf92537678f",
            "tags": [["t", "nostr"], ["t", ""], ["expiration", "1"], ["delegation", "8e0d3d3eb2881ec137a11debe736a9086715a8c8beeeda615780064d68bc25dd"]]
          }]"#,
        )?;
        assert!(matches!(msg, IncomingMessage::Event( ref event ) if event.kind() == 1));

        // let sub: Subscription = serde_json::from_str(r#"["sub_id1", {}, {}]"#)?;
        // assert_eq!(sub.id, "sub_id1");
        // assert_eq!(sub.filters.len(), 2);

        // req
        let msg: IncomingMessage = serde_json::from_str(r#"["REQ", "sub_id1", {}]"#)?;
        assert!(matches!(msg, IncomingMessage::Req(sub) if sub.id == "sub_id1"));
        let msg = serde_json::from_str::<IncomingMessage>(r#"["REQ", "sub_id1", ""]"#);
        assert!(msg.is_err());
        let msg = serde_json::from_str::<IncomingMessage>(r#"["REQ", "sub_id1"]"#);
        assert!(msg.is_ok());

        // unknown
        let msg: IncomingMessage = serde_json::from_str(r#"["REQ1", "sub_id1", {}]"#)?;
        assert!(matches!(msg, IncomingMessage::Unknown(ref cmd, ref _val) if cmd == "REQ1"));

        // auth
        let msg: IncomingMessage = serde_json::from_str(
            r#"["AUTH", {
    "content": "Good morning everyone 😃",
    "created_at": 1680690006,
    "id": "332747c0fab8a1a92def4b0937e177be6df4382ce6dd7724f86dc4710b7d4d7d",
    "kind": 1,
    "pubkey": "7abf57d516b1ff7308ca3bd5650ea6a4674d469c7c5057b1d005fb13d218bfef",
    "sig": "ef4ff4f69ac387239eb1401fb07d7a44a5d5d57127e0dc3466a0403cf7d5486b668608ebfcbe9ff1f8d3b5d710545999fe08ee767284ec0b474e4cf92537678f",
    "tags": [["t", "nostr"], ["t", ""], ["expiration", "1"], ["delegation", "8e0d3d3eb2881ec137a11debe736a9086715a8c8beeeda615780064d68bc25dd"]]
  }]"#,
        )?;
        assert!(matches!(msg, IncomingMessage::Auth( ref event ) if event.kind() == 1));

        // count
        let msg: IncomingMessage = serde_json::from_str(r#"["COUNT", "sub_id1", {}]"#)?;
        assert!(matches!(msg, IncomingMessage::Count(sub) if sub.id == "sub_id1"));

        Ok(())
    }

    #[test]
    fn se_outgoing_message() -> Result<()> {
        let msg = OutgoingMessage::notice("hello");
        let json = msg.to_string();
        assert_eq!(json, r#"["NOTICE","hello"]"#);
        let msg = OutgoingMessage::event("id", r#"{"id":"1"}"#);
        let json = msg.to_string();
        assert_eq!(json, r#"["EVENT","id",{"id":"1"}]"#);
        let msg = OutgoingMessage::eose("hello");
        let json = msg.to_string();
        assert_eq!(json, r#"["EOSE","hello"]"#);

        let msg = OutgoingMessage::closed("1", "hello");
        let json = msg.to_string();
        assert_eq!(json, r#"["CLOSED","1","hello"]"#);

        // let event = Event::default();
        // let msg = OutgoingMessage("id".to_owned(), Some(event));
        // let json = msg.to_string();
        // assert!(json.starts_with(r#"["EVENT","id",{"#));
        Ok(())
    }

    #[test]
    fn validate() -> Result<()> {
        let msg: IncomingMessage = serde_json::from_str(
            r#"["EVENT", {
            "content": "Good morning everyone 😃",
            "created_at": 1680690006,
            "id": "332747c0fab8a1a92def4b0937e177be6df4382ce6dd7724f86dc4710b7d4d7d",
            "kind": 1,
            "pubkey": "7abf57d516b1ff7308ca3bd5650ea6a4674d469c7c5057b1d005fb13d218bfef",
            "sig": "ef4ff4f69ac387239eb1401fb07d7a44a5d5d57127e0dc3466a0403cf7d5486b668608ebfcbe9ff1f8d3b5d710545999fe08ee767284ec0b474e4cf92537678f",
            "tags": [["t", "nostr"], ["expiration", "1"], ["delegation", "8e0d3d3eb2881ec137a11debe736a9086715a8c8beeeda615780064d68bc25dd"]]
          }]"#,
        )?;
        let msg = ClientMessage::new(1, "text".to_string(), msg);
        assert!(msg.validate_nip70().is_ok());

        let msg: IncomingMessage = serde_json::from_str(
            r#"["EVENT", {
            "content": "Good morning everyone 😃",
            "created_at": 1680690006,
            "id": "332747c0fab8a1a92def4b0937e177be6df4382ce6dd7724f86dc4710b7d4d7d",
            "kind": 1,
            "pubkey": "7abf57d516b1ff7308ca3bd5650ea6a4674d469c7c5057b1d005fb13d218bfef",
            "sig": "ef4ff4f69ac387239eb1401fb07d7a44a5d5d57127e0dc3466a0403cf7d5486b668608ebfcbe9ff1f8d3b5d710545999fe08ee767284ec0b474e4cf92537678f",
            "tags": [["t", "nostr"], ["-"], ["expiration", "1"], ["delegation", "8e0d3d3eb2881ec137a11debe736a9086715a8c8beeeda615780064d68bc25dd"]]
          }]"#,
        )?;
        let msg = ClientMessage::new(1, "text".to_string(), msg);
        assert!(msg.validate_nip70().is_err());

        let msg: IncomingMessage = serde_json::from_str(r#"["REQ", "sub_id1", {}]"#)?;
        let mut msg = ClientMessage::new(1, "text".to_string(), msg);
        let mut limitation = Limitation::default();
        limitation.max_limit = 300;

        msg.validate(&limitation).unwrap();
        assert!(
            matches!(msg.msg, IncomingMessage::Req(sub) if sub.filters.get(0).unwrap().limit.unwrap() == 300)
        );

        let msg: IncomingMessage = serde_json::from_str(r#"["REQ", "sub_id1", {"limit": 400}]"#)?;
        let mut msg = ClientMessage::new(1, "text".to_string(), msg);
        msg.validate(&limitation).unwrap();
        assert!(
            matches!(msg.msg, IncomingMessage::Req(sub) if sub.filters.get(0).unwrap().limit.unwrap() == 300)
        );

        let msg: IncomingMessage = serde_json::from_str(r#"["REQ", "sub_id1", {"limit": 200}]"#)?;
        let mut msg = ClientMessage::new(1, "text".to_string(), msg);
        msg.validate(&limitation).unwrap();
        assert!(
            matches!(msg.msg, IncomingMessage::Req(sub) if sub.filters.get(0).unwrap().limit.unwrap() == 200)
        );

        for limit in [0, 100, 400, u64::MAX] {
            let text = json!([NEG_OPEN, "sub_id1", {"limit": limit}, "61"]).to_string();
            let msg = serde_json::from_str(&text)?;
            let mut msg = ClientMessage::new(1, text, msg);
            assert_eq!(
                msg.validate(&limitation).unwrap_err().to_string(),
                "invalid: limit is not supported"
            );
        }

        let msg: IncomingMessage = serde_json::from_str(&format!(
            r#"["NEG-OPEN", "{}", {{}}, "61"]"#,
            "x".repeat(101)
        ))?;
        let mut msg = ClientMessage::new(1, "text".to_string(), msg);
        let err = msg.validate(&limitation).unwrap_err();
        assert!(err.to_string().contains("max_subid_length"), "{err}");

        Ok(())
    }

    #[test]
    fn de_neg_open() -> Result<()> {
        let msg: IncomingMessage =
            serde_json::from_str(r#"["NEG-OPEN", "sync", {"kinds": [1]}, "61"]"#)?;
        assert!(matches!(
            &msg,
            IncomingMessage::NegOpen(open)
                if open.id == "sync" && open.filter.kinds.contains(&1) && open.message == "61"
        ));
        assert_eq!(msg.command(), "NEG-OPEN");
        assert_eq!(msg.known_command(), Some("NEG-OPEN"));

        for text in [
            r#"["NEG-OPEN"]"#,
            r#"["NEG-OPEN", "sync"]"#,
            r#"["NEG-OPEN", "sync", {}]"#,
            r#"["NEG-OPEN", "sync", {"kinds": "invalid"}, "61"]"#,
            r#"["NEG-OPEN", "sync", {}, 61]"#,
            r#"["NEG-OPEN", "sync", {}, "61", "extra"]"#,
        ] {
            assert!(
                serde_json::from_str::<IncomingMessage>(text).is_err(),
                "{text}"
            );
        }

        let msg: IncomingMessage = serde_json::from_str(r#"["NEG-MSG", "sync", "61"]"#)?;
        assert!(
            matches!(&msg, IncomingMessage::NegMsg(id, message) if id == "sync" && message == "61")
        );
        assert_eq!(msg.known_command(), Some("NEG-MSG"));
        let msg: IncomingMessage = serde_json::from_str(r#"["NEG-CLOSE", "sync"]"#)?;
        assert!(matches!(&msg, IncomingMessage::NegClose(id) if id == "sync"));
        assert_eq!(msg.known_command(), Some("NEG-CLOSE"));
        for text in [
            r#"["NEG-MSG","sync"]"#,
            r#"["NEG-MSG","sync",123]"#,
            r#"["NEG-MSG",123,"61"]"#,
            r#"["NEG-MSG","sync","61",0]"#,
            r#"["NEG-CLOSE"]"#,
            r#"["NEG-CLOSE",123]"#,
            r#"["NEG-CLOSE","sync",0]"#,
        ] {
            assert!(
                serde_json::from_str::<IncomingMessage>(text).is_err(),
                "{text}"
            );
        }
        Ok(())
    }
}
