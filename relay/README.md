# Nostr relay

A high-performance and scalable [nostr](https://github.com/nostr-protocol/nostr) relay library.

## Usage

```shell

cargo add nostr-relay actix-web tracing-subscriber

```

See [demo](./examples/demo.rs)

### Custom extensions

See [extensions demo](../extensions/examples/demo.rs)

Return `msg.reject(reason)` to refuse a request. The dispatcher formats the error
and closes any associated reconciliation. `Stop(reply)` and `Ignore` mean the
request was handled, including asynchronous work; they do not signal rejection.
`Extensions::call_message` emits handled replies and returns only requests that
still need the relay's core handler.

Version 0.5 adds typed `IncomingMessage::NegMsg` and `NegClose` variants and
`ExtensionMessageResult::Reject`. Update exhaustive matches when upgrading;
`Extensions::call_message` now returns `Option<ClientMessage>`.
