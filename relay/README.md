# Nostr relay

A high-performance and scalable [nostr](https://github.com/nostr-protocol/nostr) relay library.

## Usage

```shell
cargo add nostr-relay actix-web tracing-subscriber
```

See [demo](./examples/demo.rs) and [custom extensions](../extensions/examples/demo.rs).

Existing `Extension::setting` callbacks and `App::add_extension` remain supported.
Use `Auth::from_setting(&app.setting)?` before `add_extension` to return startup
errors; `add_extension(Auth::new())` panics on invalid auth settings.
Auth settings require a restart; other extensions reload through `setting`.
Callbacks rebuild their NIP-11 metadata on reload.
