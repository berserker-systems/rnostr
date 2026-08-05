# Rnostr

A high-performance and scalable [nostr](https://github.com/nostr-protocol/nostr) relay written in Rust.

## Features

- [Most NIPs support](#nips)
- Easy to use, no third-party service dependencies
- High performance, Events is stored in [LMDB](https://github.com/LMDB/lmdb), Inspired by [strfry](https://github.com/hoytech/strfry)
- Most configurations can be hot reloaded
- Scalability, can be used as a library to [create custom relays](./relay/README.md)

### [NIPs](https://github.com/nostr-protocol/nips)

- [x] NIP-01: Basic protocol flow description
- [x] NIP-02: Contact list and petnames
- [x] NIP-04: Encrypted Direct Message
- [x] NIP-09: Event deletion
- [x] NIP-11: Relay information document
- [x] NIP-12: Generic tag queries
- [ ] NIP-13: Proof of Work
- [x] NIP-15: End of Stored Events Notice
- [x] NIP-16: Event Treatment
- [x] NIP-20: Command Results
- [x] NIP-22: Event `created_at` Limits
- [x] NIP-25: Reactions
- [x] NIP-26: Delegated Event Signing
- [x] NIP-28: Public Chat
- [x] NIP-33: Parameterized Replaceable Events
- [x] NIP-40: Expiration Timestamp
- [x] NIP-42: Authentication of clients to relays
- [x] NIP-45: Counting results. [experimental](#count)
- [x] NIP-50: Keywords filter. [experimental](#search)
- [x] NIP-70: Protected Events
- [x] NIP-77: Negentropy syncing. [experimental](#negentropy)

### Extensions

The library [nostr-relay](./relay/) implements a simple extension mechanism to intercept user messages for custom processing. rnostr is built on top of [nostr-relay](./relay/) and implements several simple extensions.
All extensions support configuration in the [config file](./rnostr.example.toml).

[Custom relay and extensions](./relay/).

#### Metrics

Provide metrics url for [prometheus](https://prometheus.io/) scrape

#### Auth

[NIP-42](https://nips.be/42) Authentication, ip, auth pubkey and event pubkey whitelist blacklist

See [allowlist sync](#allowlist-sync) for keeping the auth whitelists in sync
with a NIP-34 repo announcement.

#### Rate limiter

Limit event write frequency.

#### Count

[NIP-45](https://nips.be/45) count results.
When the query results are too large (millions) will trigger a slow query. `setting.data.db_query_timeout`.

#### Search

[NIP-50](https://nips.be/50) Keywords filter. [nostr-db](./db/) implement a simple exact match pattern, case-insensitive, time-sorted full-text search. No performance optimization for multi-word queries, so it's experimental.

It reduces write concurrency and makes space usage significantly larger. So it is suitable for use in private or paid relay.

Now we only index the content of `kind: 1` note event.

#### Negentropy

[NIP-77](https://nips.be/77) set reconciliation, letting a client and the relay
work out which events each side is missing without transferring them all.

`NEG-OPEN` snapshots the `(created_at, id)` pairs matching its filter, so the
cost of a reconciliation is set by how many events the filter matches, not by
their size. The snapshot is taken once when the reconciliation opens and is not
updated by events written afterwards; open a new one to pick those up.

`NEG-OPEN` is a filter query like `REQ`, so it obeys the same `[auth.req]`
permission — on an authenticated relay a client must complete NIP-42 before it
can reconcile.

Because the whole matched set is held in memory for the duration of a
reconciliation (roughly 40 bytes per event), `max_records` caps how large a set
one `NEG-OPEN` may cover; a filter matching more is refused with `blocked:`
rather than reconciled against a truncated set. `max_sessions` caps how many
reconciliations one connection may keep open, and `idle_timeout` drops those
that go quiet — including on a connection that has stopped sending anything at
all, which is the case that actually pins memory.

Those two only bound a single connection, so their product is what one client
can hold: 8 MiB at the defaults. `max_total_records` bounds the relay instead,
across every connection, and refuses a `NEG-OPEN` that would exceed it.

`frame_size_limit` bounds the size of a single response, which `max_records`
does not: a client whose set is empty opens with a 5 byte message that asks for
every matching id, so with splitting disabled the relay would answer in one
frame of roughly 64 bytes of hex per event. The default splits responses across
rounds instead; lowering it costs extra round trips.

## Usage

### Prepare source and config

```shell

git clone https://github.com/rnostr/rnostr.git
cd rnostr
mkdir config
cp ./rnostr.example.toml ./config/rnostr.toml

```

Edit the `./config/rnostr.toml`, remember to modify network.host to `0.0.0.0` for public access.

### Build and run

```shell

# Build
cargo build --release

# Show help
./target/release/rnostr relay --help

# Run with config hot reload
./target/release/rnostr relay -c ./config/rnostr.toml --watch

```

### Docker

```shell

# Create data dir
mkdir ./data

docker run -it --rm -p 8080:8080 \
  --user=$(id -u) \
  -v $(pwd)/data:/rnostr/data \
  -v $(pwd)/config:/rnostr/config \
  --name rnostr rnostr/rnostr:latest

```

Build by self

```shell

docker build . -t rnostr/rnostr

# Build in China need to configure the mirror.
docker build . -t rnostr/rnostr --build-arg BASE=mirror_cn

```

See docker compose [example](./docker-compose.yml)

### Allowlist sync

`allowlist-sync` is a separate binary that keeps the `[auth]` pubkey whitelists
in `rnostr.toml` in sync with a [NIP-34](https://nips.be/34) kind-30617 repo
announcement. The allowed set is the announcement author plus its `maintainers`
tag, unioned with any local `--extra-pubkey` operator keys. It rewrites the
config atomically, so run the relay with `--watch` to pick up changes without a
restart.

```shell

cargo build --release
./target/release/allowlist-sync --help

# One-shot: fetch, apply, exit. Exits non-zero if no announcement is found.
./target/release/allowlist-sync \
    --authority npub1... \
    --identifier my-repo \
    --relay wss://relay.example.com \
    --config ./config/rnostr.toml \
    --once

```

Every flag also has an environment variable. See the annotated
[allowlist-sync.example.env](./allowlist-sync.example.env) for the full list
with defaults and deployment caveats, and
[allowlist-sync.example.service](./allowlist-sync.example.service) for a
systemd unit that uses it.

### Commands

rnostr provides other commands such as import and export.

```shell

./target/release/rnostr --help

# Usage: rnostr <COMMAND>

# Commands:
#   import  Import data from jsonl file
#   export  Export data to jsonl file
#   bench   Benchmark filter
#   relay   Start nostr relay server
#   delete  Delete data by filter
#   help    Print this message or the help of the given subcommand(s)

# Options:
#   -h, --help     Print help
#   -V, --version  Print version

```
