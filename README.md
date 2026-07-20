# Rnostr

A high-performance and scalable [nostr](https://github.com/nostr-protocol/nostr) relay written in Rust.

## Features

- [Most NIPs support](#nips)
- Easy to use, no third-party service dependencies
- High performance, Events is stored in [LMDB](https://github.com/LMDB/lmdb), Inspired by [strfry](https://github.com/hoytech/strfry)
- Configuration reload with `--watch`; auth settings require a restart
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

### Extensions

The library [nostr-relay](./relay/) implements a simple extension mechanism to intercept user messages for custom processing. rnostr is built on top of [nostr-relay](./relay/) and implements several simple extensions.
All extensions support configuration in the [config file](./rnostr.example.toml).

[Custom relay and extensions](./relay/).

#### Metrics

Provide metrics url for [prometheus](https://prometheus.io/) scrape

#### Auth

[NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md) Authentication, ip, auth pubkey and event pubkey whitelist blacklist

See [allowlist sync](#allowlist-sync) for membership from a private shareholder registry.

Upgrade note: unknown keys under `[auth]`, `[auth.req]` and `[auth.event]` now
reject startup. Remove obsolete options and fix misspellings.

Auth configuration requires a restart to change. Registry membership updates
are applied separately. An empty whitelist denies everyone;
an empty blacklist blocks nobody.

#### Rate limiter

Limit event write frequency.

#### Count

[NIP-45](https://github.com/nostr-protocol/nips/blob/master/45.md) count results.
When the query results are too large (millions) will trigger a slow query. `setting.data.db_query_timeout`.

#### Search

[NIP-50](https://github.com/nostr-protocol/nips/blob/master/50.md) Keywords filter. [nostr-db](./db/) implement a simple exact match pattern, case-insensitive, time-sorted full-text search. No performance optimization for multi-word queries, so it's experimental.

It reduces write concurrency and makes space usage significantly larger. So it is suitable for use in private or paid relay.

Now we only index the content of `kind: 1` note event.

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

With `--watch`, the config is reloaded once the file has been unchanged for 250 ms;
a file with no settings is skipped. To update it safely, write the new config to a
temporary file in the same directory and rename it over the watched file: a writer
that pauses mid-file for longer than that can get a partial config applied.

Japanese and Korean search tokenization are enabled by default. Their dictionaries
are downloaded by Lindera build scripts during compilation. To build without
these downloads, while keeping search and the other relay extensions enabled:

```shell
cargo build --release --no-default-features
```

Enable either language separately with `--features search-japanese` or
`--features search-korean`; those features require the corresponding dictionary
downloads. `--offline` only controls Cargo itself, so it does not prevent build
scripts from downloading dictionaries when these features are enabled.

When building or testing the whole workspace, also use `--no-default-features`
to prevent benchmark defaults from enabling the dictionaries.

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

`allowlist-sync` fetches encrypted kind-30617 snapshots using a dedicated
recipient key. Register its public key as `nostr.allowlist_sync_pubkey` in
`shareholder-governance-registry`.

Create a dedicated `allowlist-sync` user with primary group `rnostr-policy`,
and add the relay user to that group. Keep the recipient nsec owned by
`allowlist-sync`, mode 0600. The policy is mode 0640; the relay needs read access
only. Use one writer per policy. File symlinks are rejected.

Configure `/etc/rnostr/allowlist-sync.env` using the [example](./allowlist-sync.example.env).
Private sources must authenticate the sync identity; use `--public-relay` for
sources serving snapshots without auth.

```sh
cargo build --release -p allowlist-sync
sudo install -Dm755 target/release/allowlist-sync /opt/rnostr/allowlist-sync
sudo install -m644 allowlist-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now allowlist-sync
```

On first installation, wait for `/var/lib/allowlist-sync/allowlist.json` to be
created from a valid snapshot before starting the relay with registry auth:

```toml
[auth]
enabled = true
registry_file = "/var/lib/allowlist-sync/allowlist.json"
```

The operator, sync recipient, members and extras are allowed. Reads require
NIP-42 auth; writes check the event author. Static restrictions also apply.
File notifications apply policy changes immediately, independently of `--watch`,
with a recovery poll every 60 seconds. Missed notifications may delay updates until
that poll. Revoked readers receive no further events. Invalid files retain the last
valid policy. Startup fails if the initial policy or watcher cannot be loaded.
The sidecar alone enforces event version ordering.
Changing auth configuration requires a restart; other extension settings can reload
with `--watch`. Auth edits are retained on disk but ignored until restart; base and
other extension changes in the same edit still apply.

Each source uses one live connection, including periodic catch-up. Verified updates
apply as they arrive. Every source must send EOSE; `--relay` also requires successful
NIP-42 auth and a fresh request.
Malformed member key strings are skipped with a warning; decryption and payload
schema errors reject the snapshot. Snapshots more than 15 minutes ahead of the
local clock are rejected. EOSE does not prove the source has the latest snapshot.
Extras can change offline at startup without resetting the registry version.

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
