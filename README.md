Command-line tool & Rust crate that lets you **encrypt descriptors (or arbitrary
data)** with a set of **public** keys (or xpubs) and later decrypt when **at least
one** of them is physically present—either via a local file containing the key or
automatically fetched from a signing device.
Devices are **not mandatory**; you can use the tool completely off-device.

## CLI

### Build

To build the cli without device support:

```
cargo build --bin beb --release --no-default-features --features="cli"
```

or with devices support:

```
cargo build --bin beb --release --no-default-features --features="cli,devices"
```

Note: if a signing device supported by
[`async-hwi`](https://github.com/wizardsardine/async-hwi) is connected and unlocked,
the CLI will automatically try to fetch a set of xpubs from it.


### Usage:

```
$ beb --help
Usage: beb <COMMAND>

Commands:
  encrypt  Encrypt some descriptor
  decrypt  Decrypt an encrypted descriptor with a given xpub
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```
```
$ beb encrypt --help
Encrypt some descriptor

Usage: beb encrypt [OPTIONS]

Options:
  -f, --file <FILE>      Input file containing the descriptor
  -o, --output <OUTPUT>  Optional output to encrypted descriptor
  -h, --help             Print help

```
```
$ beb decrypt --help
Decrypt an encrypted descriptor with a given xpub

Usage: beb decrypt [OPTIONS]

Options:
  -f, --file <FILE>      Input file to be decrypted
  -k, --key <KEY>        The key containing a xpub
  -o, --output <OUTPUT>  Optional decrypted descriptor
  -h, --help             Print help

```
## Library usage

### Encryption
```rust
let descriptor = Descriptor::<DescriptorPublicKey>::from_str("<descriptor
string>").unwrap();
let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
let encrypted_blob = backp.encrypt().unwrap();
```

### Decryption
```rust

let encrypted_blob: Vec<u8> = vec![/* your encrypted descriptor*/];
let key = DescriptorPublicKey::from_str("<your xpub>").unwrap();
let descriptor = EncryptedBackup::new()
    .set_encrypted_payload(&encrypted_blob)
    .unwrap()
    .set_keys(vec![key])
    .decrypt()
    .unwrap();
```

## WASM support

This carate can be build against these wasm targets:
 - `wasm32-unknown-unknown`
 - `wasm32-wasip1`

Note: `rand` feature must be disabled for these target:

```
cargo build --target wasm32-unknown-unknown --no-default-features --features "miniscript_latest"
```

## Features

| Feature flag        | Default | Description                                           |
|---------------------|---------|-------------------------------------------------------|
| `miniscript_12_0`   | –       | Compile against `miniscript` v0.12.0                  |
| `miniscript_12_3_5` | –       | Compile against `miniscript` v0.12.3.5                |
| `miniscript_latest` | ✓       | Alias for `miniscript_12_3_5`                         |
| `devices`           | -       | Enable automatic enumeration of signing devices.      |
| `tokio`             | ✓       | Pull in `tokio` runtime used by the `devices`feature. |
| `rand`              | ✓       | Enable random nonce generation                        |

Note: the `devices` feature uses
[`async-hwi`](https://github.com/wizardsardine/async-hwi) crate, see
[there](https://github.com/wizardsardine/async-hwi) for supported signing devices.

## Regenerating test vectors

The crate ships JSON test vectors under `test_vectors/` that are checked
against the current implementation by the standard test suite. Whenever
the spec or the crypto changes (cipher, tag strings, key width, TYPE
encoding, …), the `expected` fields in those JSON files must be
recomputed.

Four `#[ignore]` helpers are provided for that purpose; each rewrites a
single vector file in place from the current code:

| Test                                            | File rewritten                              |
|-------------------------------------------------|---------------------------------------------|
| `descriptor::tests::regenerate_vectors`         | `test_vectors/keys_types.json`              |
| `ll::encryption_secret::regenerate_vectors`     | `test_vectors/encryption_secret.json`       |
| `ll::encryption_vectors::regenerate_vectors`    | `test_vectors/chacha20poly1305_encryption.json` |
| `ll::encrypted_backup::regenerate_vectors`      | `test_vectors/encrypted_backup.json`        |

Run them all at once:

```
cargo test regenerate_vectors -- --ignored
```

They are gated with `#[ignore]` so `cargo test` never touches the
committed vectors. After running, inspect `git diff test_vectors/` and
only commit the change when it reflects an intentional spec update.
