# azkv

A small Azure Key Vault TUI (`azkv`) and CLI (`azkvctl`).

It reads existing Azure CLI profiles and their MSAL token cache.

## Requirements

- An existing Azure CLI login (`az login`)

## Build

```sh
cargo build --release
```

The binaries are in `target/release/`.

## TUI

```sh
azkv
azkv --profile test
```

Basic keys:

| Key | Action |
| --- | --- |
| `↑/↓`, `tab` | Move |
| `enter` | Open vault / focus secrets |
| `a` | Add secret |
| `e` | Edit secret |
| `d` | Duplicate secret |
| `D` | Delete secret |
| `C` | Copy secret or vault |
| `i` | Vault info |
| `P` | Configure proxy |
| `r` | Refresh |
| `q` | Quit |

## CLI

```sh
azkvctl profiles
azkvctl vaults
azkvctl secrets my-vault
azkvctl get my-vault my-secret
printf '%s' 'value' | azkvctl set my-vault my-secret
```

Run `azkvctl --help` for all commands.

## Proxy

Both binaries accept `--proxy` and `--no-proxy`, or the `AZKV_PROXY` and
`AZKV_NO_PROXY` environment variables. They also honour the usual proxy
environment variables.

## Tests

```sh
cargo test
```
