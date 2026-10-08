# logos-zcash-node-module

`zcash_node_module`: the lightwalletd servers a Zcash wallet talks to, per network. It keeps
the server list and the socks5h proxy, answers a route table for each kind of call, and polls
every enabled server's health over Tor. With no proxy there is no route: it fails closed.

## Presets

| Preset | Mainnet | Testnet |
|---|---|---|
| `two-operators` (default) | zec.rocks and Stardust, one host each | testnet.zec.rocks |
| `single` | zec.rocks | testnet.zec.rocks |
| `custom` | your list (`set_servers`, https only) | your list |

The other zec.rocks and Stardust hosts stay in the list, disabled, as failover candidates.

## Routes

`route_table(network)` gives the wallet core one list per call class: `sync`, `details`,
`taddr`, `broadcast`, `mempool` and `tip`, plus the proxy and `crossCheck`, true when a second
operator is enabled. Each route is `{ id, url, operator }`.

## Callers

Only `zcash_wallet_backend` may change the list, the preset or the proxy, or clear a suspect
server. The backend and `zcash_wallet_core_module` may read routes and report a mismatch,
which marks a server suspect until the backend clears it. Events: `server_health_changed`,
`routes_changed`, `server_suspect`.

`MAINNET_NU7_OVERRIDE` in `rust-lib/src/network.rs` must match the wallet core's.

```bash
cd rust-lib && cargo test --no-default-features
```
