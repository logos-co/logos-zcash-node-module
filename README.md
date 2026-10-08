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

## Regtest (test harnesses)

A `regtest.json` in the instance persistence directory adds a local `regtest` network. It
holds upgrade heights in the wallet core's format, e.g.
`{"overwinter":1,"sapling":1,"blossom":1,"heartwood":1,"canopy":1,"nu5":1,"nu6":1,"nu6_1":1,"nu6_2":1,"nu6_3":300,"nu7":null}`.
Regtest has no presets and starts with no servers and no proxy. It alone takes
`http://127.0.0.1:PORT` servers and the proxy `direct`: plain gRPC to that loopback
lightwalletd, without Tor.

## Callers

Only `zcash_wallet_backend` may change the list, the preset or the proxy, or clear a suspect
server. The backend and `zcash_wallet_core_module` may read routes and report a mismatch,
which marks a server suspect until the backend clears it. Events: `server_health_changed`,
`routes_changed`, `server_suspect`.

`MAINNET_NU7_OVERRIDE` in `rust-lib/src/network.rs` must match the wallet core's.

```bash
cd rust-lib && cargo test --no-default-features
```
