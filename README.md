# logos-zcash-node-module

`zcash_node_module`: the lightwalletd servers a Zcash wallet talks to, per network. It keeps
the server list and the socks5h proxy, answers a route table for each kind of call, and polls
every enabled server's health over Tor. Servers on the user's own network are reached
directly, and the user may set any https server to skip Tor. With no proxy only those servers
have a route: everything else fails closed.

## Presets

| Preset | Mainnet | Testnet |
|---|---|---|
| `two-operators` (default) | zec.rocks and Stardust, one host each | testnet.zec.rocks and ours, an onion service |
| `single` | zec.rocks | testnet.zec.rocks |
| `custom` | your list (`set_servers`) | your list |

The other zec.rocks and Stardust hosts stay in the list, disabled, as failover candidates.

## Servers and Tor

A server is one of:
- `https://host:port`, port 443 when absent;
- a v3 onion service, `http://<onion>:port`;
- a server on the user's own network, `http://host:port` (port 9067, lightwalletd's, when
  absent) or `https://host:port`. That means loopback, private, CGNAT and link-local
  addresses, and `.local`, `.lan`, `.home.arpa` and `.internal` names. A name must resolve
  only to such addresses.

`set_servers` also takes a bare `host` or `host:port`: onion and LAN hosts become http, the
rest https.

LAN servers are always dialled directly, since Tor cannot reach them. Tor is chosen per
server:
- a server with `"direct": true` is reached without Tor;
- `direct` is refused for an onion service, which is reached through Tor only;
- the choice survives re-applying a preset;
- the route table lists these servers in `direct`, for the wallet core.

The proxy `direct` means none: only LAN servers and the ones set to `direct` are then
reached.

## Routes

`route_table(network)` gives the wallet core one list per call class: `sync`, `details`,
`taddr`, `broadcast`, `mempool` and `tip`, plus the proxy and `crossCheck`, true when a second
operator is enabled. Each route is `{ id, url, operator }`.

## Regtest (test harnesses)

A `regtest.json` in the instance persistence directory adds a local `regtest` network. It
holds upgrade heights in the wallet core's format, e.g.
`{"overwinter":1,"sapling":1,"blossom":1,"heartwood":1,"canopy":1,"nu5":1,"nu6":1,"nu6_1":1,"nu6_2":1,"nu6_3":300,"nu7":null}`.
Regtest has no presets and starts with no servers and no proxy. Its lightwalletd servers,
`http://127.0.0.1:PORT`, are on the user's network, so they need no proxy.

## Callers

Only `zcash_wallet_backend` may change the list, the preset or the proxy, or clear a suspect
server. The backend and `zcash_wallet_core_module` may read routes and report a mismatch,
which marks a server suspect until the backend clears it. Events: `server_health_changed`,
`routes_changed`, `server_suspect`.

`MAINNET_NU7_OVERRIDE` in `rust-lib/src/network.rs` must match the wallet core's.

```bash
cd rust-lib && cargo test --no-default-features
```
