# logos-zcash-node-module

`zcash_node_module`: the lightwalletd servers a Zcash wallet talks to, per network. It keeps
the server list and the proxy, answers a route table for each kind of call, and polls every
enabled server's health over Tor. The proxy is the Tor that comes with Logos
([`tor_module`](https://github.com/logos-co/logos-tor-module)) unless the user picks their
own. Servers on the user's own network are reached directly, and the user may set any https
server to skip Tor. With no proxy only those servers have a route: everything else fails
closed.

## Presets

| Preset | Mainnet | Testnet |
|---|---|---|
| `two-operators` (default) | zec.rocks and Stardust, one host each | testnet.zec.rocks |
| `single` | zec.rocks | testnet.zec.rocks |
| `custom` | your list (`set_servers`) | your list |

The other zec.rocks and Stardust hosts stay in the list, disabled, as failover candidates.
A preset host a later release drops leaves saved lists when they load; the user's own
servers stay.

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

## The built-in Tor

The proxy setting `tor`, the default, is `tor_module`, a dependency the host loads with this
module. A thread asks it for its status every 2 s until Tor is ready, then every 30 s.
- The route table and the health poller dial its SOCKS port, which changes each time it
  loads. Until the port is known, servers that need Tor have no route
  (`the built-in Tor is not running`), and LAN servers are still reached directly.
- `server_health` carries its `{ state, progress, detail }` as `tor` while the network uses
  it: `connecting`, `ready`, `blocked` or `failed`.
- The poller looks again when Tor becomes ready, since checks made while it joined timed out.
- The user's own Tor is set as `socks5h://host:port`, such as a system Tor at
  `socks5h://127.0.0.1:9050` or Tor Browser at `socks5h://127.0.0.1:9150`.

Settings saved before the built-in Tor (file version 1) seeded `socks5h://127.0.0.1:9050`.
Those move to `tor` once, when the file loads; a proxy the user chose stays.

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

```bash
cd rust-lib && cargo test --no-default-features
```
