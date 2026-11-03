# logos-zcash-node-module

`zcash_node_module`: the lightwalletd servers a Zcash wallet talks to, per network. It keeps
the server list, the proxy and what Tor is used for, answers a route table for each kind of
call, and checks the enabled servers of the network a wallet is open on every 60 s. The backend says which
network with `watch(network)`, and `watch("")` when the wallet closes; until it does, every
network's servers are checked. The proxy is the Tor that comes with Logos
([`tor_module`](https://github.com/logos-co/logos-tor-module)), reached over IPC, unless the
user picks their own. Servers on the user's own network are reached directly, and the user may set any https
server to skip Tor. With no proxy only those servers have a route: everything else fails
closed.

## Presets

| Preset | Mainnet | Testnet |
|---|---|---|
| `two-operators` (default) | zec.rocks and Stardust, one host each | testnet.zec.rocks and ZombieCash |
| `single` | zec.rocks | testnet.zec.rocks |
| `custom` | your list (`set_servers`) | your list |

The default enables the first host of the first two operators. The other hosts stay in the
list, switched off: zec.rocks's and Stardust's other regions and Cake Wallet's server on
mainnet, and ZombieCash's onion service on testnet.

A preset host a later release drops leaves saved lists when they load; the user's own
servers stay. A host it adds is offered once: a list still on its preset follows it, keeping
the user's Tor choices, and a `custom` list gets the host switched off.

## Use Tor for

One setting for every network, `set_tor_use(mode)`:

| Mode | Direct | Through Tor |
|---|---|---|
| `all` | Servers on the user's network, and https servers set to skip Tor | Everything else |
| `identifying` (default) | `sync` and `tip`: compact blocks, tree states, subtree roots, tips | `details`, `taddr`, `broadcast`, `mempool`: anything that names the wallet's transactions, addresses or sends, and the health checks |
| `none` | Every https server | Nothing: onion services are off, and tor_module is never asked |

- The route table carries `torUse` and `directFor`, the classes the wallet core dials directly
  (`["sync","tip"]` in `identifying`). An older core ignores `directFor` and keeps every call on
  Tor. In `none`, `direct` lists every enabled https server and the proxy is `direct`.
- An onion service goes through Tor in every mode, and a server on the user's network is
  direct in every mode. The per-server Tor switch applies to `all` only.
- `identifying` and `all` need a Tor: setting either gives each network without one the
  built-in Tor. Which Tor stays per network (`set_proxy`).
- `tor_use()` and `server_health` answer `{ torUse, torUseChosen, torUseMigrated }`.
  `torUseChosen` turns true at the first `set_tor_use`; until then the app asks.
- Refused while a wallet is open: the backend reports it with `set_wallet_open(network, open)`.

A fresh file starts at `identifying`. A file from before the setting (version 1 or 2) keeps its
routing: `all` if any network has a Tor proxy, else `none`, with `torUseMigrated` true and
`torUseChosen` false, so the app asks once with today's routing preselected. An older build
sets a version 3 file aside as corrupt and seeds the presets.

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

LAN servers are always dialled directly, since Tor cannot reach them. With `all`, Tor is
chosen per server:
- a server with `"direct": true` is reached without Tor;
- `direct` is refused for an onion service, which is reached through Tor only;
- the choice survives re-applying a preset;
- the route table lists these servers in `direct`, for the wallet core.

The proxy `direct` means none: with `all`, only LAN servers and the ones set to `direct` are
then reached, and with `identifying` only LAN servers.

## The built-in Tor

The proxy setting `tor`, the default, is `tor_module`, a dependency the host loads with this
module, reached over Logos IPC: no SOCKS port is involved. Each gRPC call becomes one
HTTP/2 request to tor_module, which does the TLS, and its answer comes back over IPC. Calls
on one client share a circuit and an HTTP/2 connection, as they would one connection
through a SOCKS proxy; another client gets its own.
- The route table names it as the proxy `tor`, so the wallet core reaches it over IPC too.
  A request starts Tor if it has not, so servers keep their routes while Tor joins.
- While the watched network uses it, a thread asks it for its status every 2 s until Tor is
  ready, then every 30 s, and `server_health` carries its `{ state, progress, detail }` as `tor`:
  `connecting`, `ready`, `blocked` or `failed`. With every network on the user's own Tor,
  or on none, with Tor used for nothing, or with no wallet open, nothing is asked and the
  built-in Tor never connects.
- The poller looks again when Tor becomes ready, since checks made while it joined timed out.
- The user's own Tor is set as `socks5h://host:port`, such as a system Tor at
  `socks5h://127.0.0.1:9050` or Tor Browser at `socks5h://127.0.0.1:9150`.

Settings saved before the built-in Tor (file version 1) seeded `socks5h://127.0.0.1:9050`.
Those move to `tor` once, when the file loads; a proxy the user chose stays.

## Routes

`route_table(network)` gives the wallet core one list per call class: `sync`, `details`,
`taddr`, `broadcast`, `mempool` and `tip`, plus the proxy, `direct`, `torUse`, `directFor` and
`crossCheck`, true when a second operator is enabled. Each route is `{ id, url, operator }`.

## Regtest (test harnesses)

A `regtest.json` in the instance persistence directory adds a local `regtest` network. It
holds upgrade heights in the wallet core's format, e.g.
`{"overwinter":1,"sapling":1,"blossom":1,"heartwood":1,"canopy":1,"nu5":1,"nu6":1,"nu6_1":1,"nu6_2":1,"nu6_3":300,"nu7":null}`.
Regtest has no presets and starts with no servers and no proxy. Its lightwalletd servers,
`http://127.0.0.1:PORT`, are on the user's network, so they need no proxy.

## Callers

Only `zcash_wallet_backend` may change the list, the preset, the proxy or what Tor is used
for, clear a suspect server, or say which network a wallet is open on or watched. The backend and `zcash_wallet_core_module`
may read routes and report a mismatch, which marks a server suspect until the backend clears
it. Events: `server_health_changed`, `routes_changed`, `server_suspect`.

```bash
cd rust-lib && cargo test --no-default-features
```
