//! The module without the SDK: server lists, proxy, route table, live health and
//! events. The glue gates callers and forwards here; replies are flat JSON strings.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::health::{self, Row, ServerHealth};
use crate::net::client::is_lan_url;
use crate::network::{networks, ZNetwork};
use crate::proxy::{self, DIRECT};
use crate::reply;
use crate::servers::{self, preset_servers, CallClass, Preset, Route, Server, Source, MAX_SERVERS};
use crate::store::{NetConfig, Store, Suspicion};

pub const NO_PROXY: &str = "no proxy is set";

/// Why `s` cannot be dialled as configured, if it cannot. A server on the user's network, or one
/// the user set to skip Tor, is reached directly; every other one needs the proxy.
fn blocked(cfg: &NetConfig, s: &Server) -> Option<&'static str> {
    match cfg.proxy.as_deref() {
        _ if is_lan_url(&s.url) || s.direct => None,
        None | Some(DIRECT) => Some(NO_PROXY),
        Some(_) => None,
    }
}

/// The enabled servers the user set to skip Tor, as the wallet core's routes list them.
fn direct_urls(cfg: &NetConfig) -> Vec<String> {
    cfg.servers.iter().filter(|s| s.enabled && s.direct).map(|s| s.url.clone()).collect()
}

pub enum Event {
    HealthChanged { network: ZNetwork, payload: String },
    RoutesChanged { network: ZNetwork },
    Suspect { network: ZNetwork, server_id: String, kind: String },
}

pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// One enabled server the poller should ask, through `proxy`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub network: ZNetwork,
    pub id: String,
    pub url: String,
    pub proxy: String,
}

pub struct Node {
    inner: Mutex<Inner>,
    path: Option<PathBuf>,
    sink: Sink,
    wake: Notify,
    local: Mutex<Option<Arc<dyn LocalStatus>>>,
}

struct Inner {
    store: Store,
    /// Live health by (network, id), with the url it was measured at.
    health: HashMap<(ZNetwork, String), (String, ServerHealth)>,
    sent_health: HashMap<ZNetwork, String>,
    sent_routes: HashMap<ZNetwork, String>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn bad_network() -> String {
    reply::err("network must be mainnet or testnet")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteTable<'a> {
    ok: bool,
    network: &'a str,
    proxy: &'a str,
    proxy_required: bool,
    cross_check: bool,
    sync: Vec<Route>,
    details: Vec<Route>,
    taddr: Vec<Route>,
    broadcast: Vec<Route>,
    mempool: Vec<Route>,
    tip: Vec<Route>,
    direct: Vec<String>,
}

impl Inner {
    fn cfg(&self, net: ZNetwork) -> &NetConfig {
        &self.store.networks[&net]
    }

    /// The health measured for `s` at its current url, if it is enabled.
    fn health_of(&self, net: ZNetwork, s: &Server) -> Option<&ServerHealth> {
        match self.health.get(&(net, s.id.clone())) {
            Some((url, h)) if s.enabled && *url == s.url => Some(h),
            _ => None,
        }
    }

    fn forget_stale_health(&mut self, net: ZNetwork) {
        let live: Vec<(String, String)> =
            self.cfg(net).servers.iter().filter(|s| s.enabled).map(|s| (s.id.clone(), s.url.clone())).collect();
        self.health.retain(|(n, id), (url, _)| *n != net || live.iter().any(|(i, u)| i == id && u == url));
    }

    /// Fail closed: only servers that can be dialled as configured are routed. Without a
    /// proxy, that leaves the servers on the user's network, which need none.
    fn route_table(&self, net: ZNetwork) -> String {
        let cfg = self.cfg(net);
        let usable = |s: &Server| {
            blocked(cfg, s).is_none()
                && !cfg.suspects.contains_key(&s.id)
                && !self.health_of(net, s).is_some_and(|h| h.incompatible)
        };
        let r = servers::routes(&cfg.servers, usable);
        if cfg.local_node {
            return self.local_route_table(net, cfg, r.broadcast);
        }
        let proxy = match cfg.proxy.as_deref() {
            Some(p) => p,
            None if !r.sync.is_empty() => DIRECT,
            None => return reply::err(NO_PROXY),
        };
        let table = RouteTable {
            ok: true,
            network: net.name(),
            proxy,
            proxy_required: cfg.proxy_required && proxy != DIRECT,
            cross_check: r.cross_check,
            sync: r.sync,
            details: r.details,
            taddr: r.taddr,
            broadcast: r.broadcast,
            mempool: r.mempool,
            tip: r.tip,
            direct: direct_urls(cfg),
        };
        serde_json::to_string(&table).unwrap_or_else(reply::err)
    }

    /// Every read from the local node, which checks the chain itself, so nothing is cross-checked.
    /// Broadcasts stay on the servers, even when none is usable right now; only a user with no
    /// server enabled at all has the node send them itself.
    fn local_route_table(&self, net: ZNetwork, cfg: &NetConfig, remote: Vec<Route>) -> String {
        let local = vec![Route { id: "local".into(), url: LOCAL_NODE_URL.into(), operator: "local".into() }];
        let senders: Vec<&Server> = cfg.servers.iter().filter(|s| s.enabled && s.classes.contains(&CallClass::Broadcast)).collect();
        let (broadcast, proxy) = match cfg.proxy.as_deref() {
            _ if senders.is_empty() => (local.clone(), ""),
            Some(p) => (remote, p),
            None if senders.iter().any(|s| is_lan_url(&s.url) || s.direct) => (remote, DIRECT),
            None => return reply::err(NO_PROXY),
        };
        let table = RouteTable {
            ok: true,
            network: net.name(),
            proxy,
            proxy_required: cfg.proxy_required && !matches!(proxy, "" | DIRECT),
            cross_check: false,
            sync: local.clone(),
            details: local.clone(),
            taddr: local.clone(),
            broadcast,
            mempool: local.clone(),
            tip: local,
            direct: direct_urls(cfg),
        };
        serde_json::to_string(&table).unwrap_or_else(reply::err)
    }

    /// server_health()'s fields, without `ok`.
    fn health_value(&self, net: ZNetwork) -> Value {
        let cfg = self.cfg(net);
        let seen: Vec<(&Server, Option<&ServerHealth>, Option<&Suspicion>)> =
            cfg.servers.iter().map(|s| (s, self.health_of(net, s), cfg.suspects.get(&s.id))).collect();
        let rows: Vec<Row> = seen
            .iter()
            .map(|(s, h, sus)| Row { operator: &s.operator, enabled: s.enabled, suspect: sus.is_some(), health: *h })
            .collect();
        let servers: Vec<Value> = seen
            .iter()
            .map(|(s, h, sus)| {
                let mut v = serde_json::to_value(h.cloned().unwrap_or_default()).unwrap_or_else(|_| json!({}));
                if let Value::Object(m) = &mut v {
                    m.insert("id".into(), json!(s.id));
                    m.insert("url".into(), json!(s.url));
                    m.insert("operator".into(), json!(s.operator));
                    m.insert("label".into(), json!(s.label));
                    m.insert("enabled".into(), json!(s.enabled));
                    m.insert("suspect".into(), json!(sus.is_some()));
                    m.insert("suspectKind".into(), json!(sus.map(|x| &x.kind)));
                    m.insert("suspectHeight".into(), json!(sus.map(|x| x.height)));
                }
                v
            })
            .collect();
        json!({
            "network": net.name(),
            "overall": health::overall(net, &rows),
            "pending": rows.iter().any(|r| r.enabled && r.health.is_none()),
            "servers": servers,
        })
    }

    /// Events for whatever changed since they were last sent. Round-trip times and
    /// timestamps alone do not count as a change.
    fn changes(&mut self, net: ZNetwork) -> Vec<Event> {
        let mut events = Vec::new();
        let routes = self.route_table(net);
        if self.sent_routes.get(&net) != Some(&routes) {
            self.sent_routes.insert(net, routes);
            events.push(Event::RoutesChanged { network: net });
        }
        let value = self.health_value(net);
        let signature = signature(&value);
        if self.sent_health.get(&net) != Some(&signature) {
            self.sent_health.insert(net, signature);
            events.push(Event::HealthChanged { network: net, payload: reply::ok(value) });
        }
        events
    }
}

fn signature(health: &Value) -> String {
    let mut v = health.clone();
    if let Some(list) = v.get_mut("servers").and_then(Value::as_array_mut) {
        for s in list.iter_mut().filter_map(Value::as_object_mut) {
            s.remove("rttMs");
            s.remove("checkedAt");
        }
    }
    v.to_string()
}

fn servers_reply(net: ZNetwork, cfg: &NetConfig) -> String {
    reply::ok(json!({"network": net.name(), "preset": cfg.preset, "servers": cfg.servers,
                     "proxy": cfg.proxy, "proxyRequired": cfg.proxy_required, "localNode": cfg.local_node}))
}

/// The route the wallet core reaches the local node by, over Logos IPC.
pub const LOCAL_NODE_URL: &str = "logos://zebrad_module";

/// zebrad_module's status, when it is loaded. A trait so the pure tests can stand one in.
pub trait LocalStatus: Send + Sync {
    fn status(&self) -> Result<Value, String>;
}

impl Node {
    /// Loads `path` (or seeds the presets); `None` keeps everything in memory.
    pub fn open(path: Option<PathBuf>, sink: Sink) -> Arc<Self> {
        let store = match &path {
            Some(p) => Store::load_or_seed(p),
            None => Store::seeded(),
        };
        let mut inner = Inner { store, health: HashMap::new(), sent_health: HashMap::new(), sent_routes: HashMap::new() };
        for net in networks() {
            let _ = inner.changes(net);
        }
        Arc::new(Self { inner: Mutex::new(inner), path, sink, wake: Notify::new(), local: Mutex::new(None) })
    }

    /// Notified when the servers or the proxy change, so the poller looks at once.
    pub fn wake(&self) -> &Notify {
        &self.wake
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn emit(&self, events: Vec<Event>) {
        for e in events {
            (self.sink)(e);
        }
    }

    /// Applies `change` to a copy of the network's config, validates and saves it,
    /// then swaps it in. `change` returns the reply and any events to send first.
    fn mutate(
        &self,
        net: ZNetwork,
        poke: bool,
        change: impl FnOnce(&mut NetConfig) -> Result<(String, Vec<Event>), String>,
    ) -> String {
        let (out, events) = {
            let mut inner = self.lock();
            let mut cfg = inner.cfg(net).clone();
            let (out, mut events) = match change(&mut cfg).and_then(|r| cfg.validate(net).map(|_| r)) {
                Ok(r) => r,
                Err(e) => return reply::err(e),
            };
            let mut store = inner.store.clone();
            store.networks.insert(net, cfg);
            if let Some(p) = &self.path {
                if let Err(e) = store.save(p) {
                    return reply::err(format!("saving {}: {e}", p.display()));
                }
            }
            inner.store = store;
            inner.forget_stale_health(net);
            events.extend(inner.changes(net));
            (out, events)
        };
        if poke {
            self.wake.notify_one();
        }
        self.emit(events);
        out
    }

    pub fn servers(&self, network: &str) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        servers_reply(net, self.lock().cfg(net))
    }

    pub fn set_servers(&self, network: &str, list_json: &str) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        let list = match servers::parse_list(net, list_json) {
            Ok(l) => l,
            Err(e) => return reply::err(e),
        };
        self.mutate(net, true, |cfg| {
            cfg.replace_servers(list);
            cfg.preset = Preset::Custom;
            Ok((servers_reply(net, cfg), vec![]))
        })
    }

    /// A preset replaces the list; servers the user added stay, disabled. `custom`
    /// keeps the list as it is. Regtest has no presets.
    pub fn apply_preset(&self, network: &str, name: &str) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        if net == ZNetwork::Regtest {
            return reply::err("regtest has no presets; use set_servers");
        }
        let Some(preset) = Preset::parse(name) else {
            return reply::err("preset must be two-operators, single or custom");
        };
        self.mutate(net, true, |cfg| {
            if let Some(mut list) = preset_servers(net, preset) {
                // The user's choice of Tor for a preset server outlives the preset.
                for p in list.iter_mut() {
                    p.direct = cfg.servers.iter().any(|s| s.id == p.id && s.url == p.url && s.direct);
                }
                for s in cfg.servers.iter().filter(|s| s.source == Source::User) {
                    if list.len() < MAX_SERVERS && !list.iter().any(|p| p.id == s.id || p.url == s.url) {
                        list.push(Server { enabled: false, ..s.clone() });
                    }
                }
                cfg.replace_servers(list);
            }
            cfg.preset = preset;
            Ok((servers_reply(net, cfg), vec![]))
        })
    }

    pub fn set_proxy(&self, network: &str, config_json: &str) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        let (proxy, required) = match proxy::parse_config(config_json) {
            Ok(c) => c,
            Err(e) => return reply::err(e),
        };
        self.mutate(net, true, |cfg| {
            cfg.proxy = proxy;
            cfg.proxy_required = required;
            let out = json!({"network": net.name(), "proxy": cfg.proxy, "proxyRequired": cfg.proxy_required});
            Ok((reply::ok(out), vec![]))
        })
    }

    pub fn route_table(&self, network: &str) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        self.lock().route_table(net)
    }

    pub fn server_health(&self, network: &str) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        reply::ok(self.lock().health_value(net))
    }

    pub fn report_mismatch(&self, network: &str, server_id: &str, kind: &str, height: i64) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        if kind.trim().is_empty() || kind.chars().count() > 64 || kind.chars().any(char::is_control) {
            return reply::err("kind must be 1 to 64 printable characters");
        }
        let Ok(height) = u64::try_from(height) else { return reply::err("height must not be negative") };
        self.mutate(net, false, |cfg| {
            if cfg.server(server_id).is_none() {
                return Err(format!("unknown server {server_id}"));
            }
            cfg.suspects.insert(server_id.into(), Suspicion { kind: kind.into(), height, at: now() });
            let out = json!({"network": net.name(), "serverId": server_id, "suspect": true, "kind": kind, "height": height});
            let first = Event::Suspect { network: net, server_id: server_id.into(), kind: kind.into() };
            Ok((reply::ok(out), vec![first]))
        })
    }

    pub fn clear_suspect(&self, network: &str, server_id: &str) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        self.mutate(net, false, |cfg| {
            if cfg.server(server_id).is_none() {
                return Err(format!("unknown server {server_id}"));
            }
            let cleared = cfg.suspects.remove(server_id).is_some();
            Ok((reply::ok(json!({"network": net.name(), "serverId": server_id, "cleared": cleared})), vec![]))
        })
    }

    /// Installed by the glue when zebrad_module is a dependency.
    pub fn set_local_status(&self, s: Arc<dyn LocalStatus>) {
        *self.local.lock().unwrap() = Some(s);
    }

    pub fn set_local_node(&self, network: &str, enabled: bool) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        self.mutate(net, false, |cfg| {
            cfg.local_node = enabled;
            Ok((reply::ok(json!({"network": net.name(), "localNode": enabled})), vec![]))
        })
    }

    /// `{ ok, enabled, available, status? , error? }`: whether reads go to the local node, and
    /// whether zebrad_module runs it for `network` now.
    pub fn local_node(&self, network: &str) -> String {
        let Some(net) = ZNetwork::parse(network) else { return bad_network() };
        let enabled = self.lock().cfg(net).local_node;
        let source = self.local.lock().unwrap().clone();
        let Some(source) = source else {
            return reply::ok(json!({"enabled": enabled, "available": false, "error": "zebrad_module is not installed"}));
        };
        match source.status() {
            Ok(st) => {
                // zebrad_module may name the network as Zebra does ("Testnet").
                let on_net = st["network"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(net.name()));
                let available = st["state"] == "running" && on_net;
                reply::ok(json!({"enabled": enabled, "available": available, "status": st}))
            }
            Err(e) => reply::ok(json!({"enabled": enabled, "available": false, "error": e})),
        }
    }

    /// The enabled servers to poll, and those that cannot be dialled as configured, with why.
    /// Nothing is dialled for those: they read unreachable.
    pub fn poll_plan(&self) -> (Vec<Target>, Vec<(Target, &'static str)>) {
        let inner = self.lock();
        let (mut targets, mut skipped) = (Vec::new(), Vec::new());
        for (net, cfg) in &inner.store.networks {
            for s in cfg.servers.iter().filter(|s| s.enabled) {
                let proxy = if s.direct { DIRECT.into() } else { cfg.proxy.clone().unwrap_or_else(|| DIRECT.into()) };
                let t = Target { network: *net, id: s.id.clone(), url: s.url.clone(), proxy };
                match blocked(cfg, s) {
                    Some(why) => skipped.push((t, why)),
                    None => targets.push(t),
                }
            }
        }
        (targets, skipped)
    }

    /// Stores a poll result, unless the server changed or went away meanwhile.
    pub fn record(&self, t: &Target, health: ServerHealth) {
        let mut inner = self.lock();
        let current = inner.cfg(t.network).servers.iter().any(|s| s.id == t.id && s.url == t.url && s.enabled);
        if current {
            inner.health.insert((t.network, t.id.clone()), (t.url.clone(), health));
        }
    }

    /// Sends the events for everything that changed since the last flush.
    pub fn flush(&self) {
        let events: Vec<Event> = {
            let mut inner = self.lock();
            networks().into_iter().flat_map(|n| inner.changes(n)).collect()
        };
        self.emit(events);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::Observed;

    struct Harness {
        node: Arc<Node>,
        events: Arc<Mutex<Vec<String>>>,
        _dir: tempfile::TempDir,
    }

    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let events: Arc<Mutex<Vec<String>>> = Arc::default();
        let log = events.clone();
        let sink: Sink = Arc::new(move |e| {
            let line = match e {
                Event::HealthChanged { network, payload } => {
                    let v: Value = serde_json::from_str(&payload).unwrap();
                    format!("health {} {}", network.name(), v["overall"].as_str().unwrap())
                }
                Event::RoutesChanged { network } => format!("routes {}", network.name()),
                Event::Suspect { network, server_id, kind } => format!("suspect {} {server_id} {kind}", network.name()),
            };
            log.lock().unwrap().push(line);
        });
        let node = Node::open(Some(dir.path().join(crate::store::FILE_NAME)), sink);
        Harness { node, events, _dir: dir }
    }

    impl Harness {
        fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.events.lock().unwrap())
        }
    }

    fn v(s: String) -> Value {
        serde_json::from_str(&s).unwrap()
    }

    fn ids(v: &Value, class: &str) -> Vec<String> {
        v[class].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect()
    }

    struct FakeLocal(Value);

    impl LocalStatus for FakeLocal {
        fn status(&self) -> Result<Value, String> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn local_node_takes_every_read_and_broadcasts_stay_on_tor() {
        let h = harness();
        assert_eq!(v(h.node.local_node("testnet"))["error"], "zebrad_module is not installed");
        h.take();
        assert_eq!(v(h.node.set_local_node("testnet", true))["localNode"], true);
        assert_eq!(h.take(), vec!["routes testnet"]);
        let rt = v(h.node.route_table("testnet"));
        for class in ["sync", "details", "taddr", "mempool", "tip"] {
            assert_eq!(rt[class][0]["url"], LOCAL_NODE_URL, "{class}");
        }
        let broadcast = ids(&rt, "broadcast");
        assert_eq!(broadcast.len(), 2, "both operators");
        assert_eq!((&rt["crossCheck"], &rt["proxy"]), (&json!(false), &json!("socks5h://127.0.0.1:9050")));
        assert_eq!(v(h.node.servers("testnet"))["localNode"], true);
        // Suspect servers leave no broadcast route; the local node does not quietly take over.
        for id in &broadcast {
            h.node.report_mismatch("testnet", id, "tip", 1);
        }
        assert_eq!(v(h.node.route_table("testnet"))["broadcast"], json!([]));
        // Status comes from zebrad_module; it must run this network to be available.
        h.node.set_local_status(Arc::new(FakeLocal(json!({"state": "running", "network": "Testnet", "height": 10}))));
        let st = v(h.node.local_node("testnet"));
        assert_eq!((&st["enabled"], &st["available"], &st["status"]["height"]), (&json!(true), &json!(true), &json!(10)));
        assert_eq!(v(h.node.local_node("mainnet"))["available"], false);
        // Off again: the servers take every class back.
        h.node.set_local_node("testnet", false);
        for id in &broadcast {
            h.node.clear_suspect("testnet", id);
        }
        assert_eq!(ids(&v(h.node.route_table("testnet")), "sync"), broadcast);
    }

    fn answer(net: ZNetwork, chain: &str, branch: &str, tip: u64) -> ServerHealth {
        let o = Observed {
            chain_name: chain.into(),
            consensus_branch_id: branch.into(),
            info_height: tip,
            tip,
            version: "v0.4.18".into(),
            vendor: "ECC LightWalletD".into(),
            protocol_version: "v0.5.0".into(),
            rtt_ms: 700,
        };
        ServerHealth::observed(net, o, now())
    }

    fn poll_all(node: &Node, f: impl Fn(&Target) -> ServerHealth) {
        let (targets, skipped) = node.poll_plan();
        for (t, why) in &skipped {
            node.record(t, ServerHealth::unreachable(*why, now()));
        }
        for t in &targets {
            node.record(t, f(t));
        }
        node.flush();
    }

    #[test]
    fn route_table_shape_and_fail_closed() {
        let h = harness();
        let rt = h.node.route_table("testnet");
        assert!(rt.starts_with(r#"{"ok":true,"network":"testnet","proxy":"socks5h://127.0.0.1:9050","proxyRequired":true,"crossCheck":true,"sync":[{"id":"testnet.zec.rocks","url":"https://testnet.zec.rocks:443","operator":"zec.rocks"},{"id":"#), "{rt}");
        let keys: Vec<String> = v(rt).as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys.len(), 12);

        let main = v(h.node.route_table("mainnet"));
        assert_eq!(ids(&main, "sync"), ["zec.rocks", "us.zec.stardust.rest"]);
        assert_eq!(main["crossCheck"], true);

        assert_eq!(v(h.node.set_proxy("testnet", r#"{"proxy":null,"proxyRequired":true}"#))["proxy"], Value::Null);
        assert_eq!(h.node.route_table("testnet"), r#"{"ok":false,"error":"no proxy is set"}"#);
        assert_eq!(h.take(), ["routes testnet"]);
        h.node.set_proxy("testnet", r#"{"proxy":null,"proxyRequired":false}"#);
        assert_eq!(h.node.route_table("testnet"), r#"{"ok":false,"error":"no proxy is set"}"#);
        // The poller dials nothing on a network without a proxy.
        let (targets, skipped) = h.node.poll_plan();
        assert!(targets.iter().all(|t| t.network == ZNetwork::Mainnet) && skipped.len() == 2);
        assert!(skipped.iter().all(|(t, why)| t.network == ZNetwork::Testnet && *why == NO_PROXY));
        for (t, why) in &skipped {
            h.node.record(t, ServerHealth::unreachable(*why, now()));
        }
        let health = v(h.node.server_health("testnet"));
        assert_eq!((health["overall"].as_str(), health["servers"][0]["lastError"].as_str()), (Some("offline"), Some(NO_PROXY)));

        for refused in [r#"{"proxy":"socks5://127.0.0.1:9050"}"#, r#"{"proxy":"http://127.0.0.1:8118"}"#, r#"{"proxy":"https://p:443"}"#] {
            assert_eq!(v(h.node.set_proxy("mainnet", refused))["ok"], false);
        }
        assert_eq!(v(h.node.route_table("mainnet"))["proxy"], "socks5h://127.0.0.1:9050");
        assert_eq!(v(h.node.route_table("regtest"))["error"], "network must be mainnet or testnet");
    }

    #[test]
    fn regtest_needs_configuring() {
        let h = harness();
        let lwd = r#"[{"id":"lwd","url":"http://127.0.0.1:29061","operator":"local"}]"#;
        let direct = r#"{"proxy":"direct","proxyRequired":false}"#;
        // No unit test configures regtest (tests/regtest.rs does, in its own process).
        for reply in [h.node.servers("regtest"), h.node.set_servers("regtest", lwd), h.node.set_proxy("regtest", direct)] {
            assert_eq!(v(reply)["error"], "network must be mainnet or testnet");
        }
        assert!(h.take().is_empty());
        let (targets, skipped) = h.node.poll_plan();
        assert!(skipped.is_empty() && targets.iter().all(|t| t.network != ZNetwork::Regtest && t.proxy != DIRECT));
    }

    #[test]
    fn lan_servers_and_tor_per_server() {
        let h = harness();
        // A node on the user's network, typed as an address: dialled directly, so no proxy is needed.
        let s = v(h.node.set_servers("testnet", r#"[{"id":"home","url":"192.168.1.20","operator":"me"}]"#));
        assert_eq!(s["servers"][0]["url"], "http://192.168.1.20:9067");
        h.node.set_proxy("testnet", r#"{"proxy":null,"proxyRequired":false}"#);
        let rt = v(h.node.route_table("testnet"));
        assert_eq!((ids(&rt, "sync"), rt["proxy"].as_str()), (vec!["home".to_string()], Some(DIRECT)));
        let (targets, skipped) = h.node.poll_plan();
        assert!(skipped.is_empty() && targets.iter().any(|t| t.id == "home" && t.proxy == DIRECT));
        // Next to a public server and without a proxy, only the LAN one is routed.
        let mixed = r#"[{"id":"home","url":"http://192.168.1.20:9067","operator":"me"},
                        {"id":"testnet.zec.rocks","url":"https://testnet.zec.rocks:443","operator":"zec.rocks"}]"#;
        h.node.set_servers("testnet", mixed);
        assert_eq!(ids(&v(h.node.route_table("testnet")), "sync"), ["home"]);
        let (_, skipped) = h.node.poll_plan();
        assert_eq!(skipped.iter().map(|(t, why)| (t.id.as_str(), *why)).collect::<Vec<_>>(), [("testnet.zec.rocks", NO_PROXY)]);
        // The local node broadcasts through the LAN server then, with no proxy either.
        h.node.set_local_node("testnet", true);
        let rt = v(h.node.route_table("testnet"));
        assert_eq!((ids(&rt, "broadcast"), rt["proxy"].as_str()), (vec!["home".to_string()], Some(DIRECT)));
        h.node.set_local_node("testnet", false);

        // Tor per server: zec.rocks skips it, the onion service keeps it.
        h.node.apply_preset("testnet", "two-operators");
        let tor = r#"{"proxy":"socks5h://127.0.0.1:9050","proxyRequired":true}"#;
        h.node.set_proxy("testnet", tor);
        let mut list = v(h.node.servers("testnet"))["servers"].clone();
        let onion = list.as_array().unwrap().iter().find(|s| s["id"].as_str().unwrap().ends_with(".onion")).unwrap()["id"].clone();
        for s in list.as_array_mut().unwrap().iter_mut().filter(|s| s["id"] == "testnet.zec.rocks") {
            s["direct"] = json!(true);
        }
        assert_eq!(v(h.node.set_servers("testnet", &list.to_string()))["ok"], true);
        let rt = v(h.node.route_table("testnet"));
        assert_eq!((ids(&rt, "sync").len(), &rt["direct"]), (2, &json!(["https://testnet.zec.rocks:443"])));
        assert_eq!(rt["proxy"], "socks5h://127.0.0.1:9050");
        let (targets, _) = h.node.poll_plan();
        let proxy_of = |id: &Value| targets.iter().find(|t| t.network == ZNetwork::Testnet && t.id == *id).unwrap().proxy.clone();
        assert_eq!((proxy_of(&json!("testnet.zec.rocks")).as_str(), proxy_of(&onion).as_str()), (DIRECT, "socks5h://127.0.0.1:9050"));
        // The choice outlives re-applying the preset.
        h.node.apply_preset("testnet", "two-operators");
        assert_eq!(v(h.node.route_table("testnet"))["direct"], json!(["https://testnet.zec.rocks:443"]));
        // Without a proxy, the server that skips Tor is still routed, and the onion service is not.
        h.node.set_proxy("testnet", r#"{"proxy":null,"proxyRequired":false}"#);
        let rt = v(h.node.route_table("testnet"));
        assert_eq!((ids(&rt, "sync"), rt["proxy"].as_str()), (vec!["testnet.zec.rocks".to_string()], Some(DIRECT)));
        let (_, skipped) = h.node.poll_plan();
        assert!(skipped.len() == 1 && json!(skipped[0].0.id) == onion && skipped[0].1 == NO_PROXY);
        // An onion service is reached through Tor only.
        for s in list.as_array_mut().unwrap().iter_mut().filter(|s| s["id"] == onion) {
            s["direct"] = json!(true);
        }
        assert!(v(h.node.set_servers("testnet", &list.to_string()))["error"].as_str().unwrap().contains("through Tor only"));
        // Plain http to a public host stays refused.
        let public = r#"[{"id":"x","url":"http://zec.rocks:9067","operator":"o"}]"#;
        assert!(v(h.node.set_servers("testnet", public))["error"].as_str().unwrap().contains("plain http"));
    }

    #[test]
    fn presets_and_custom_lists() {
        let h = harness();
        let s = v(h.node.apply_preset("mainnet", "single"));
        assert_eq!(s["preset"], "single");
        let rt = v(h.node.route_table("mainnet"));
        assert_eq!((ids(&rt, "sync"), &rt["crossCheck"]), (vec!["zec.rocks".to_string()], &json!(false)));
        assert_eq!(h.take(), ["routes mainnet", "health mainnet offline"]);

        let custom = r#"[{"id":"mine","url":"https://node.example:9067","operator":"me"},
                         {"id":"zec.rocks","url":"https://zec.rocks:443","operator":"zec.rocks","enabled":false}]"#;
        let s = v(h.node.set_servers("mainnet", custom));
        assert_eq!((s["preset"].as_str(), s["servers"][0]["source"].as_str(), s["servers"][1]["source"].as_str()), (Some("custom"), Some("user"), Some("preset")));
        assert_eq!(ids(&v(h.node.route_table("mainnet")), "sync"), ["mine"]);

        // A preset brings its hosts back and keeps the user's server, disabled.
        let s = v(h.node.apply_preset("mainnet", "two-operators"));
        let list = s["servers"].as_array().unwrap();
        assert_eq!(list.len(), 8);
        assert_eq!((list[7]["id"].as_str(), &list[7]["enabled"]), (Some("mine"), &json!(false)));
        assert_eq!(ids(&v(h.node.route_table("mainnet")), "sync"), ["zec.rocks", "us.zec.stardust.rest"]);
        // `custom` keeps the list as it is.
        let s = v(h.node.apply_preset("mainnet", "custom"));
        assert_eq!((s["preset"].as_str(), s["servers"].as_array().unwrap().len()), (Some("custom"), 8));

        let t = v(h.node.apply_preset("testnet", "two-operators"));
        assert_eq!(t["servers"].as_array().unwrap().len(), 2);
        assert_eq!(v(h.node.route_table("testnet"))["crossCheck"], true);
        h.node.apply_preset("testnet", "single");
        assert_eq!(v(h.node.route_table("testnet"))["crossCheck"], false);
        assert_eq!(v(h.node.apply_preset("testnet", "three"))["ok"], false);
        assert_eq!(v(h.node.set_servers("mainnet", r#"[{"id":"x","url":"http://x:1","operator":"o"}]"#))["ok"], false);
        assert_eq!(v(h.node.servers("mainnet"))["servers"].as_array().unwrap().len(), 8);
    }

    #[test]
    fn health_events_and_suspects() {
        let h = harness();
        let ok = |t: &Target| match t.network {
            ZNetwork::Mainnet => answer(ZNetwork::Mainnet, "main", "37a5165b", 3_500_000),
            ZNetwork::Testnet => answer(ZNetwork::Testnet, "test", "77190ad9", 4_480_000),
            ZNetwork::Regtest => unreachable!("no unit test configures regtest"),
        };
        assert_eq!(v(h.node.server_health("mainnet"))["pending"], true);
        poll_all(&h.node, ok);
        assert_eq!(h.take(), ["health mainnet ok", "health testnet ok"]);
        let sh = v(h.node.server_health("mainnet"));
        assert_eq!((&sh["overall"], &sh["pending"]), (&json!("ok"), &json!(false)));
        let first = &sh["servers"][0];
        for key in ["reachable", "rttMs", "chain", "branchId", "height", "protocolVersion", "lightwalletdVersion", "vendor", "suspect", "lastError", "checkedAt"] {
            assert!(first.get(key).is_some(), "{key}");
        }
        assert_eq!((first["chain"].as_str(), first["height"].as_u64()), (Some("main"), Some(3_500_000)));

        // Same answers again: nothing to report, even though rtt and time moved.
        poll_all(&h.node, |t| ServerHealth { rtt_ms: Some(1), checked_at: Some(1), ..ok(t) });
        assert!(h.take().is_empty());

        // A suspect leaves the routes and degrades health.
        assert_eq!(v(h.node.report_mismatch("mainnet", "zec.rocks", "tree_state", 3_499_990))["suspect"], true);
        assert_eq!(h.take(), ["suspect mainnet zec.rocks tree_state", "routes mainnet", "health mainnet degraded"]);
        let rt = v(h.node.route_table("mainnet"));
        assert_eq!((ids(&rt, "sync"), &rt["crossCheck"]), (vec!["us.zec.stardust.rest".to_string()], &json!(false)));
        assert_eq!(v(h.node.server_health("mainnet"))["servers"][0]["suspectKind"], "tree_state");
        assert_eq!(v(h.node.report_mismatch("mainnet", "nope", "x", 1))["error"], "unknown server nope");
        assert_eq!(v(h.node.report_mismatch("mainnet", "zec.rocks", "", 1))["ok"], false);
        assert_eq!(v(h.node.report_mismatch("mainnet", "zec.rocks", "a\nb", 1))["ok"], false);
        assert_eq!(v(h.node.report_mismatch("mainnet", "zec.rocks", "x", -1))["ok"], false);

        assert_eq!(v(h.node.clear_suspect("mainnet", "zec.rocks"))["cleared"], true);
        assert_eq!(h.take(), ["routes mainnet", "health mainnet ok"]);
        assert_eq!(v(h.node.clear_suspect("mainnet", "zec.rocks"))["cleared"], false);

        // A wrong-chain server is unreachable, and it leaves the routes.
        poll_all(&h.node, |t| match t.id.as_str() {
            "us.zec.stardust.rest" => answer(ZNetwork::Mainnet, "test", "77190ad9", 4_480_000),
            _ => ok(t),
        });
        assert_eq!(h.take(), ["routes mainnet", "health mainnet degraded"]);
        let row = &v(h.node.server_health("mainnet"))["servers"][5];
        assert_eq!((&row["reachable"], row["lastError"].as_str()), (&json!(false), Some("wrong chain")));
        assert_eq!(ids(&v(h.node.route_table("mainnet")), "sync"), ["zec.rocks"]);

        // Tips more than two blocks apart across operators disagree.
        poll_all(&h.node, |t| match t.id.as_str() {
            "us.zec.stardust.rest" => answer(ZNetwork::Mainnet, "main", "37a5165b", 3_500_003),
            _ => ok(t),
        });
        assert_eq!(h.take(), ["routes mainnet", "health mainnet disagreement"]);
        // An unknown branch means this build is behind.
        poll_all(&h.node, |t| match t.id.as_str() {
            "us.zec.stardust.rest" => answer(ZNetwork::Mainnet, "main", "77190ad9", 3_500_000),
            _ => ok(t),
        });
        assert_eq!(h.take(), ["health mainnet update_required"]);
        let down = |_: &Target| ServerHealth::unreachable("connect: timed out", now());
        poll_all(&h.node, down);
        assert_eq!(h.take(), ["health mainnet offline", "health testnet offline"]);
    }

    #[test]
    fn results_for_changed_servers_are_dropped_and_state_persists() {
        let h = harness();
        let (targets, _) = h.node.poll_plan();
        h.node.apply_preset("mainnet", "single");
        for t in targets.iter().filter(|t| t.network == ZNetwork::Mainnet) {
            h.node.record(t, answer(t.network, "main", "37a5165b", 3_500_000));
        }
        let sh = v(h.node.server_health("mainnet"));
        let stardust = sh["servers"].as_array().unwrap().iter().find(|s| s["id"] == "us.zec.stardust.rest").unwrap();
        assert_eq!((&stardust["enabled"], &stardust["checkedAt"]), (&json!(false), &Value::Null));

        h.node.set_proxy("testnet", r#"{"proxy":"socks5h://127.0.0.1:19050","proxyRequired":true}"#);
        h.node.report_mismatch("mainnet", "zec.rocks", "block_hash", 10);
        let path = h._dir.path().join(crate::store::FILE_NAME);
        let again = Node::open(Some(path), Arc::new(|_| {}));
        for net in ["mainnet", "testnet"] {
            assert_eq!(again.servers(net), h.node.servers(net));
            assert_eq!(again.route_table(net), h.node.route_table(net));
        }
        assert_eq!(v(again.server_health("mainnet"))["servers"][0]["suspect"], true);
        assert_eq!(v(again.route_table("testnet"))["proxy"], "socks5h://127.0.0.1:19050");
        assert_eq!(v(again.local_node("testnet"))["available"], false);
    }
}
