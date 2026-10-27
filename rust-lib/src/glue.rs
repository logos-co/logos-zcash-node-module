//! Logos glue for `zcash_node_module` (rust-first, `concurrency: "multi"`). Replies are
//! flat JSON strings, `{ ok, ... }` or `{ ok: false, error }`; gate.rs says who may call.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use logos_rust_sdk::{AboutToUnload, LogosCaller, Shutdown};

use crate::gate::{Access, Caller, Callers};
use crate::node::{Event, Node, Sink, TorView};
use crate::poll::Poller;
use crate::reply;
use crate::store::FILE_NAME;

pub trait ZcashNodeModule: Send + Sync + 'static {
    /// `{ ok, network, preset, servers: [{ id, url, operator, label, enabled, classes, source }] }`.
    fn servers(&self, network: String) -> String;
    /// Replaces the list with a JSON array of servers (https only, unique ids, one
    /// enabled at least); the preset becomes `custom`. Regtest also takes
    /// `http://127.0.0.1:port`, and an empty list. Backend only.
    fn set_servers(&self, network: String, list_json: String) -> String;
    /// `two-operators`, `single` or `custom`; regtest has none. Backend only.
    fn apply_preset(&self, network: String, name: String) -> String;
    /// `{ proxy, proxyRequired }`; the proxy is `tor` (the built-in Tor, the default), the
    /// user's own as socks5h://host:port, or `direct` on regtest. Backend only.
    fn set_proxy(&self, network: String, config_json: String) -> String;
    /// `{ ok, network, proxy, proxyRequired, crossCheck, sync, details, taddr, broadcast,
    /// mempool, tip }`, each class a list of `{ id, url, operator }`. `proxy` is what to dial
    /// through: for `tor`, the built-in Tor's port, and an error until it is known. Backend
    /// and wallet core.
    fn route_table(&self, network: String) -> String;
    /// `{ ok, network, overall, pending, servers: [{ id, reachable, rttMs, chain, branchId,
    /// height, protocolVersion, lightwalletdVersion, vendor, suspect, lastError, checkedAt }],
    /// tor }`; `tor` is the built-in Tor's `{ state, progress, detail }` when the network
    /// uses it, else null.
    fn server_health(&self, network: String) -> String;
    /// Marks a server suspect until the backend clears it. Backend and wallet core.
    fn report_mismatch(&self, network: String, server_id: String, kind: String, height: i64) -> String;
    /// `{ ok, network, serverId, cleared }`. Backend only.
    fn clear_suspect(&self, network: String, server_id: String) -> String;
    /// `{ ok, enabled, available, status?, error? }`: whether reads go to the local node, and
    /// whether zebrad_module runs it for `network`; `status` is its status().
    fn local_node(&self, network: String) -> String;
    /// Reads from the local node over IPC, broadcasts over Tor. `{ ok, network, localNode }`.
    /// Backend only.
    fn set_local_node(&self, network: String, enabled: bool) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

#[allow(dead_code)] // Read by logos-lidl-gen, which generates the emitters.
pub trait ZcashNodeModuleEvents {
    /// server_health()'s reply, when anything but round-trip times changed.
    fn server_health_changed(&self, network: String, payload: String);
    /// route_table(network) would now answer differently.
    fn routes_changed(&self, network: String);
    fn server_suspect(&self, network: String, server_id: String, kind: String);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
pub struct ZcashNodeModuleImpl {
    node: OnceLock<Arc<Node>>,
    // Qualified: the generated scaffold already imports `Mutex` into this module.
    callers: std::sync::Mutex<Callers>,
    poller: std::sync::Mutex<Option<Poller>>,
    tor: std::sync::Mutex<Option<TorFollower>>,
}

impl ZcashNodeModuleImpl {
    /// Runs `f` for a caller `access` admits, once the node exists. The caller is
    /// read first, on the dispatching thread.
    fn gated(&self, access: Access, f: impl FnOnce(&Node) -> String) -> String {
        let caller = match logos_rust_sdk::current_caller() {
            LogosCaller::Module { name, .. } => Caller::Module(name),
            LogosCaller::HostAnchor => Caller::Host,
            LogosCaller::Unknown => Caller::Unknown,
            _ => Caller::Other,
        };
        if !self.callers.lock().unwrap().admits(access, &caller) {
            return reply::NOT_AUTHORIZED.into();
        }
        match self.node.get() {
            Some(n) => f(n),
            None => reply::err("starting"),
        }
    }
}

impl ZcashNodeModule for ZcashNodeModuleImpl {
    fn servers(&self, network: String) -> String {
        self.gated(Access::Open, |n| n.servers(&network))
    }

    fn set_servers(&self, network: String, list_json: String) -> String {
        self.gated(Access::Backend, |n| n.set_servers(&network, &list_json))
    }

    fn apply_preset(&self, network: String, name: String) -> String {
        self.gated(Access::Backend, |n| n.apply_preset(&network, &name))
    }

    fn set_proxy(&self, network: String, config_json: String) -> String {
        self.gated(Access::Backend, |n| n.set_proxy(&network, &config_json))
    }

    fn route_table(&self, network: String) -> String {
        self.gated(Access::BackendOrCore, |n| n.route_table(&network))
    }

    fn server_health(&self, network: String) -> String {
        self.gated(Access::Open, |n| n.server_health(&network))
    }

    fn report_mismatch(&self, network: String, server_id: String, kind: String, height: i64) -> String {
        self.gated(Access::BackendOrCore, |n| n.report_mismatch(&network, &server_id, &kind, height))
    }

    fn clear_suspect(&self, network: String, server_id: String) -> String {
        self.gated(Access::Backend, |n| n.clear_suspect(&network, &server_id))
    }

    fn local_node(&self, network: String) -> String {
        self.gated(Access::Open, |n| n.local_node(&network))
    }

    fn set_local_node(&self, network: String, enabled: bool) -> String {
        self.gated(Access::Backend, |n| n.set_local_node(&network, enabled))
    }

    /// Loads the servers and starts the Tor and health threads; the threads make the calls.
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = std::path::PathBuf::from(&ctx.instance_persistence_path);
        let callers = std::fs::read_to_string(dir.join("callers.json")).ok();
        *self.callers.lock().unwrap() = Callers::from_file(callers.as_deref());
        // A local test chain's upgrade heights, for test harnesses only.
        if let Some(h) = std::fs::read_to_string(dir.join("regtest.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<crate::network::RegtestHeights>(&t).ok())
        {
            crate::network::configure_regtest(&h);
        }
        let sink: Sink = Arc::new(|ev| match ev {
            Event::HealthChanged { network, payload } => emit_server_health_changed(network.name(), &payload),
            Event::RoutesChanged { network } => emit_routes_changed(network.name()),
            Event::Suspect { network, server_id, kind } => emit_server_suspect(network.name(), &server_id, &kind),
        });
        let node = Node::open(Some(dir.join(FILE_NAME)), sink);
        node.set_local_status(Arc::new(ZebradStatus::default()));
        if self.node.set(node.clone()).is_ok() {
            match TorFollower::start(node.clone()) {
                Ok(t) => *self.tor.lock().unwrap() = Some(t),
                Err(e) => eprintln!("zcash_node_module: tor thread: {e}"),
            }
            match Poller::start(node) {
                Ok(p) => *self.poller.lock().unwrap() = Some(p),
                Err(e) => eprintln!("zcash_node_module: health thread: {e}"),
            }
        }
    }
}

/// Bounds each status call, so unloading never waits on tor_module for long.
const TOR_BUDGET: Duration = Duration::from_millis(1000);

/// Follows tor_module, the built-in Tor, while a network uses it: its status every 2 s until
/// it is ready, then every 30 s. Asking starts Tor, so with no network on it nothing is asked
/// and Tor stays off. The call is async with a channel: a blocking one from this thread would
/// run nested on the main thread.
struct TorFollower {
    stop: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TorFollower {
    fn start(node: Arc<Node>) -> std::io::Result<Self> {
        let stop = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let flag = stop.clone();
        let thread = std::thread::Builder::new().name("zcash_node_tor".into()).spawn(move || {
            // One client: each new one opens its own connection.
            let client = tor_module::TorModuleClient::new();
            loop {
                let mut every = Duration::from_secs(2);
                if node.uses_built_in_tor() {
                    let (tx, rx) = std::sync::mpsc::channel();
                    client.status_async_with_timeout(TOR_BUDGET, move |r| {
                        let _ = tx.send(r.map_err(|e| e.to_string()));
                    });
                    let reply = rx
                        .recv_timeout(TOR_BUDGET + Duration::from_millis(200))
                        .unwrap_or_else(|_| Err("tor_module did not answer".into()));
                    let view = TorView::from_reply(reply);
                    if view.state == "ready" {
                        every = Duration::from_secs(30);
                    }
                    node.set_tor(view);
                }
                let (lock, cvar) = &*flag;
                let (stopped, _) = cvar.wait_timeout_while(lock.lock().unwrap(), every, |s| !*s).unwrap();
                if *stopped {
                    return;
                }
            }
        })?;
        Ok(Self { stop, thread: Some(thread) })
    }

    fn signal(&self) {
        let (lock, cvar) = &*self.stop;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }

    fn join(mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// zebrad_module, an OPTIONAL dependency: when it is not loaded, local_node() says so.
/// The client is made on first use and kept: each new one opens its own connection.
#[derive(Default)]
struct ZebradStatus(std::sync::OnceLock<zebrad_module::ZebradModuleClient>);

/// Bounded so an absent zebrad_module costs 1.5 s, not the protocol deadline.
const LOCAL_BUDGET: std::time::Duration = std::time::Duration::from_millis(1500);

impl crate::node::LocalStatus for ZebradStatus {
    fn status(&self) -> Result<serde_json::Value, String> {
        self.0
            .get_or_init(zebrad_module::ZebradModuleClient::new)
            .status_with_timeout(LOCAL_BUDGET)
            .map(|m| serde_json::Value::Object(m.into_iter().collect()))
            .map_err(|e| {
                let s = e.to_string();
                if s.contains("object_unavailable") { "zebrad_module is not loaded".into() } else { format!("zebrad_module: {s}") }
            })
    }
}

impl AboutToUnload for ZcashNodeModuleImpl {
    /// Stops the Tor and health threads, cancelling calls in flight, and joins them within
    /// ~1.2 s: the Tor thread's last call runs out while the health thread stops.
    fn about_to_unload(&self) -> Shutdown {
        let tor = self.tor.lock().unwrap().take();
        if let Some(t) = &tor {
            t.signal();
        }
        if let Some(p) = self.poller.lock().unwrap().take() {
            if !p.stop(Duration::from_millis(1000)) {
                eprintln!("zcash_node_module: health thread did not stop within 1 s");
            }
        }
        if let Some(t) = tor {
            t.join();
        }
        Shutdown::Synchronous
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    logos_install!(ZcashNodeModuleImpl);
}
