//! Logos glue for `zcash_node_module` (rust-first, `concurrency: "multi"`). Replies are
//! flat JSON strings, `{ ok, ... }` or `{ ok: false, error }`; gate.rs says who may call.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use logos_rust_sdk::{AboutToUnload, LogosCaller, Shutdown};

use crate::gate::{Access, Caller, Callers};
use crate::node::{Event, Node, Sink};
use crate::poll::Poller;
use crate::reply;
use crate::store::FILE_NAME;

pub trait ZcashNodeModule: Send + Sync + 'static {
    /// `{ ok, network, preset, servers: [{ id, url, operator, label, enabled, classes, source }] }`.
    fn servers(&self, network: String) -> String;
    /// Replaces the list with a JSON array of servers (https only, unique ids, one
    /// enabled at least); the preset becomes `custom`. Backend only.
    fn set_servers(&self, network: String, list_json: String) -> String;
    /// `two-operators`, `single` or `custom`. Backend only.
    fn apply_preset(&self, network: String, name: String) -> String;
    /// `{ proxy, proxyRequired }`; the proxy must be socks5h://host:port. Backend only.
    fn set_proxy(&self, network: String, config_json: String) -> String;
    /// `{ ok, network, proxy, proxyRequired, crossCheck, sync, details, taddr, broadcast,
    /// mempool, tip }`, each class a list of `{ id, url, operator }`. Backend and wallet core.
    fn route_table(&self, network: String) -> String;
    /// `{ ok, network, overall, pending, servers: [{ id, reachable, rttMs, chain, branchId,
    /// height, protocolVersion, lightwalletdVersion, vendor, suspect, lastError, checkedAt }] }`.
    fn server_health(&self, network: String) -> String;
    /// Marks a server suspect until the backend clears it. Backend and wallet core.
    fn report_mismatch(&self, network: String, server_id: String, kind: String, height: i64) -> String;
    /// `{ ok, network, serverId, cleared }`. Backend only.
    fn clear_suspect(&self, network: String, server_id: String) -> String;
    /// `{ ok, available }`: no local node yet.
    fn local_node(&self, network: String) -> String;

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

    /// Loads the servers and starts the health thread; the thread makes the calls.
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        let dir = std::path::PathBuf::from(&ctx.instance_persistence_path);
        let callers = std::fs::read_to_string(dir.join("callers.json")).ok();
        *self.callers.lock().unwrap() = Callers::from_file(callers.as_deref());
        let sink: Sink = Arc::new(|ev| match ev {
            Event::HealthChanged { network, payload } => emit_server_health_changed(network.name(), &payload),
            Event::RoutesChanged { network } => emit_routes_changed(network.name()),
            Event::Suspect { network, server_id, kind } => emit_server_suspect(network.name(), &server_id, &kind),
        });
        let node = Node::open(Some(dir.join(FILE_NAME)), sink);
        if self.node.set(node.clone()).is_ok() {
            match Poller::start(node) {
                Ok(p) => *self.poller.lock().unwrap() = Some(p),
                Err(e) => eprintln!("zcash_node_module: health thread: {e}"),
            }
        }
    }
}

impl AboutToUnload for ZcashNodeModuleImpl {
    /// Stops the health thread, cancelling calls in flight, and joins it within ~1 s.
    fn about_to_unload(&self) -> Shutdown {
        if let Some(p) = self.poller.lock().unwrap().take() {
            if !p.stop(Duration::from_millis(1000)) {
                eprintln!("zcash_node_module: health thread did not stop within 1 s");
            }
        }
        Shutdown::Synchronous
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    logos_install!(ZcashNodeModuleImpl);
}
