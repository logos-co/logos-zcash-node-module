//! The health poller: a thread with a current-thread runtime that polls every enabled
//! server once a minute, four at a time, each on one Tor circuit for the whole session.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use futures_util::{stream, StreamExt};
use tokio::sync::Notify;
use zcash_client_backend::proto::service::{ChainSpec, Empty};

use crate::health::{Observed, ServerHealth};
use crate::net::client::{connect, Client};
use crate::net::socks::{Isolation, ProxyAddr};
use crate::network::ZNetwork;
use crate::node::{now, Node, Target};
use crate::proxy;

pub const POLL_INTERVAL: Duration = Duration::from_secs(60);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(50);
pub const MAX_CONCURRENT: usize = 4;

pub struct Poller {
    stop: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    done: mpsc::Receiver<()>,
    handle: Option<JoinHandle<()>>,
}

impl Poller {
    /// Starts the thread. It makes its first round of calls straight away.
    pub fn start(node: Arc<Node>) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_notify = Arc::new(Notify::new());
        let (done_tx, done) = mpsc::channel();
        let handle = std::thread::Builder::new().name("zcash-node-health".into()).spawn({
            let (stop, stop_notify) = (stop.clone(), stop_notify.clone());
            move || {
                run(&node, &stop, &stop_notify);
                let _ = done_tx.send(());
            }
        })?;
        Ok(Self { stop, stop_notify, done, handle: Some(handle) })
    }

    /// Stops the thread, cancelling calls in flight, and joins it if it ends within
    /// `within`. Returns whether it was joined.
    pub fn stop(mut self, within: Duration) -> bool {
        self.signal();
        match self.done.recv_timeout(within) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                if let Some(h) = self.handle.take() {
                    let _ = h.join();
                }
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
        }
    }

    fn signal(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.stop_notify.notify_one();
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        self.signal();
    }
}

fn run(node: &Node, stop: &AtomicBool, stop_notify: &Notify) {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("zcash_node_module: health runtime: {e}");
            return;
        }
    };
    let mut prober = Prober::default();
    rt.block_on(async {
        while !stop.load(Ordering::SeqCst) {
            let next = tokio::time::Instant::now() + POLL_INTERVAL;
            tokio::select! {
                _ = cycle(node, &mut prober) => {}
                _ = stop_notify.notified() => break,
            }
            tokio::select! {
                _ = tokio::time::sleep_until(next) => {}
                _ = node.wake().notified() => {}
                _ = stop_notify.notified() => break,
            }
        }
    });
    drop(prober);
    rt.shutdown_background();
}

/// The circuit of one server: fixed SOCKS credentials, and the open channel if any.
struct Circuit {
    isolation: Isolation,
    client: Option<Client>,
}

#[derive(Default)]
struct Prober {
    circuits: HashMap<Target, Circuit>,
}

async fn cycle(node: &Node, prober: &mut Prober) {
    let (targets, no_proxy) = node.poll_plan();
    for net in no_proxy {
        node.mark_no_proxy(net);
    }
    prober.circuits.retain(|t, _| targets.contains(t));
    let jobs: Vec<(Target, Isolation, Option<Client>)> = targets
        .into_iter()
        .map(|t| {
            let c = prober
                .circuits
                .entry(t.clone())
                .or_insert_with(|| Circuit { isolation: Isolation::fresh(), client: None });
            let (iso, client) = (c.isolation.clone(), c.client.take());
            (t, iso, client)
        })
        .collect();
    let mut results = stream::iter(jobs)
        .map(|(t, iso, client)| async move {
            let (health, client) = match proxy::addr(t.network, &t.proxy) {
                Ok(proxy) => probe(t.network, &t.url, &proxy, iso, client).await,
                Err(e) => (ServerHealth::unreachable(e, now()), None),
            };
            (t, health, client)
        })
        .buffer_unordered(MAX_CONCURRENT);
    while let Some((t, health, client)) = results.next().await {
        if let Some(c) = prober.circuits.get_mut(&t) {
            c.client = client;
        }
        node.record(&t, health);
    }
    node.flush();
}

/// Polls one server on the circuit `iso` names, reusing `cached` when it still works.
/// Returns the health and the channel to keep for the next poll.
pub async fn probe(
    net: ZNetwork,
    url: &str,
    proxy: &ProxyAddr,
    iso: Isolation,
    cached: Option<Client>,
) -> (ServerHealth, Option<Client>) {
    let attempt = async {
        let had_cached = cached.is_some();
        match query(url, proxy, &iso, cached).await {
            Err(_) if had_cached => query(url, proxy, &iso, None).await,
            other => other,
        }
    };
    match tokio::time::timeout(PROBE_TIMEOUT, attempt).await {
        Ok(Ok((client, observed))) => (ServerHealth::observed(net, observed, now()), Some(client)),
        Ok(Err(e)) => (ServerHealth::unreachable(e, now()), None),
        Err(_) => (ServerHealth::unreachable("timed out", now()), None),
    }
}

async fn query(url: &str, proxy: &ProxyAddr, iso: &Isolation, cached: Option<Client>) -> Result<(Client, Observed), String> {
    let mut client = match cached {
        Some(c) => c,
        None => connect(url, proxy, iso.clone()).await.map_err(|e| describe(&e))?,
    };
    let info = client.get_lightd_info(Empty {}).await.map_err(|s| status(&s))?.into_inner();
    let started = Instant::now();
    let tip = client.get_latest_block(ChainSpec {}).await.map_err(|s| status(&s))?.into_inner().height;
    let rtt_ms = started.elapsed().as_millis() as u64;
    let observed = Observed {
        chain_name: info.chain_name,
        consensus_branch_id: info.consensus_branch_id,
        info_height: info.block_height,
        tip,
        version: info.version,
        vendor: info.vendor,
        protocol_version: info.lightwallet_protocol_version,
        rtt_ms,
    };
    Ok((client, observed))
}

/// An error and its causes on one line, without repeats.
fn describe(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        let text = c.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        cause = c.source();
    }
    out.chars().take(240).collect()
}

fn status(s: &tonic::Status) -> String {
    format!("{:?}: {}", s.code(), s.message()).chars().take(240).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Sink;

    #[test]
    fn stops_within_a_second_while_calls_hang() {
        // A listener that accepts and never answers: every probe hangs until stopped.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let sink: Sink = Arc::new(|_| {});
        let node = Node::open(Some(dir.path().join("zcash_servers.json")), sink);
        let cfg = format!(r#"{{"proxy":"socks5h://127.0.0.1:{port}","proxyRequired":true}}"#);
        for net in ["mainnet", "testnet"] {
            assert!(node.set_proxy(net, &cfg).starts_with(r#"{"ok":true"#));
        }
        let poller = Poller::start(node.clone()).unwrap();
        let mut held = Vec::new();
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while held.len() < 3 && Instant::now() < deadline {
            match listener.accept() {
                Ok((s, _)) => held.push(s),
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        assert_eq!(held.len(), 3, "three enabled servers, three concurrent dials");
        let started = Instant::now();
        assert!(poller.stop(Duration::from_millis(1000)), "joined");
        assert!(started.elapsed() < Duration::from_millis(1000));
    }

    #[test]
    fn errors_read_as_one_line() {
        let e = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert_eq!(describe(&e), "refused");
        assert_eq!(status(&tonic::Status::unavailable("down")), "Unavailable: down");
    }
}
