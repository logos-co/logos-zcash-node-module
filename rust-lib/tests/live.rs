//! Live checks over Tor, ignored by default. Run with
//! ZCASH_TEST_TOR=socks5h://127.0.0.1:19050 cargo test --no-default-features -- --ignored --nocapture

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{stream, StreamExt};
use serde_json::Value;
use zcash_node::health::branch_ok;
use zcash_node::net::socks::{Isolation, ProxyAddr};
use zcash_node::network::ZNetwork;
use zcash_node::node::{now, Event, Node, Sink};
use zcash_node::poll::{probe, Poller};
use zcash_node::servers::{preset_servers, Preset};

fn tor() -> String {
    std::env::var("ZCASH_TEST_TOR").expect("set ZCASH_TEST_TOR=socks5h://127.0.0.1:PORT")
}

/// GetLightdInfo + GetLatestBlock against every preset host, each on its own circuit.
#[test]
#[ignore]
fn every_preset_host_answers() {
    let proxy = ProxyAddr::parse(&tor()).unwrap();
    let mut hosts = Vec::new();
    for net in [ZNetwork::Testnet, ZNetwork::Mainnet] {
        for s in preset_servers(net, Preset::TwoOperators).unwrap() {
            hosts.push((net, s));
        }
    }
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let started = now();
    let results = rt.block_on(
        stream::iter(hosts)
            .map(|(net, s)| {
                let proxy = proxy.clone();
                async move {
                    let t0 = Instant::now();
                    let (h, _) = probe(net, &s.url, &proxy, Isolation::fresh(), None).await;
                    (net, s, h, t0.elapsed())
                }
            })
            .buffer_unordered(4)
            .collect::<Vec<_>>(),
    );
    println!("polled at unix time {started}");
    let mut answered = Vec::new();
    for (net, s, h, took) in &results {
        let expected = h.info_height.map(|t| format!("{:08x}", net.branch_at(t + 1))).unwrap_or_default();
        println!(
            "{:8} {:30} chain={:?} branch={:?} (expect {expected}) protocol={:?} lightwalletd={:?} vendor={:?} height={:?} rttMs={:?} reachable={} lastError={:?} in {:.1}s",
            net.name(), s.url, h.chain, h.branch_id, h.protocol_version, h.lightwalletd_version, h.vendor, h.height,
            h.rtt_ms, h.reachable, h.last_error, took.as_secs_f64()
        );
        if h.reachable && h.last_error.is_none() {
            assert!(branch_ok(*net, h), "{} reports an unexpected branch", s.url);
            answered.push((*net, s.operator.clone()));
        }
    }
    assert!(answered.contains(&(ZNetwork::Testnet, "zec.rocks".into())), "testnet.zec.rocks");
    for op in ["zec.rocks", "stardust"] {
        assert!(answered.contains(&(ZNetwork::Mainnet, op.into())), "no mainnet {op} host answered");
    }
}

/// The real poller thread: both networks get health, then it stops within a second.
#[test]
#[ignore]
fn poller_reports_and_stops() {
    let dir = tempfile::tempdir().unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = seen.clone();
    let sink: Sink = Arc::new(move |e| {
        if let Event::HealthChanged { network, .. } = e {
            log.lock().unwrap().push(network.name().into());
        }
    });
    let node = Node::open(Some(dir.path().join("zcash_servers.json")), sink);
    let cfg = format!(r#"{{"proxy":"{}","proxyRequired":true}}"#, tor());
    for net in ["mainnet", "testnet"] {
        assert!(node.set_proxy(net, &cfg).starts_with(r#"{"ok":true"#));
    }
    let poller = Poller::start(node.clone()).unwrap();
    let health = |n: &str| serde_json::from_str::<Value>(&node.server_health(n)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(150);
    while ["mainnet", "testnet"].iter().any(|n| health(n)["pending"] != false) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    for n in ["mainnet", "testnet"] {
        println!("{}\n{}", node.server_health(n), node.route_table(n));
        let h = health(n);
        assert_eq!(h["pending"], false, "{n} still pending");
        assert_eq!(h["overall"], "ok", "{n}");
    }
    let t0 = Instant::now();
    assert!(poller.stop(Duration::from_millis(1000)));
    println!("poller stopped in {:?}", t0.elapsed());
    let seen = seen.lock().unwrap();
    assert!(seen.iter().any(|n| n == "mainnet") && seen.iter().any(|n| n == "testnet"), "{seen:?}");
}
