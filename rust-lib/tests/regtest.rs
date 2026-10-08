//! Regtest, in its own process: its heights are set once per process, and the unit tests
//! check that "regtest" is refused until they are. The live check needs a regtest
//! lightwalletd on loopback, and runs alone since it may take other heights:
//! REGTEST_SERVERS=http://127.0.0.1:29061,http://127.0.0.1:29063 [REGTEST_HEIGHTS=regtest.json] \
//!   cargo test --no-default-features --test regtest -- --ignored --nocapture

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use zcash_node::health::{branch_ok, Observed, ServerHealth, WRONG_CHAIN};
use zcash_node::network::{configure_regtest, networks, regtest_configured, RegtestHeights, ZNetwork};
use zcash_node::node::{now, Node};
use zcash_node::poll::Poller;

/// `regtest.json` as the wallet core reads it.
const HEIGHTS: &str = r#"{"overwinter":1,"sapling":1,"blossom":1,"heartwood":1,"canopy":1,"nu5":1,"nu6":1,"nu6_1":1,"nu6_2":1,"nu6_3":300,"nu7":null}"#;
const GO_DIRECT: &str = r#"{"proxy":"direct","proxyRequired":false}"#;

/// Every test configures regtest before it opens a node; the first call wins.
fn configure(heights: &str) {
    configure_regtest(&serde_json::from_str::<RegtestHeights>(heights).unwrap());
    assert!(regtest_configured());
}

fn open(dir: &tempfile::TempDir) -> Arc<Node> {
    Node::open(Some(dir.path().join("zcash_servers.json")), Arc::new(|_| {}))
}

fn v(s: String) -> Value {
    serde_json::from_str(&s).unwrap()
}

/// Leaves only regtest to poll, so no test dials Tor.
fn regtest_only(node: &Node, servers: &str) {
    for net in ["mainnet", "testnet"] {
        assert_eq!(v(node.set_proxy(net, r#"{"proxy":null}"#))["ok"], true);
    }
    assert_eq!(v(node.set_servers("regtest", servers))["ok"], true);
    assert_eq!(v(node.set_proxy("regtest", GO_DIRECT))["ok"], true);
}

#[test]
fn heights_and_chain_names() {
    configure(HEIGHTS);
    assert_eq!(ZNetwork::parse("regtest"), Some(ZNetwork::Regtest));
    assert_eq!(networks(), [ZNetwork::Mainnet, ZNetwork::Testnet, ZNetwork::Regtest]);
    // Branch IDs follow regtest.json: NU6.2 from block 1, NU6.3 from 300, no NU7.
    assert_eq!(ZNetwork::Regtest.branch_at(299), 0x5437_f330);
    assert_eq!(ZNetwork::Regtest.branch_at(300), 0x37a5_165b);
    assert_eq!(ZNetwork::Regtest.nu7_height(), None);
    assert!(serde_json::from_str::<RegtestHeights>(r#"{"nu5":1,"nu8":2}"#).is_err());

    let seen = |chain: &str, branch: &str, tip: u64| {
        let o = Observed {
            chain_name: chain.into(),
            consensus_branch_id: branch.into(),
            info_height: tip,
            tip,
            version: "v0.4.18".into(),
            vendor: "ECC LightWalletD".into(),
            protocol_version: "v0.5.0".into(),
            rtt_ms: 1,
        };
        ServerHealth::observed(ZNetwork::Regtest, o, now())
    };
    // Zebra names its regtest chain "test", zcashd "regtest".
    for chain in ["test", "regtest"] {
        let h = seen(chain, "37a5165b", 400);
        assert!(h.reachable && !h.incompatible && branch_ok(ZNetwork::Regtest, &h), "{chain}");
    }
    assert_eq!(seen("main", "37a5165b", 400).last_error.as_deref(), Some(WRONG_CHAIN));
    assert!(!branch_ok(ZNetwork::Regtest, &seen("test", "37a5165b", 100)));
}

#[test]
fn route_table_over_a_direct_connection() {
    configure(HEIGHTS);
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    // No presets and no proxy until the harness sets them: no route.
    let s = v(node.servers("regtest"));
    assert_eq!((s["preset"].as_str(), s["servers"].as_array().unwrap().len(), &s["proxy"]), (Some("custom"), 0, &Value::Null));
    assert_eq!(node.route_table("regtest"), r#"{"ok":false,"error":"no proxy is set"}"#);
    assert_eq!(v(node.apply_preset("regtest", "two-operators"))["ok"], false);

    // Plain http to 127.0.0.1 only, even on regtest; never on the public networks.
    for url in ["http://10.0.0.1:9067", "http://localhost:9067", "http://[::1]:9067", "http://127.0.0.1"] {
        let list = json!([{"id": "x", "url": url, "operator": "o"}]).to_string();
        assert_eq!(v(node.set_servers("regtest", &list))["ok"], false, "{url}");
    }
    let lwd = r#"[{"id":"lwd1","url":"http://127.0.0.1:29061","operator":"local"}]"#;
    for net in ["mainnet", "testnet"] {
        assert_eq!(v(node.set_servers(net, lwd))["ok"], false);
        assert_eq!(v(node.set_proxy(net, GO_DIRECT))["ok"], false);
    }
    assert_eq!(v(node.set_servers("regtest", lwd))["servers"][0]["url"], "http://127.0.0.1:29061");
    let p = v(node.set_proxy("regtest", GO_DIRECT));
    assert_eq!((p["proxy"].as_str(), &p["proxyRequired"]), (Some("direct"), &json!(false)));

    // The core's routes take { proxy, servers } from this table unchanged.
    let rt = node.route_table("regtest");
    assert!(rt.starts_with(r#"{"ok":true,"network":"regtest","proxy":"direct","proxyRequired":false,"crossCheck":false,"sync":[{"id":"lwd1","url":"http://127.0.0.1:29061","operator":"local"}],"#), "{rt}");
    assert_eq!(v(node.route_table("mainnet"))["proxy"], "socks5h://127.0.0.1:9050");
    let (targets, _) = node.poll_plan();
    assert!(targets.iter().any(|t| t.network == ZNetwork::Regtest && t.proxy == "direct" && t.url == "http://127.0.0.1:29061"));

    // It persists, and an empty list puts regtest back where it started.
    assert_eq!(open(&dir).route_table("regtest"), rt);
    assert_eq!(v(node.set_servers("regtest", "[]"))["servers"], json!([]));
    assert_eq!(v(node.route_table("regtest"))["sync"], json!([]));
}

#[test]
fn the_poller_dials_regtest_without_a_proxy() {
    configure(HEIGHTS);
    // A listener that accepts and never answers: the dial itself is what is checked.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    regtest_only(&node, &json!([{"id": "lwd", "url": format!("http://127.0.0.1:{port}"), "operator": "local"}]).to_string());
    let poller = Poller::start(node.clone()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut held = None;
    while held.is_none() && Instant::now() < deadline {
        match listener.accept() {
            Ok((s, _)) => held = Some(s),
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    assert!(held.is_some(), "the poller never dialled the regtest server");
    assert!(poller.stop(Duration::from_millis(1000)), "joined");
}

/// The real poller against regtest lightwalletd servers, one operator each.
#[test]
#[ignore]
fn poller_reports_a_live_regtest_chain() {
    configure(&std::env::var("REGTEST_HEIGHTS").map(|p| std::fs::read_to_string(p).unwrap()).unwrap_or(HEIGHTS.into()));
    let urls: Vec<String> = std::env::var("REGTEST_SERVERS")
        .expect("set REGTEST_SERVERS=http://127.0.0.1:PORT[,...]")
        .split(',')
        .map(String::from)
        .collect();
    let list: Vec<Value> =
        urls.iter().enumerate().map(|(i, url)| json!({"id": format!("lwd{i}"), "url": url, "operator": format!("local{i}")})).collect();
    let dir = tempfile::tempdir().unwrap();
    let node = open(&dir);
    regtest_only(&node, &Value::from(list).to_string());
    let poller = Poller::start(node.clone()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while v(node.server_health("regtest"))["pending"] != false && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("{}\n{}", node.server_health("regtest"), node.route_table("regtest"));
    let h = v(node.server_health("regtest"));
    assert_eq!(h["overall"], "ok", "{h}");
    assert!(h["servers"].as_array().unwrap().iter().all(|s| s["reachable"] == true && (s["chain"] == "test" || s["chain"] == "regtest")));
    let rt = v(node.route_table("regtest"));
    let sync: Vec<&str> = rt["sync"].as_array().unwrap().iter().map(|r| r["url"].as_str().unwrap()).collect();
    assert_eq!((rt["proxy"].as_str(), sync), (Some("direct"), urls.iter().map(String::as_str).collect::<Vec<_>>()));
    let t0 = Instant::now();
    assert!(poller.stop(Duration::from_millis(1000)));
    println!("poller stopped in {:?}", t0.elapsed());
}
