//! gRPC clients for lightwalletd-protocol servers, one Tor circuit per isolation.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use http::Uri;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

use super::socks::{Isolation, ProxyAddr, Socks5hConnector};

pub type Client = CompactTxStreamerClient<Channel>;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("bad server URL {0}")]
    BadUrl(String),
    #[error("connect to {server}: {source}")]
    Connect { server: String, source: tonic::transport::Error },
    #[error("{server}: {status}")]
    Status { server: String, status: tonic::Status },
    #[error("{0} does not resolve to an address on your network")]
    NotLan(String),
    #[error("{0} is an onion service, which is reached through Tor only")]
    NeedsTor(String),
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);

/// A v3 onion service. Tor authenticates and encrypts it end to end, so it is reached over
/// plain HTTP/2 through Tor, without TLS.
pub fn is_onion(host: &str) -> bool {
    host.strip_suffix(".onion")
        .is_some_and(|name| name.len() == 56 && name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
}

/// `http://<onion>:port`, the only plain-HTTP server reached through Tor.
pub fn is_onion_url(server: &str) -> bool {
    server.parse::<Uri>().is_ok_and(|u| u.scheme_str() == Some("http") && u.host().is_some_and(is_onion))
}

/// An address on the user's own network, which Tor cannot reach: loopback, the private
/// IPv4 ranges, CGNAT's 100.64/10 (Tailscale), link-local, and IPv6 unique-local.
pub fn is_lan_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            ip.is_loopback() || ip.is_private() || ip.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00 || (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// A LAN address, or a name only the user's network resolves: mDNS `.local`, and the `.lan`,
/// `.home.arpa` and `.internal` names home routers hand out.
pub fn is_lan_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.').to_ascii_lowercase();
    match host.parse::<IpAddr>() {
        Ok(ip) => is_lan_ip(ip),
        Err(_) => host == "localhost" || [".local", ".lan", ".home.arpa", ".internal"].iter().any(|s| host.len() > s.len() && host.ends_with(s)),
    }
}

/// A server on the user's own network, reached directly: Tor cannot reach it.
pub fn is_lan_url(server: &str) -> bool {
    server.parse::<Uri>().is_ok_and(|u| matches!(u.scheme_str(), Some("http" | "https")) && u.host().is_some_and(is_lan_host))
}

/// Opens a TLS channel to `server` (https://host:port), or a plain one to an onion service,
/// through the proxy, on the circuit `isolation` selects. A server on the user's network is
/// dialled directly, as is an https server the user set to skip Tor (its target's proxy is direct).
pub async fn connect(server: &str, proxy: &ProxyAddr, isolation: Isolation) -> Result<Client, NetError> {
    let uri: Uri = server.parse().map_err(|_| NetError::BadUrl(server.into()))?;
    let host = uri.host().ok_or_else(|| NetError::BadUrl(server.into()))?.trim_start_matches('[').trim_end_matches(']').to_string();
    let https = uri.scheme_str() == Some("https");
    let wrap = |source| NetError::Connect { server: server.into(), source };
    let endpoint = Endpoint::from_shared(server.to_string()).map_err(wrap)?.connect_timeout(CONNECT_TIMEOUT);
    let endpoint = match https {
        true => endpoint.tls_config(ClientTlsConfig::new().with_webpki_roots().domain_name(host.clone())).map_err(wrap)?,
        false => endpoint,
    };
    let channel = if is_lan_url(server) {
        // A name must resolve onto the user's network, or this connection would bypass Tor.
        if host.parse::<IpAddr>().is_err() {
            let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), port)).await.map(Iterator::collect).unwrap_or_default();
            if addrs.is_empty() || !addrs.iter().all(|a| is_lan_ip(a.ip())) {
                return Err(NetError::NotLan(server.into()));
            }
        }
        endpoint.connect().await.map_err(wrap)?
    } else if proxy.is_direct() {
        // A server the user set to skip Tor: https only.
        if is_onion(&host) {
            return Err(NetError::NeedsTor(server.into()));
        }
        if !https {
            return Err(NetError::BadUrl(server.into()));
        }
        endpoint.connect().await.map_err(wrap)?
    } else {
        if !https && !is_onion(&host) {
            return Err(NetError::BadUrl(server.into()));
        }
        endpoint.connect_with_connector(Socks5hConnector::new(proxy.clone(), isolation)).await.map_err(wrap)?
    };
    Ok(CompactTxStreamerClient::new(channel).max_decoding_message_size(16 * 1024 * 1024))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::proto::service::Empty;

    #[test]
    fn lan_addresses() {
        for host in ["127.0.0.1", "10.0.0.5", "172.16.3.4", "172.31.255.1", "192.168.1.10", "100.64.0.1", "100.127.1.1", "169.254.1.1", "[::1]", "[fd12:3456::1]", "[fe80::1]"] {
            assert!(is_lan_host(host), "{host}");
        }
        for host in ["localhost", "nas.local", "framework.lan", "Node.LAN.", "box.home.arpa", "zebra.internal"] {
            assert!(is_lan_host(host), "{host}");
        }
        for host in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "193.168.1.1", "[2001:db8::1]", "zec.rocks", "lan", ".local", "local.example.com", "planet"] {
            assert!(!is_lan_host(host), "{host}");
        }
        assert!(is_lan_url("http://192.168.1.10:9067") && is_lan_url("https://[fd00::2]:9067") && is_lan_url("http://framework.lan:9067"));
        assert!(!is_lan_url("http://zec.rocks:9067") && !is_lan_url("socks5h://192.168.1.10:9050"));
    }

    #[tokio::test]
    async fn refused_before_anything_is_dialled() {
        let direct = ProxyAddr::direct();
        let onion = format!("http://{}.onion:9067", "a2".repeat(28));
        assert!(matches!(connect(&onion, &direct, Isolation::fresh()).await, Err(NetError::NeedsTor(_))));
        assert!(matches!(connect("http://zec.rocks:443", &direct, Isolation::fresh()).await, Err(NetError::BadUrl(_))));
        let tor = ProxyAddr::parse("socks5h://127.0.0.1:9050").unwrap();
        assert!(matches!(connect("http://zec.rocks:9067", &tor, Isolation::fresh()).await, Err(NetError::BadUrl(_))));
        let name = "http://this-name-does-not-exist.home.arpa:9067";
        assert!(matches!(connect(name, &tor, Isolation::fresh()).await, Err(NetError::NotLan(_))));
    }

    #[tokio::test]
    async fn a_lan_server_is_dialled_directly() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        // Through this proxy, which nothing listens on, the listener would never hear a thing.
        let dead = ProxyAddr::parse("socks5h://127.0.0.1:9").unwrap();
        let dial = tokio::spawn(async move { connect(&url, &dead, Isolation::fresh()).await.map(|_| ()) });
        let accepted = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
        dial.abort();
        assert!(accepted.is_ok_and(|a| a.is_ok()), "dialled directly");
    }

    /// Needs a Tor SOCKS port in ZCASH_TEST_TOR, e.g. socks5h://127.0.0.1:19050.
    #[tokio::test]
    #[ignore]
    async fn lightd_info_over_tor() {
        let proxy = ProxyAddr::parse(&std::env::var("ZCASH_TEST_TOR").unwrap()).unwrap();
        let mut c = connect("https://testnet.zec.rocks:443", &proxy, Isolation::fresh()).await.unwrap();
        let info = c.get_lightd_info(Empty {}).await.unwrap().into_inner();
        println!("{} {} height {} branch {} lightwalletd {}", info.chain_name, info.vendor, info.block_height, info.consensus_branch_id, info.version);
        assert_eq!(info.chain_name, "test");
    }
}
