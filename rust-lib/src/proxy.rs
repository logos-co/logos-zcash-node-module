//! The proxy setting. Only socks5h is accepted: plain socks5 resolves names
//! locally, and http(s) proxies cannot isolate Tor circuits. Regtest alone may go
//! `direct`, to a loopback lightwalletd.

use serde::Deserialize;

use crate::net::socks::ProxyAddr;
use crate::network::ZNetwork;

pub const DEFAULT_PROXY: &str = "socks5h://127.0.0.1:9050";

/// No proxy, as the wallet core's routes name it: regtest's loopback lightwalletd only.
pub const DIRECT: &str = "direct";

/// `{ proxy, proxyRequired }` as set_proxy receives it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProxyInput {
    #[serde(default)]
    proxy: Option<String>,
    #[serde(default = "required_by_default")]
    proxy_required: bool,
}

fn required_by_default() -> bool {
    true
}

/// Parses set_proxy's argument into a normalized `(proxy, proxyRequired)`.
/// A null or empty proxy clears it, which leaves no usable route.
pub fn parse_config(net: ZNetwork, json: &str) -> Result<(Option<String>, bool), String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("proxy config: {e}"))?;
    if !value.is_object() {
        return Err("proxy config must be a JSON object".into());
    }
    let input: ProxyInput = serde_json::from_value(value).map_err(|e| format!("proxy config: {e}"))?;
    let proxy = match input.proxy.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(url) => Some(normalize(net, url)?),
    };
    Ok((proxy, input.proxy_required))
}

/// Normalizes a proxy URL to `socks5h://host:port`, refusing every other scheme, or
/// to `direct` on regtest.
pub fn normalize(net: ZNetwork, url: &str) -> Result<String, String> {
    let lower = url.trim().to_ascii_lowercase();
    if lower == DIRECT {
        return match net {
            ZNetwork::Regtest => Ok(DIRECT.into()),
            _ => Err("a direct connection is only for a loopback regtest server".into()),
        };
    }
    if lower.starts_with("socks5://") || lower.starts_with("socks4") || lower.starts_with("socks://") {
        return Err("socks5:// resolves names locally; use socks5h://host:port".into());
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Err("http(s) proxies cannot isolate circuits; use socks5h://host:port".into());
    }
    let Some(rest) = lower.strip_prefix("socks5h://") else {
        return Err("proxy must be socks5h://host:port".into());
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains(['@', '/', '?', '#']) {
        return Err("proxy must be socks5h://host:port".into());
    }
    let addr = ProxyAddr::parse(&format!("socks5h://{rest}"))?;
    if addr.port == 0 || !addr.host.chars().all(|c| c.is_ascii_alphanumeric() || "-._:".contains(c)) {
        return Err("proxy must be socks5h://host:port".into());
    }
    let host = if addr.host.contains(':') { format!("[{}]", addr.host) } else { addr.host };
    Ok(format!("socks5h://{host}:{}", addr.port))
}

/// What a stored proxy dials through: `direct` on regtest, a socks5h proxy otherwise.
pub fn addr(net: ZNetwork, proxy: &str) -> Result<ProxyAddr, String> {
    match (net, proxy) {
        (ZNetwork::Regtest, DIRECT) => Ok(ProxyAddr::direct()),
        _ => ProxyAddr::parse(proxy),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_socks5h() {
        let normalize = |url| normalize(ZNetwork::Mainnet, url);
        assert_eq!(normalize("socks5h://127.0.0.1:9050").unwrap(), "socks5h://127.0.0.1:9050");
        assert_eq!(normalize(" SOCKS5H://Tor.Local:9150/ ").unwrap(), "socks5h://tor.local:9150");
        assert_eq!(normalize("socks5h://[::1]:9050").unwrap(), "socks5h://[::1]:9050");
        for (url, why) in [
            ("socks5://127.0.0.1:9050", "resolves names locally"),
            ("socks4a://127.0.0.1:9050", "resolves names locally"),
            ("http://127.0.0.1:8118", "cannot isolate"),
            ("https://proxy.example:443", "cannot isolate"),
            ("tor://127.0.0.1:9050", "must be socks5h"),
            ("127.0.0.1:9050", "must be socks5h"),
            ("socks5h://127.0.0.1", "port"),
            ("socks5h://127.0.0.1:0", "port"),
            ("socks5h://127.0.0.1:99999", "port"),
            ("socks5h://user:pw@127.0.0.1:9050", "must be socks5h"),
            ("socks5h://127.0.0.1:9050/path", "must be socks5h"),
            ("socks5h://:9050", "host"),
        ] {
            let e = normalize(url).unwrap_err();
            assert!(e.contains(why), "{url}: {e}");
        }
    }

    #[test]
    fn config() {
        let parse_config = |json| parse_config(ZNetwork::Mainnet, json);
        assert_eq!(
            parse_config(r#"{"proxy":"socks5h://127.0.0.1:19050","proxyRequired":true}"#).unwrap(),
            (Some("socks5h://127.0.0.1:19050".into()), true)
        );
        assert_eq!(parse_config(r#"{"proxy":null,"proxyRequired":false}"#).unwrap(), (None, false));
        assert_eq!(parse_config(r#"{"proxy":""}"#).unwrap(), (None, true));
        assert!(parse_config(r#"{"proxy":"socks5://127.0.0.1:9050"}"#).is_err());
        assert!(parse_config(r#"{"proxy":"socks5h://127.0.0.1:9050","required":true}"#).is_err());
        assert!(parse_config("[]").is_err());
    }

    #[test]
    fn direct_only_on_regtest() {
        let direct = r#"{"proxy":"direct","proxyRequired":false}"#;
        assert_eq!(parse_config(ZNetwork::Regtest, direct).unwrap(), (Some(DIRECT.into()), false));
        assert_eq!(normalize(ZNetwork::Regtest, " Direct ").unwrap(), DIRECT);
        assert_eq!(normalize(ZNetwork::Regtest, "socks5h://127.0.0.1:9050").unwrap(), "socks5h://127.0.0.1:9050");
        for net in [ZNetwork::Mainnet, ZNetwork::Testnet] {
            assert!(parse_config(net, direct).unwrap_err().contains("regtest"));
            assert!(addr(net, DIRECT).is_err());
        }
        assert!(addr(ZNetwork::Regtest, DIRECT).unwrap().is_direct());
        assert!(!addr(ZNetwork::Regtest, DEFAULT_PROXY).unwrap().is_direct());
        // The sentinel cannot be reached through a proxy URL.
        assert!(normalize(ZNetwork::Regtest, "socks5h://direct:0").is_err());
    }
}
