//! The proxy setting. Only socks5h is accepted: plain socks5 resolves names
//! locally, and http(s) proxies cannot isolate Tor circuits.

use serde::Deserialize;

use crate::net::socks::ProxyAddr;

pub const DEFAULT_PROXY: &str = "socks5h://127.0.0.1:9050";

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
pub fn parse_config(json: &str) -> Result<(Option<String>, bool), String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("proxy config: {e}"))?;
    if !value.is_object() {
        return Err("proxy config must be a JSON object".into());
    }
    let input: ProxyInput = serde_json::from_value(value).map_err(|e| format!("proxy config: {e}"))?;
    let proxy = match input.proxy.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(url) => Some(normalize(url)?),
    };
    Ok((proxy, input.proxy_required))
}

/// Normalizes a proxy URL to `socks5h://host:port`, refusing every other scheme.
pub fn normalize(url: &str) -> Result<String, String> {
    let lower = url.trim().to_ascii_lowercase();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_socks5h() {
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
            ("socks5h://127.0.0.1:0", "must be socks5h"),
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
}
