//! Server lists per network: presets, validation, and the routes per call class.

use std::collections::HashSet;

use http::Uri;
use serde::{Deserialize, Serialize};

use crate::net::client::{is_lan_host, is_onion};
use crate::network::ZNetwork;

/// What a server may be asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallClass {
    /// Compact blocks and tree states.
    Sync,
    /// GetTransaction.
    Details,
    /// Transparent address queries.
    Taddr,
    Broadcast,
    Mempool,
    Tip,
}

pub const ALL_CLASSES: [CallClass; 6] =
    [CallClass::Sync, CallClass::Details, CallClass::Taddr, CallClass::Broadcast, CallClass::Mempool, CallClass::Tip];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Preset,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Preset {
    TwoOperators,
    Single,
    Custom,
}

impl Preset {
    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(s.into())).ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Server {
    pub id: String,
    pub url: String,
    pub operator: String,
    pub label: String,
    pub enabled: bool,
    pub classes: Vec<CallClass>,
    pub source: Source,
    /// The user chose to reach this server without Tor. https servers only.
    #[serde(default)]
    pub direct: bool,
}

struct Host {
    host: &'static str,
    port: u16,
    operator: &'static str,
    label: &'static str,
}

const fn h(host: &'static str, port: u16, operator: &'static str, label: &'static str) -> Host {
    Host { host, port, operator, label }
}

impl Host {
    /// An onion service is plain http: Tor already authenticates and encrypts it.
    fn url(&self) -> String {
        let scheme = if crate::net::client::is_onion(self.host) { "http" } else { "https" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }
}

// Ports verified over Tor with GetLightdInfo (see tests/live.rs). The first host of
// each operator is the one the presets enable; the rest are failover candidates.
const MAINNET: &[Host] = &[
    h("zec.rocks", 443, "zec.rocks", "zec.rocks"),
    h("na.zec.rocks", 443, "zec.rocks", "zec.rocks North America"),
    h("sa.zec.rocks", 443, "zec.rocks", "zec.rocks South America"),
    h("eu.zec.rocks", 443, "zec.rocks", "zec.rocks Europe"),
    h("ap.zec.rocks", 443, "zec.rocks", "zec.rocks Asia-Pacific"),
    h("us.zec.stardust.rest", 443, "stardust", "Stardust US"),
    h("eu.zec.stardust.rest", 443, "stardust", "Stardust EU"),
];

const TESTNET: &[Host] = &[
    h("testnet.zec.rocks", 443, "zec.rocks", "zec.rocks testnet"),
    // Ours: zebrad and lightwalletd behind an onion service, the testnet's second operator.
    h("cnphkglrgl6xb4bz4zukbntfimrdqk3u4rf4mys2vhrvc73w3ulhb4id.onion", 9067, "logos", "Logos testnet (onion)"),
];

fn hosts(net: ZNetwork) -> &'static [Host] {
    match net {
        ZNetwork::Mainnet => MAINNET,
        ZNetwork::Testnet => TESTNET,
        ZNetwork::Regtest => &[],
    }
}

/// The preset's server list; `None` for `custom`, which keeps the current list.
pub fn preset_servers(net: ZNetwork, preset: Preset) -> Option<Vec<Server>> {
    if preset == Preset::Custom {
        return None;
    }
    let mut operators: Vec<&str> = Vec::new();
    let servers = hosts(net)
        .iter()
        .enumerate()
        .map(|(i, host)| {
            let first_of_operator = !operators.contains(&host.operator);
            if first_of_operator {
                operators.push(host.operator);
            }
            let enabled = match preset {
                Preset::TwoOperators => first_of_operator,
                _ => i == 0,
            };
            Server {
                id: host.host.into(),
                url: host.url(),
                operator: host.operator.into(),
                label: host.label.into(),
                enabled,
                classes: ALL_CLASSES.to_vec(),
                source: Source::Preset,
                direct: false,
            }
        })
        .collect();
    Some(servers)
}

fn is_preset_entry(net: ZNetwork, id: &str, url: &str, operator: &str) -> bool {
    hosts(net)
        .iter()
        .any(|h| h.host == id && h.url() == url && h.operator == operator)
}

/// One entry of set_servers' list. `source` is accepted for round trips but recomputed.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ServerInput {
    id: String,
    url: String,
    operator: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    #[serde(default)]
    classes: Option<Vec<CallClass>>,
    #[serde(default)]
    #[allow(dead_code)]
    source: Option<Source>,
    #[serde(default)]
    direct: bool,
}

fn enabled_by_default() -> bool {
    true
}

pub const MAX_SERVERS: usize = 32;

/// Parses and validates set_servers' list. An entry is `preset` only when it is a
/// preset host unchanged in id, url and operator.
pub fn parse_list(net: ZNetwork, json: &str) -> Result<Vec<Server>, String> {
    let items: Vec<serde_json::Value> = serde_json::from_str(json).map_err(|e| format!("server list: {e}"))?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if !item.is_object() {
            return Err("server list: every entry must be a JSON object".into());
        }
        let s: ServerInput = serde_json::from_value(item).map_err(|e| format!("server list: {e}"))?;
        let url = normalize_url(&s.url)?;
        let operator = s.operator.trim().to_string();
        let mut classes = s.classes.unwrap_or_else(|| ALL_CLASSES.to_vec());
        classes.sort();
        classes.dedup();
        let label = match s.label.map(|l| l.trim().to_string()) {
            Some(l) if !l.is_empty() => l,
            _ => host_of(&url),
        };
        let source = if is_preset_entry(net, &s.id, &url, &operator) { Source::Preset } else { Source::User };
        out.push(Server { id: s.id, url, operator, label, enabled: s.enabled, classes, source, direct: s.direct });
    }
    validate(net, &out)?;
    Ok(out)
}

/// The rules every stored list obeys, whoever wrote it. Regtest has no presets, so its
/// list may be empty.
pub fn validate(net: ZNetwork, list: &[Server]) -> Result<(), String> {
    if net == ZNetwork::Regtest && list.is_empty() {
        return Ok(());
    }
    if list.is_empty() || list.len() > MAX_SERVERS {
        return Err(format!("a list holds 1 to {MAX_SERVERS} servers"));
    }
    let (mut ids, mut urls) = (HashSet::new(), HashSet::new());
    for s in list {
        let id_ok = !s.id.is_empty() && s.id.len() <= 64 && s.id.chars().all(|c| c.is_ascii_alphanumeric() || "-._".contains(c));
        if !id_ok {
            return Err(format!("bad server id {:?}: use letters, digits, '-', '.', '_' (at most 64)", s.id));
        }
        if !ids.insert(s.id.as_str()) {
            return Err(format!("duplicate server id {}", s.id));
        }
        match normalize_url(&s.url) {
            Ok(n) if n == s.url => {}
            Ok(n) => return Err(format!("{}: url must be written as {n}", s.id)),
            Err(e) => return Err(format!("{}: {e}", s.id)),
        }
        if !urls.insert(s.url.as_str()) {
            return Err(format!("duplicate server url {}", s.url));
        }
        if s.operator.is_empty() || s.operator.len() > 64 || s.operator.trim() != s.operator {
            return Err(format!("{}: operator must be 1 to 64 characters", s.id));
        }
        if s.label.len() > 128 {
            return Err(format!("{}: label is longer than 128 characters", s.id));
        }
        if s.enabled && s.classes.is_empty() {
            return Err(format!("{}: an enabled server needs at least one call class", s.id));
        }
        if s.direct && crate::net::client::is_onion_url(&s.url) {
            return Err(format!("{}: an onion service is reached through Tor only", s.id));
        }
    }
    if !list.iter().any(|s| s.enabled) {
        return Err("at least one server must be enabled".into());
    }
    Ok(())
}

/// lightwalletd's port, for a server on the user's network given without one.
pub const LAN_PORT: u16 = 9067;

/// `https://host:port`, lowercase host, port 443 when absent; a v3 onion service as
/// `http://<onion>:port`; a server on the user's network also as `http://host:port`, port
/// 9067 when absent. Without a scheme, onion and LAN hosts take http and the rest https.
pub fn normalize_url(url: &str) -> Result<String, String> {
    let bad = || format!("{url}: url must be https://host:port");
    let url = url.trim();
    let full = if url.contains("://") {
        url.to_string()
    } else {
        let host = format!("http://{url}").parse::<Uri>().ok().and_then(|u| u.host().map(str::to_ascii_lowercase));
        let plain = host.is_some_and(|h| is_onion(&h) || is_lan_host(&h));
        format!("{}://{url}", if plain { "http" } else { "https" })
    };
    let uri: Uri = full.parse().map_err(|_| bad())?;
    let authority = uri.authority().ok_or_else(bad)?;
    if authority.as_str().contains('@') || uri.query().is_some() || !matches!(uri.path(), "" | "/") {
        return Err(bad());
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || "-.[]:".contains(c)) {
        return Err(bad());
    }
    let port = authority.port_u16();
    if port == Some(0) {
        return Err(bad());
    }
    match uri.scheme_str().map(str::to_ascii_lowercase).as_deref() {
        Some("https") => Ok(format!("https://{host}:{}", port.unwrap_or(443))),
        Some("http") if is_onion(&host) => match port {
            Some(port) => Ok(format!("http://{host}:{port}")),
            None => Err(format!("{url}: an onion server needs its port, http://<onion>:port")),
        },
        Some("http") if is_lan_host(&host) => Ok(format!("http://{host}:{}", port.unwrap_or(LAN_PORT))),
        Some("http") => Err(format!("{url}: plain http is only for onion services and servers on your network")),
        _ => Err(format!("{url}: only https servers are allowed")),
    }
}

fn host_of(url: &str) -> String {
    url.parse::<Uri>().ok().and_then(|u| u.host().map(str::to_string)).unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Route {
    pub id: String,
    pub url: String,
    pub operator: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Routes {
    pub sync: Vec<Route>,
    pub details: Vec<Route>,
    pub taddr: Vec<Route>,
    pub broadcast: Vec<Route>,
    pub mempool: Vec<Route>,
    pub tip: Vec<Route>,
    /// Two or more operators serve sync, so their answers can be compared.
    pub cross_check: bool,
}

/// Routes over the enabled servers that `usable` admits. Sync takes at most one host
/// per operator; every class alternates operators in the order they first appear.
pub fn routes(servers: &[Server], usable: impl Fn(&Server) -> bool) -> Routes {
    let pick = |class: CallClass, per_operator: usize| {
        let candidates: Vec<&Server> =
            servers.iter().filter(|s| s.enabled && s.classes.contains(&class) && usable(s)).collect();
        alternate(&candidates, per_operator)
    };
    let sync = pick(CallClass::Sync, 1);
    let operators: HashSet<String> = sync.iter().map(|r| r.operator.to_ascii_lowercase()).collect();
    Routes {
        cross_check: operators.len() >= 2,
        sync,
        details: pick(CallClass::Details, usize::MAX),
        taddr: pick(CallClass::Taddr, usize::MAX),
        broadcast: pick(CallClass::Broadcast, usize::MAX),
        mempool: pick(CallClass::Mempool, usize::MAX),
        tip: pick(CallClass::Tip, usize::MAX),
    }
}

fn alternate(candidates: &[&Server], per_operator: usize) -> Vec<Route> {
    let mut groups: Vec<(String, Vec<&Server>)> = Vec::new();
    for s in candidates {
        let key = s.operator.to_ascii_lowercase();
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, g)) => g.push(s),
            None => groups.push((key, vec![s])),
        }
    }
    let rounds = groups.iter().map(|(_, g)| g.len()).max().unwrap_or(0).min(per_operator);
    let mut out = Vec::new();
    for round in 0..rounds {
        for (_, g) in &groups {
            if let Some(s) = g.get(round) {
                out.push(Route { id: s.id.clone(), url: s.url.clone(), operator: s.operator.clone() });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(r: &[Route]) -> Vec<&str> {
        r.iter().map(|r| r.id.as_str()).collect()
    }

    fn all(_: &Server) -> bool {
        true
    }

    #[test]
    fn mainnet_two_operators() {
        let list = preset_servers(ZNetwork::Mainnet, Preset::TwoOperators).unwrap();
        validate(ZNetwork::Mainnet, &list).unwrap();
        assert_eq!(list.len(), 7);
        let enabled: Vec<&str> = list.iter().filter(|s| s.enabled).map(|s| s.id.as_str()).collect();
        assert_eq!(enabled, ["zec.rocks", "us.zec.stardust.rest"]);
        assert!(list.iter().all(|s| s.source == Source::Preset && s.classes == ALL_CLASSES && s.url.ends_with(":443")));
        let r = routes(&list, all);
        assert_eq!(ids(&r.sync), ["zec.rocks", "us.zec.stardust.rest"]);
        assert_eq!(ids(&r.tip), ["zec.rocks", "us.zec.stardust.rest"]);
        assert!(r.cross_check);
    }

    #[test]
    fn single_has_no_cross_check() {
        let single = preset_servers(ZNetwork::Mainnet, Preset::Single).unwrap();
        assert_eq!(single.iter().filter(|s| s.enabled).count(), 1);
        let r = routes(&single, all);
        assert_eq!(ids(&r.sync), ["zec.rocks"]);
        assert!(!r.cross_check);
        let t = preset_servers(ZNetwork::Testnet, Preset::Single).unwrap();
        let r = routes(&t, all);
        assert_eq!(ids(&r.sync), ["testnet.zec.rocks"]);
        assert_eq!(r.sync[0].url, "https://testnet.zec.rocks:443");
        assert!(!r.cross_check);
        // Testnet's two operators: zec.rocks, and ours behind an onion service.
        let t = preset_servers(ZNetwork::Testnet, Preset::TwoOperators).unwrap();
        let r = routes(&t, all);
        assert_eq!(r.sync.len(), 2);
        assert!(r.sync.iter().any(|s| s.url.starts_with("http://") && s.url.ends_with(".onion:9067")));
        assert!(r.cross_check);
        assert!(preset_servers(ZNetwork::Mainnet, Preset::Custom).is_none());
        assert_eq!(Preset::parse("two-operators"), Some(Preset::TwoOperators));
        assert_eq!(Preset::parse("two_operators"), None);
    }

    #[test]
    fn sync_takes_one_host_per_operator_and_alternates() {
        let mut list = preset_servers(ZNetwork::Mainnet, Preset::TwoOperators).unwrap();
        for s in &mut list {
            s.enabled = true;
        }
        list.push(Server {
            id: "mine".into(),
            url: "https://node.example:9067".into(),
            operator: "me".into(),
            label: "mine".into(),
            enabled: true,
            classes: vec![CallClass::Sync, CallClass::Tip],
            source: Source::User,
            direct: false,
        });
        let r = routes(&list, all);
        assert_eq!(ids(&r.sync), ["zec.rocks", "us.zec.stardust.rest", "mine"]);
        assert_eq!(
            ids(&r.details),
            ["zec.rocks", "us.zec.stardust.rest", "na.zec.rocks", "eu.zec.stardust.rest", "sa.zec.rocks", "eu.zec.rocks", "ap.zec.rocks"]
        );
        assert_eq!(ids(&r.tip)[..4], ["zec.rocks", "us.zec.stardust.rest", "mine", "na.zec.rocks"]);
        assert!(!ids(&r.broadcast).contains(&"mine"));
        assert!(r.cross_check);
        // An unusable host gives way to the operator's next enabled one.
        let r = routes(&list, |s| s.id != "zec.rocks");
        assert_eq!(ids(&r.sync), ["na.zec.rocks", "us.zec.stardust.rest", "mine"]);
        // Operators compare case-insensitively.
        list.iter_mut().filter(|s| s.operator == "stardust").for_each(|s| s.operator = "zec.ROCKS".into());
        list.retain(|s| s.id != "mine");
        let r = routes(&list, all);
        assert_eq!(r.sync.len(), 1);
        assert!(!r.cross_check);
    }

    #[test]
    fn list_validation() {
        let ok = r#"[{"id":"a","url":"https://A.example","operator":"x"},
                     {"id":"b","url":"https://b.example:9067","operator":"y","enabled":false,"classes":["tip","sync","tip"]}]"#;
        let list = parse_list(ZNetwork::Mainnet, ok).unwrap();
        assert_eq!(list[0].url, "https://a.example:443");
        assert_eq!(list[0].label, "a.example");
        assert_eq!(list[0].classes, ALL_CLASSES);
        assert_eq!(list[1].classes, [CallClass::Sync, CallClass::Tip]);
        assert!(list.iter().all(|s| s.source == Source::User));

        let preset = serde_json::to_string(&preset_servers(ZNetwork::Mainnet, Preset::TwoOperators).unwrap()).unwrap();
        let back = parse_list(ZNetwork::Mainnet, &preset).unwrap();
        assert_eq!(back, preset_servers(ZNetwork::Mainnet, Preset::TwoOperators).unwrap());
        // Claiming "preset" for a different server does not make it one.
        let spoof = r#"[{"id":"zec.rocks","url":"https://evil.example:443","operator":"zec.rocks","source":"preset"}]"#;
        assert_eq!(parse_list(ZNetwork::Mainnet, spoof).unwrap()[0].source, Source::User);

        for (bad, why) in [
            (r#"[{"id":"a","url":"http://a.example:9067","operator":"x"}]"#, "plain http"),
            (r#"[{"id":"a","url":"ftp://a.example:21","operator":"x"}]"#, "only https"),
            (r#"[{"id":"a","url":"https://a.example/path","operator":"x"}]"#, "https://host:port"),
            (r#"[{"id":"a","url":"https://u@a.example","operator":"x"}]"#, "https://host:port"),
            (r#"[{"id":"a","url":"https://a.example","operator":"x"},{"id":"a","url":"https://b.example","operator":"x"}]"#, "duplicate server id"),
            (r#"[{"id":"a","url":"https://a.example","operator":"x"},{"id":"b","url":"https://a.example:443","operator":"y"}]"#, "duplicate server url"),
            (r#"[{"id":"a","url":"https://a.example","operator":"x","enabled":false}]"#, "at least one server must be enabled"),
            (r#"[{"id":"a","url":"https://a.example","operator":" "}]"#, "operator"),
            (r#"[{"id":"a b","url":"https://a.example","operator":"x"}]"#, "bad server id"),
            (r#"[{"id":"a","url":"https://a.example","operator":"x","classes":[]}]"#, "call class"),
            (r#"[{"id":"a","url":"https://a.example","operator":"x","classes":["blocks"]}]"#, "server list"),
            (r#"[{"id":"a","url":"https://a.example","operator":"x","enable":true}]"#, "server list"),
            (r#"[["a","https://a.example","x"]]"#, "JSON object"),
            ("[]", "1 to 32"),
            (r#"{"servers":[]}"#, "server list"),
        ] {
            let e = parse_list(ZNetwork::Mainnet, bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn onion_servers_are_plain_http_on_every_network() {
        let onion = format!("{}.onion", "a2".repeat(28));
        for net in [ZNetwork::Mainnet, ZNetwork::Testnet, ZNetwork::Regtest] {
            let url = format!("http://{}:9067", onion.to_uppercase());
            assert_eq!(normalize_url(&url).unwrap(), format!("http://{onion}:9067"));
            assert!(normalize_url(&format!("http://{onion}")).unwrap_err().contains("needs its port"));
            assert!(parse_list(net, &format!(r#"[{{"id":"o","url":"http://{onion}:9067","operator":"x"}}]"#)).is_ok());
        }
        assert_eq!(normalize_url(&format!("{onion}:9067")).unwrap(), format!("http://{onion}:9067"));
        // A retired v2 name is not an onion service the wallet takes.
        assert!(normalize_url("http://expyuzz4wqqyqhjn.onion:80").unwrap_err().contains("plain http"));
        // The preset entry round-trips as a preset.
        let t = preset_servers(ZNetwork::Testnet, Preset::TwoOperators).unwrap();
        let ours = t.iter().find(|s| s.operator == "logos").unwrap();
        assert_eq!(normalize_url(&ours.url).unwrap(), ours.url);
        assert!(is_preset_entry(ZNetwork::Testnet, &ours.id, &ours.url, &ours.operator));
    }

    #[test]
    fn servers_on_the_users_network() {
        for (typed, url) in [
            (" HTTP://127.0.0.1:29061/ ", "http://127.0.0.1:29061"),
            ("192.168.1.20", "http://192.168.1.20:9067"),
            ("192.168.1.20:9000", "http://192.168.1.20:9000"),
            ("http://10.0.0.1", "http://10.0.0.1:9067"),
            ("https://10.0.0.1", "https://10.0.0.1:443"),
            ("Framework.LAN:9067", "http://framework.lan:9067"),
            ("[fd00::2]:9067", "http://[fd00::2]:9067"),
            ("localhost", "http://localhost:9067"),
            ("zec.rocks", "https://zec.rocks:443"),
            ("zec.rocks:9067", "https://zec.rocks:9067"),
        ] {
            assert_eq!(normalize_url(typed).unwrap(), url, "{typed}");
        }
        for typed in ["http://8.8.8.8:9067", "http://192.169.0.1:9067", "http://framework.example:9067"] {
            assert!(normalize_url(typed).unwrap_err().contains("plain http"), "{typed}");
        }
        assert!(normalize_url("http://127.0.0.1:0").is_err());
        // Tor per server: a public https server may skip it, an onion service may not.
        let direct = parse_list(ZNetwork::Mainnet, r#"[{"id":"z","url":"https://zec.rocks:443","operator":"z","direct":true}]"#).unwrap();
        assert!(direct[0].direct);
        let onion = format!(r#"[{{"id":"o","url":"http://{}.onion:9067","operator":"o","direct":true}}]"#, "a2".repeat(28));
        assert!(parse_list(ZNetwork::Mainnet, &onion).unwrap_err().contains("through Tor only"));
        for net in [ZNetwork::Mainnet, ZNetwork::Testnet, ZNetwork::Regtest] {
            let list = parse_list(net, r#"[{"id":"home","url":"192.168.1.20","operator":"me"}]"#).unwrap();
            assert_eq!((list[0].url.as_str(), list[0].label.as_str(), list[0].source), ("http://192.168.1.20:9067", "192.168.1.20", Source::User));
        }

        // Regtest has no presets: its list starts, and may stay, empty.
        assert!(preset_servers(ZNetwork::Regtest, Preset::TwoOperators).unwrap().is_empty());
        assert!(parse_list(ZNetwork::Regtest, "[]").unwrap().is_empty());
        assert!(parse_list(ZNetwork::Testnet, "[]").is_err());
        let list = parse_list(ZNetwork::Regtest, r#"[{"id":"lwd1","url":"http://127.0.0.1:29061","operator":"local"}]"#).unwrap();
        assert_eq!(routes(&list, all).sync[0].url, "http://127.0.0.1:29061");
    }
}
