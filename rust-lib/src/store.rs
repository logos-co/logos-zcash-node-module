//! What persists, per network: the preset, the servers, the proxy and the suspects.
//! Written atomically to `<instance_persistence_path>/zcash_servers.json`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::network::{networks, ZNetwork};
use crate::proxy::{self, DEFAULT_PROXY};
use crate::servers::{self, preset_servers, Preset, Server, Source};

pub const FILE_NAME: &str = "zcash_servers.json";
pub const VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Suspicion {
    pub kind: String,
    pub height: u64,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetConfig {
    pub preset: Preset,
    pub servers: Vec<Server>,
    pub proxy: Option<String>,
    pub proxy_required: bool,
    /// By server id.
    #[serde(default)]
    pub suspects: BTreeMap<String, Suspicion>,
    /// Reads go to the local node (zebrad_module) over IPC; broadcasts stay on the servers.
    #[serde(default)]
    pub local_node: bool,
    /// The preset hosts this list has been offered, so each new one is offered once.
    #[serde(default)]
    pub presets_seen: Vec<String>,
}

fn preset_ids(net: ZNetwork) -> Vec<String> {
    preset_servers(net, Preset::TwoOperators).unwrap_or_default().into_iter().map(|s| s.id).collect()
}

impl NetConfig {
    pub fn seeded(net: ZNetwork) -> Self {
        // Regtest has no presets and no default proxy: the test harness sets both.
        if net == ZNetwork::Regtest {
            return Self { preset: Preset::Custom, servers: vec![], proxy: None, proxy_required: false, suspects: BTreeMap::new(), local_node: false, presets_seen: vec![] };
        }
        Self {
            preset: Preset::TwoOperators,
            servers: preset_servers(net, Preset::TwoOperators).unwrap_or_default(),
            proxy: Some(DEFAULT_PROXY.into()),
            proxy_required: true,
            suspects: BTreeMap::new(),
            local_node: false,
            presets_seen: preset_ids(net),
        }
    }

    pub fn server(&self, id: &str) -> Option<&Server> {
        self.servers.iter().find(|s| s.id == id)
    }

    /// Replaces the list, keeping only the suspicions of servers still at the same url.
    pub fn replace_servers(&mut self, servers: Vec<Server>) {
        let old = std::mem::replace(&mut self.servers, servers);
        let same = |id: &str| {
            let was = old.iter().find(|s| s.id == id).map(|s| &s.url);
            was.is_some() && was == self.servers.iter().find(|s| s.id == id).map(|s| &s.url)
        };
        self.suspects.retain(|id, _| same(id));
    }

    /// Drops the preset servers this release no longer ships; the user's own stay. Some
    /// server is left enabled, as every list needs one.
    pub fn retire_presets(&mut self, net: ZNetwork) -> bool {
        let mut kept = self.servers.clone();
        kept.retain(|s| s.source == Source::User || servers::is_preset_host(net, &s.id));
        if kept.len() == self.servers.len() {
            return false;
        }
        if kept.is_empty() {
            kept = preset_servers(net, Preset::TwoOperators).unwrap_or_default();
        } else if !kept.iter().any(|s| s.enabled) {
            kept[0].enabled = true;
        }
        self.replace_servers(kept);
        true
    }

    /// A preset replaces the list; servers the user added stay, disabled, and the user's
    /// choice of Tor for a preset server outlives the preset. `custom` keeps the list.
    pub fn apply_preset(&mut self, net: ZNetwork, preset: Preset) {
        if let Some(mut list) = preset_servers(net, preset) {
            for p in list.iter_mut() {
                p.direct = self.servers.iter().any(|s| s.id == p.id && s.url == p.url && s.direct);
            }
            for s in self.servers.iter().filter(|s| s.source == Source::User) {
                if list.len() < servers::MAX_SERVERS && !list.iter().any(|p| p.id == s.id || p.url == s.url) {
                    list.push(Server { enabled: false, ..s.clone() });
                }
            }
            self.replace_servers(list);
            self.presets_seen = preset_ids(net);
        }
        self.preset = preset;
    }

    /// Offers each preset host this release adds once. A list still on a preset follows
    /// it; a custom list gets the new hosts switched off, while it has room.
    pub fn adopt_presets(&mut self, net: ZNetwork) -> bool {
        let ids = preset_ids(net);
        if ids == self.presets_seen {
            return false;
        }
        if ids.iter().any(|id| !self.presets_seen.contains(id)) {
            if self.preset != Preset::Custom {
                self.apply_preset(net, self.preset);
            } else {
                let new = preset_servers(net, Preset::TwoOperators).unwrap_or_default();
                for mut s in new.into_iter().filter(|s| !self.presets_seen.contains(&s.id)) {
                    let taken = self.servers.iter().any(|x| x.id == s.id || x.url == s.url);
                    if !taken && self.servers.len() < servers::MAX_SERVERS {
                        s.enabled = false;
                        self.servers.push(s);
                    }
                }
            }
        }
        self.presets_seen = ids;
        true
    }

    pub fn validate(&self, net: ZNetwork) -> Result<(), String> {
        servers::validate(net, &self.servers)?;
        if let Some(p) = &self.proxy {
            if proxy::normalize(p)? != *p {
                return Err(format!("proxy {p} is not normalized"));
            }
        }
        match self.suspects.keys().find(|id| self.server(id).is_none()) {
            Some(id) => Err(format!("suspect {id} is not a server")),
            None => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Store {
    pub version: u32,
    pub networks: BTreeMap<ZNetwork, NetConfig>,
}

pub enum Loaded {
    Absent,
    Found(Store),
    Corrupt(String),
}

impl Store {
    pub fn seeded() -> Self {
        Self { version: VERSION, networks: networks().into_iter().map(|n| (n, NetConfig::seeded(n))).collect() }
    }

    /// Reads the file; a network missing from it gets its presets, and regtest is
    /// dropped unless it is configured.
    pub fn load(path: &Path) -> Loaded {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Absent,
            Err(e) => return Loaded::Corrupt(e.to_string()),
        };
        let mut store: Store = match serde_json::from_str(&text) {
            Ok(s) => s,
            Err(e) => return Loaded::Corrupt(e.to_string()),
        };
        if !(1..=VERSION).contains(&store.version) {
            return Loaded::Corrupt(format!("unknown version {}", store.version));
        }
        let kept = networks();
        store.networks.retain(|net, _| kept.contains(net));
        for (net, cfg) in &store.networks {
            if let Err(e) = cfg.validate(*net) {
                return Loaded::Corrupt(format!("{}: {e}", net.name()));
            }
        }
        for net in kept {
            store.networks.entry(net).or_insert_with(|| NetConfig::seeded(net));
        }
        Loaded::Found(store)
    }

    /// Writes `<file>.tmp`, syncs it, then renames it over the file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = tmp_path(path);
        let body = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    }

    /// Version 1 seeded a Tor the user had to run; the built-in one takes its place, once.
    pub fn upgrade(&mut self) -> bool {
        if self.version == VERSION {
            return false;
        }
        for cfg in self.networks.values_mut() {
            if cfg.proxy.as_deref() == Some(proxy::OLD_DEFAULT_PROXY) {
                cfg.proxy = Some(proxy::BUILT_IN.into());
            }
        }
        self.version = VERSION;
        true
    }

    /// Loads the file, or seeds the presets when it is absent. A corrupt file is kept
    /// aside as `<file>.corrupt` and replaced by the presets. An older file is upgraded,
    /// retired presets are dropped, new ones are offered once, and the file is rewritten.
    pub fn load_or_seed(path: &Path) -> Self {
        let store = match Self::load(path) {
            Loaded::Found(mut s) => {
                let mut changed = s.upgrade();
                for (net, cfg) in s.networks.iter_mut() {
                    changed |= cfg.retire_presets(*net);
                    changed |= cfg.adopt_presets(*net);
                }
                if !changed {
                    return s;
                }
                s
            }
            Loaded::Absent => Self::seeded(),
            Loaded::Corrupt(why) => {
                eprintln!("zcash_node_module: {} is unusable ({why}); seeding the presets", path.display());
                let _ = std::fs::rename(path, corrupt_path(path));
                Self::seeded()
            }
        };
        if let Err(e) = store.save(path) {
            eprintln!("zcash_node_module: writing {}: {e}", path.display());
        }
        store
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

pub fn tmp_path(path: &Path) -> PathBuf {
    with_suffix(path, ".tmp")
}

pub fn corrupt_path(path: &Path) -> PathBuf {
    with_suffix(path, ".corrupt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::servers::{CallClass, Source};

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join(FILE_NAME);
        assert!(matches!(Store::load(&path), Loaded::Absent));

        let mut store = Store::seeded();
        let main = store.networks.get_mut(&ZNetwork::Mainnet).unwrap();
        main.preset = Preset::Custom;
        main.servers.push(Server {
            id: "mine".into(),
            url: "https://node.example:9067".into(),
            operator: "me".into(),
            label: "Mine".into(),
            enabled: false,
            classes: vec![CallClass::Tip],
            source: Source::User,
            direct: true,
        });
        main.suspects.insert("zec.rocks".into(), Suspicion { kind: "block_hash".into(), height: 7, at: 9 });
        let test = store.networks.get_mut(&ZNetwork::Testnet).unwrap();
        test.proxy = None;
        test.proxy_required = false;

        store.save(&path).unwrap();
        assert!(!tmp_path(&path).exists());
        match Store::load(&path) {
            Loaded::Found(back) => assert_eq!(back, store),
            _ => panic!("reload failed"),
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"mainnet\"") && text.contains("\"two-operators\"") && text.contains("\"proxyRequired\""));
    }

    #[test]
    fn missing_network_is_seeded_and_bad_files_are_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let only_main = Store { version: VERSION, networks: [(ZNetwork::Mainnet, NetConfig::seeded(ZNetwork::Mainnet))].into() };
        only_main.save(&path).unwrap();
        match Store::load(&path) {
            Loaded::Found(s) => assert_eq!(s, Store::seeded()),
            _ => panic!("expected a store"),
        }

        let mut bad = Store::seeded();
        bad.networks.get_mut(&ZNetwork::Mainnet).unwrap().servers[0].url = "http://zec.rocks:443".into();
        bad.save(&path).unwrap();
        assert!(matches!(Store::load(&path), Loaded::Corrupt(e) if e.contains("plain http")));
        let mut socks = Store::seeded();
        socks.networks.get_mut(&ZNetwork::Testnet).unwrap().proxy = Some("socks5://127.0.0.1:9050".into());
        socks.save(&path).unwrap();
        assert!(matches!(Store::load(&path), Loaded::Corrupt(_)));

        std::fs::write(&path, "{ not json").unwrap();
        assert_eq!(Store::load_or_seed(&path), Store::seeded());
        assert_eq!(std::fs::read_to_string(corrupt_path(&path)).unwrap(), "{ not json");
        assert!(matches!(Store::load(&path), Loaded::Found(_)));
    }

    #[test]
    fn regtest_is_dropped_unless_configured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let mut store = Store::seeded();
        let regtest = NetConfig { proxy: Some(proxy::DIRECT.into()), ..NetConfig::seeded(ZNetwork::Regtest) };
        regtest.validate(ZNetwork::Regtest).unwrap();
        store.networks.insert(ZNetwork::Regtest, regtest);
        store.save(&path).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains("\"regtest\""));
        // No unit test configures regtest, so the entry is left out, not taken as corrupt.
        match Store::load(&path) {
            Loaded::Found(s) => assert_eq!(s, Store::seeded()),
            _ => panic!("expected a store"),
        }
    }

    #[test]
    fn suspicions_follow_the_server_url() {
        let mut cfg = NetConfig::seeded(ZNetwork::Mainnet);
        cfg.suspects.insert("zec.rocks".into(), Suspicion { kind: "k".into(), height: 1, at: 1 });
        cfg.suspects.insert("us.zec.stardust.rest".into(), Suspicion { kind: "k".into(), height: 1, at: 1 });
        let mut list = cfg.servers.clone();
        list[0].enabled = false;
        list.retain(|s| s.id != "us.zec.stardust.rest");
        cfg.replace_servers(list.clone());
        assert_eq!(cfg.suspects.keys().collect::<Vec<_>>(), ["zec.rocks"]);
        list[0].url = "https://elsewhere.example:443".into();
        cfg.replace_servers(list);
        assert!(cfg.suspects.is_empty());
    }

    #[test]
    fn retired_presets_are_dropped_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let (gone, mine) = (format!("{}.onion", "a2".repeat(28)), format!("{}.onion", "b3".repeat(28)));
        let entry = |id: &str, host: &str, source, enabled| Server {
            id: id.into(),
            url: format!("http://{host}:9067"),
            operator: "x".into(),
            label: id.into(),
            enabled,
            classes: vec![CallClass::Sync],
            source,
            direct: false,
        };
        // An earlier release's list the user changed: a preset it shipped, the only server in
        // use, beside the user's own onion, and without the presets this release adds.
        let mut store = Store::seeded();
        let test = store.networks.get_mut(&ZNetwork::Testnet).unwrap();
        (test.preset, test.presets_seen) = (Preset::Custom, vec![]);
        test.servers.truncate(1);
        test.servers[0].enabled = false;
        test.servers.push(entry(&gone, &gone, Source::Preset, true));
        test.servers.push(entry("mine", &mine, Source::User, false));
        test.suspects.insert(gone.clone(), Suspicion { kind: "k".into(), height: 1, at: 1 });
        store.save(&path).unwrap();

        let back = Store::load_or_seed(&path);
        let test = &back.networks[&ZNetwork::Testnet];
        let ids: Vec<_> = test.servers.iter().map(|s| (s.id.as_str(), s.enabled)).collect();
        let onion = "y64fwlthmsgxs7v4j37bv2spsp73vmfks5ypadelwyqr5cumenlt7cad.onion";
        assert_eq!(ids, [("testnet.zec.rocks", true), ("mine", false), ("tl.ombie.cash", false), (onion, false)]);
        assert!(test.suspects.is_empty());
        assert!(!std::fs::read_to_string(&path).unwrap().contains(&gone));
        assert!(matches!(Store::load(&path), Loaded::Found(s) if s == back));

        // A version 1 file on the old default moves to the built-in Tor, once; a proxy the user
        // chose stays.
        let mut old = Store::seeded();
        old.version = 1;
        old.networks.get_mut(&ZNetwork::Mainnet).unwrap().proxy = Some(proxy::OLD_DEFAULT_PROXY.into());
        old.networks.get_mut(&ZNetwork::Testnet).unwrap().proxy = Some("socks5h://127.0.0.1:9150".into());
        old.save(&path).unwrap();
        let up = Store::load_or_seed(&path);
        assert_eq!(up.version, VERSION);
        assert_eq!(up.networks[&ZNetwork::Mainnet].proxy.as_deref(), Some(proxy::BUILT_IN));
        assert_eq!(up.networks[&ZNetwork::Testnet].proxy.as_deref(), Some("socks5h://127.0.0.1:9150"));
        let mut chosen = up.clone();
        chosen.networks.get_mut(&ZNetwork::Mainnet).unwrap().proxy = Some(proxy::OLD_DEFAULT_PROXY.into());
        chosen.save(&path).unwrap();
        assert_eq!(Store::load_or_seed(&path), chosen);

        // A list of nothing else falls back to the presets.
        let mut only = NetConfig::seeded(ZNetwork::Testnet);
        only.servers = vec![entry(&gone, &gone, Source::Preset, true)];
        assert!(only.retire_presets(ZNetwork::Testnet));
        assert_eq!(only.servers, preset_servers(ZNetwork::Testnet, Preset::TwoOperators).unwrap());
        assert!(!only.retire_presets(ZNetwork::Testnet));
    }

    #[test]
    fn each_new_preset_is_offered_once() {
        // Lists from the release before Cake Wallet and ZombieCash, which kept no presetsSeen.
        let earlier = |net, preset| {
            let mut cfg = NetConfig::seeded(net);
            cfg.servers.retain(|s| !["Cake Wallet", "ZombieCash"].contains(&s.operator.as_str()));
            (cfg.preset, cfg.presets_seen) = (preset, vec![]);
            cfg
        };
        // A list still on its preset follows it, keeping the user's Tor choice.
        let mut t = earlier(ZNetwork::Testnet, Preset::TwoOperators);
        t.servers[0].direct = true;
        assert!(t.adopt_presets(ZNetwork::Testnet));
        let got: Vec<_> = t.servers.iter().map(|s| (s.id.as_str(), s.enabled, s.direct)).collect();
        let onion = "y64fwlthmsgxs7v4j37bv2spsp73vmfks5ypadelwyqr5cumenlt7cad.onion";
        assert_eq!(got, [("testnet.zec.rocks", true, true), ("tl.ombie.cash", true, false), (onion, false, false)]);
        assert!(!t.adopt_presets(ZNetwork::Testnet));
        let mut single = earlier(ZNetwork::Testnet, Preset::Single);
        single.adopt_presets(ZNetwork::Testnet);
        assert_eq!(single.servers.iter().filter(|s| s.enabled).count(), 1);

        // A list the user changed keeps their choices; the new host joins switched off.
        let mut m = earlier(ZNetwork::Mainnet, Preset::Custom);
        m.servers[0].enabled = false;
        m.servers[1].enabled = true;
        let before = m.servers.clone();
        assert!(m.adopt_presets(ZNetwork::Mainnet));
        assert_eq!(m.servers[..before.len()], before[..]);
        let cake = m.servers.last().unwrap();
        assert_eq!((cake.id.as_str(), cake.enabled, cake.source), ("zec-node.cakewallet.com", false, Source::Preset));
        m.validate(ZNetwork::Mainnet).unwrap();
        // Offered once: a preset host the user removes stays removed.
        m.servers.retain(|s| s.id != "zec-node.cakewallet.com");
        assert!(!m.adopt_presets(ZNetwork::Mainnet));

        // A url the user already added stays theirs; a full list takes nothing.
        let user = |id: &str, url: &str| Server {
            id: id.into(),
            url: url.into(),
            operator: "me".into(),
            label: id.into(),
            enabled: true,
            classes: vec![CallClass::Sync],
            source: Source::User,
            direct: false,
        };
        let mut mine = earlier(ZNetwork::Mainnet, Preset::Custom);
        mine.servers.push(user("cake", "https://zec-node.cakewallet.com:443"));
        let before = mine.servers.clone();
        mine.adopt_presets(ZNetwork::Mainnet);
        assert_eq!(mine.servers, before);
        let mut full = earlier(ZNetwork::Mainnet, Preset::Custom);
        for i in full.servers.len()..servers::MAX_SERVERS {
            full.servers.push(user(&format!("s{i}"), &format!("https://s{i}.example:443")));
        }
        let before = full.servers.clone();
        full.adopt_presets(ZNetwork::Mainnet);
        assert_eq!(full.servers, before);
        full.validate(ZNetwork::Mainnet).unwrap();
        assert!(!NetConfig::seeded(ZNetwork::Regtest).adopt_presets(ZNetwork::Regtest));
    }
}
