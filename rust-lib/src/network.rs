//! The networks this module keeps servers for, as consensus parameters.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use zcash_protocol::consensus::{self, BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

/// NU7's mainnet height, set with the wallet core's override of the same name, so
/// both expect the same branch IDs.
pub const MAINNET_NU7_OVERRIDE: Option<u32> = None;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZNetwork {
    Mainnet,
    Testnet,
    /// A local test chain; its upgrade heights come from `regtest.json`. Test harnesses only.
    Regtest,
}

pub const NETWORKS: [ZNetwork; 2] = [ZNetwork::Mainnet, ZNetwork::Testnet];

/// Upgrade heights for regtest, as the wallet core reads them from `regtest.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RegtestHeights {
    pub overwinter: Option<u32>,
    pub sapling: Option<u32>,
    pub blossom: Option<u32>,
    pub heartwood: Option<u32>,
    pub canopy: Option<u32>,
    pub nu5: Option<u32>,
    pub nu6: Option<u32>,
    pub nu6_1: Option<u32>,
    pub nu6_2: Option<u32>,
    pub nu6_3: Option<u32>,
    pub nu7: Option<u32>,
}

static REGTEST: OnceLock<LocalNetwork> = OnceLock::new();

/// Sets the regtest upgrade heights once per process, before the node opens; later calls
/// are ignored.
pub fn configure_regtest(h: &RegtestHeights) {
    let b = |v: Option<u32>| v.map(BlockHeight::from);
    let _ = REGTEST.set(LocalNetwork {
        overwinter: b(h.overwinter),
        sapling: b(h.sapling),
        blossom: b(h.blossom),
        heartwood: b(h.heartwood),
        canopy: b(h.canopy),
        nu5: b(h.nu5),
        nu6: b(h.nu6),
        nu6_1: b(h.nu6_1),
        nu6_2: b(h.nu6_2),
        nu6_3: b(h.nu6_3),
        nu7: b(h.nu7),
    });
}

pub fn regtest_configured() -> bool {
    REGTEST.get().is_some()
}

/// The networks kept: mainnet and testnet, and regtest once configured.
pub fn networks() -> Vec<ZNetwork> {
    let mut out = NETWORKS.to_vec();
    if regtest_configured() {
        out.push(ZNetwork::Regtest);
    }
    out
}

impl ZNetwork {
    pub fn name(self) -> &'static str {
        match self {
            ZNetwork::Mainnet => "mainnet",
            ZNetwork::Testnet => "testnet",
            ZNetwork::Regtest => "regtest",
        }
    }

    /// Regtest only parses once its heights are configured.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mainnet" | "main" => Some(ZNetwork::Mainnet),
            "testnet" | "test" => Some(ZNetwork::Testnet),
            "regtest" if regtest_configured() => Some(ZNetwork::Regtest),
            _ => None,
        }
    }

    /// The chain name lightwalletd reports in GetLightdInfo.
    pub fn lightd_chain_name(self) -> &'static str {
        match self {
            ZNetwork::Mainnet => "main",
            ZNetwork::Testnet => "test",
            ZNetwork::Regtest => "regtest",
        }
    }

    /// Whether a server's reported chain name fits. Zebra names regtest "test", zcashd "regtest".
    pub fn accepts_lightd_chain(self, name: &str) -> bool {
        name == self.lightd_chain_name() || (self == ZNetwork::Regtest && name == "test")
    }

    /// The consensus branch ID this build expects at `height`.
    pub fn branch_at(self, height: u64) -> u32 {
        let h = BlockHeight::from(u32::try_from(height).unwrap_or(u32::MAX));
        u32::from(BranchId::for_height(&self, h))
    }

    pub fn nu7_height(self) -> Option<u64> {
        self.activation_height(NetworkUpgrade::Nu7).map(|h| u64::from(u32::from(h)))
    }
}

impl Parameters for ZNetwork {
    fn network_type(&self) -> NetworkType {
        match self {
            ZNetwork::Mainnet => NetworkType::Main,
            ZNetwork::Testnet => NetworkType::Test,
            ZNetwork::Regtest => NetworkType::Regtest,
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match (self, nu, MAINNET_NU7_OVERRIDE) {
            (ZNetwork::Mainnet, NetworkUpgrade::Nu7, Some(h)) => Some(BlockHeight::from(h)),
            (ZNetwork::Mainnet, _, _) => consensus::Network::MainNetwork.activation_height(nu),
            (ZNetwork::Testnet, _, _) => consensus::Network::TestNetwork.activation_height(nu),
            (ZNetwork::Regtest, _, _) => REGTEST.get().and_then(|l| l.activation_height(nu)),
        }
    }
}

/// Parses a branch ID as lightwalletd prints it ("77190ad9", optionally 0x-prefixed).
pub fn parse_branch(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    if t.is_empty() || t.len() > 8 {
        return None;
    }
    u32::from_str_radix(t, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet_nu7() {
        assert_eq!(ZNetwork::Testnet.nu7_height(), Some(4_465_026));
        assert_eq!(ZNetwork::Testnet.branch_at(4_465_026), 0x7719_0ad9);
        assert_ne!(ZNetwork::Testnet.branch_at(4_465_025), 0x7719_0ad9);
        assert_eq!(parse_branch("77190ad9"), Some(0x7719_0ad9));
        assert_eq!(parse_branch("0x77190AD9"), Some(0x7719_0ad9));
        assert_eq!(parse_branch("nope"), None);
    }

    #[test]
    fn mainnet_nu7_is_unset() {
        assert_eq!(MAINNET_NU7_OVERRIDE, None);
        assert_eq!(ZNetwork::Mainnet.nu7_height(), None);
    }

    #[test]
    fn names() {
        assert_eq!(ZNetwork::parse("main"), Some(ZNetwork::Mainnet));
        assert_eq!(ZNetwork::parse("testnet").map(ZNetwork::lightd_chain_name), Some("test"));
        assert_eq!(ZNetwork::parse("regtest"), None);
        assert_eq!(serde_json::to_string(&ZNetwork::Mainnet).unwrap(), "\"mainnet\"");
    }

    #[test]
    fn regtest_is_refused_until_configured() {
        // Heights are per process: no unit test sets them, tests/regtest.rs does.
        assert!(!regtest_configured());
        assert_eq!(ZNetwork::parse("regtest"), None);
        assert_eq!(networks(), NETWORKS);
        assert_eq!(ZNetwork::Regtest.nu7_height(), None);
        assert_eq!(serde_json::to_string(&ZNetwork::Regtest).unwrap(), "\"regtest\"");
    }

    #[test]
    fn chain_names() {
        assert!(ZNetwork::Regtest.accepts_lightd_chain("test") && ZNetwork::Regtest.accepts_lightd_chain("regtest"));
        assert!(ZNetwork::Testnet.accepts_lightd_chain("test") && !ZNetwork::Testnet.accepts_lightd_chain("regtest"));
        assert!(ZNetwork::Mainnet.accepts_lightd_chain("main") && !ZNetwork::Mainnet.accepts_lightd_chain("test"));
    }
}
