//! The networks this module keeps servers for, as consensus parameters.

use serde::{Deserialize, Serialize};
use zcash_protocol::consensus::{self, BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};

/// NU7's mainnet height, set with the wallet core's override of the same name, so
/// both expect the same branch IDs.
pub const MAINNET_NU7_OVERRIDE: Option<u32> = None;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZNetwork {
    Mainnet,
    Testnet,
}

pub const NETWORKS: [ZNetwork; 2] = [ZNetwork::Mainnet, ZNetwork::Testnet];

impl ZNetwork {
    pub fn name(self) -> &'static str {
        match self {
            ZNetwork::Mainnet => "mainnet",
            ZNetwork::Testnet => "testnet",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mainnet" | "main" => Some(ZNetwork::Mainnet),
            "testnet" | "test" => Some(ZNetwork::Testnet),
            _ => None,
        }
    }

    /// The chain name lightwalletd reports in GetLightdInfo.
    pub fn lightd_chain_name(self) -> &'static str {
        match self {
            ZNetwork::Mainnet => "main",
            ZNetwork::Testnet => "test",
        }
    }

    fn inner(self) -> consensus::Network {
        match self {
            ZNetwork::Mainnet => consensus::Network::MainNetwork,
            ZNetwork::Testnet => consensus::Network::TestNetwork,
        }
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
        self.inner().network_type()
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match (self, nu, MAINNET_NU7_OVERRIDE) {
            (ZNetwork::Mainnet, NetworkUpgrade::Nu7, Some(h)) => Some(BlockHeight::from(h)),
            _ => self.inner().activation_height(nu),
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
}
