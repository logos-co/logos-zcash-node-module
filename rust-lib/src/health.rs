//! Per-server health and the overall verdict, as pure functions over poll results.

use serde::Serialize;

use crate::network::{parse_branch, ZNetwork};

/// The lowest lightwallet_protocol_version the wallet works with.
pub const MIN_PROTOCOL: (u64, u64, u64) = (0, 5, 0);
pub const WRONG_CHAIN: &str = "wrong chain";
pub const OLD_PROTOCOL: &str = "protocol below v0.5.0";
pub const BAD_BRANCH: &str = "unreadable branch id";

/// What one poll learned about one server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerHealth {
    pub reachable: bool,
    pub rtt_ms: Option<u64>,
    pub chain: Option<String>,
    pub branch_id: Option<String>,
    pub height: Option<u64>,
    pub protocol_version: Option<String>,
    pub lightwalletd_version: Option<String>,
    pub vendor: Option<String>,
    pub last_error: Option<String>,
    pub checked_at: Option<u64>,
    /// GetLightdInfo's height, which goes with its branch ID.
    #[serde(skip)]
    pub info_height: Option<u64>,
    /// Answered, but must not be routed to (wrong chain, old protocol, garbled branch).
    #[serde(skip)]
    pub incompatible: bool,
}

/// GetLightdInfo and GetLatestBlock as one poll saw them.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub chain_name: String,
    pub consensus_branch_id: String,
    pub info_height: u64,
    pub tip: u64,
    pub version: String,
    pub vendor: String,
    pub protocol_version: String,
    pub rtt_ms: u64,
}

impl ServerHealth {
    pub fn unreachable(error: impl Into<String>, now: u64) -> Self {
        Self { last_error: Some(error.into()), checked_at: Some(now), ..Self::default() }
    }

    /// Applies the per-server rules: a wrong chain is unreachable; an old protocol
    /// or a garbled branch ID is reachable but not routable.
    pub fn observed(net: ZNetwork, o: Observed, now: u64) -> Self {
        let mut h = Self {
            reachable: true,
            rtt_ms: Some(o.rtt_ms),
            chain: Some(o.chain_name),
            branch_id: Some(o.consensus_branch_id),
            height: Some(o.tip),
            protocol_version: Some(o.protocol_version),
            lightwalletd_version: Some(o.version),
            vendor: Some(o.vendor),
            last_error: None,
            checked_at: Some(now),
            info_height: Some(o.info_height),
            incompatible: false,
        };
        let problem = if h.chain.as_deref() != Some(net.lightd_chain_name()) {
            h.reachable = false;
            Some(WRONG_CHAIN)
        } else if !protocol_at_least(h.protocol_version.as_deref().unwrap_or(""), MIN_PROTOCOL) {
            Some(OLD_PROTOCOL)
        } else if h.branch_id.as_deref().and_then(parse_branch).is_none() {
            Some(BAD_BRANCH)
        } else {
            None
        };
        if let Some(p) = problem {
            h.last_error = Some(p.into());
            h.incompatible = true;
        }
        h
    }
}

/// `v0.5.0`, `0.5.0` or `v0.5.0-rc1` compare by their numbers; empty or garbled is old.
pub fn protocol_at_least(version: &str, min: (u64, u64, u64)) -> bool {
    let v = version.trim();
    let v = v.strip_prefix(['v', 'V']).unwrap_or(v);
    let mut parts = v.split('.').map(|p| p.chars().take_while(char::is_ascii_digit).collect::<String>());
    let mut num = || parts.next().and_then(|p| p.parse::<u64>().ok());
    match (num(), num(), num()) {
        (Some(a), Some(b), c) => (a, b, c.unwrap_or(0)) >= min,
        _ => false,
    }
}

/// False when the branch ID matches neither tip + 1 nor the tip itself (lightwalletd
/// reports the tip's branch, which lags one block at an activation height).
pub fn branch_ok(net: ZNetwork, h: &ServerHealth) -> bool {
    let (Some(branch), Some(height)) = (h.branch_id.as_deref().and_then(parse_branch), h.info_height.or(h.height))
    else {
        return true;
    };
    branch == net.branch_at(height + 1) || branch == net.branch_at(height)
}

/// Tips of different operators may differ by this much before they disagree:
/// 2 blocks, or 6 once the lower tip is at or above the NU7 activation height.
pub fn tip_tolerance(net: ZNetwork, lower_tip: u64) -> u64 {
    match net.nu7_height() {
        Some(nu7) if lower_tip >= nu7 => 6,
        _ => 2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Overall {
    Ok,
    Degraded,
    Disagreement,
    Offline,
    UpdateRequired,
}

/// One server as the verdict sees it. `health` is `None` until its first poll.
pub struct Row<'a> {
    pub operator: &'a str,
    pub enabled: bool,
    pub suspect: bool,
    pub health: Option<&'a ServerHealth>,
}

/// The overall verdict over the enabled servers, first rule that applies:
/// update_required, disagreement, offline, degraded, ok.
pub fn overall(net: ZNetwork, rows: &[Row]) -> Overall {
    let live: Vec<&Row> = rows.iter().filter(|r| r.enabled).collect();
    let checked: Vec<(&Row, &ServerHealth)> = live.iter().filter_map(|r| r.health.map(|h| (*r, h))).collect();
    let reachable: Vec<(&Row, &ServerHealth)> = checked.iter().copied().filter(|(_, h)| h.reachable).collect();
    if reachable.iter().any(|(_, h)| !branch_ok(net, h)) {
        return Overall::UpdateRequired;
    }
    if disagree(net, &reachable) {
        return Overall::Disagreement;
    }
    if reachable.is_empty() {
        return Overall::Offline;
    }
    let unusable = checked.iter().any(|(_, h)| !h.reachable || h.incompatible);
    if unusable || live.iter().any(|r| r.suspect) {
        return Overall::Degraded;
    }
    Overall::Ok
}

fn disagree(net: ZNetwork, reachable: &[(&Row, &ServerHealth)]) -> bool {
    reachable.iter().enumerate().any(|(i, (ra, ha))| {
        reachable[i + 1..].iter().any(|(rb, hb)| {
            if ra.operator.eq_ignore_ascii_case(rb.operator) {
                return false;
            }
            let (Some(a), Some(b)) = (ha.height, hb.height) else { return false };
            a.abs_diff(b) > tip_tolerance(net, a.min(b))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAIN_TIP: u64 = 3_500_000;
    const NU6_3: &str = "37a5165b";
    const NU7: &str = "77190ad9";
    const TEST_NU7: u64 = 4_465_026;

    fn seen(net: ZNetwork, chain: &str, branch: &str, tip: u64, protocol: &str) -> ServerHealth {
        let o = Observed {
            chain_name: chain.into(),
            consensus_branch_id: branch.into(),
            info_height: tip,
            tip,
            version: "v0.4.18".into(),
            vendor: "ECC LightWalletD".into(),
            protocol_version: protocol.into(),
            rtt_ms: 900,
        };
        ServerHealth::observed(net, o, 1_000)
    }

    fn main_at(tip: u64) -> ServerHealth {
        seen(ZNetwork::Mainnet, "main", NU6_3, tip, "v0.5.0")
    }

    fn row<'a>(operator: &'a str, h: Option<&'a ServerHealth>) -> Row<'a> {
        Row { operator, enabled: true, suspect: false, health: h }
    }

    #[test]
    fn expectations_from_zcash_protocol() {
        assert_eq!(ZNetwork::Mainnet.branch_at(MAIN_TIP + 1), 0x37a5_165b);
        assert_eq!(ZNetwork::Mainnet.nu7_height(), None);
        assert_eq!(ZNetwork::Testnet.branch_at(TEST_NU7), 0x7719_0ad9);
    }

    #[test]
    fn per_server_rules() {
        let h = main_at(MAIN_TIP);
        assert!(h.reachable && !h.incompatible && h.last_error.is_none());

        let wrong = seen(ZNetwork::Mainnet, "test", NU7, TEST_NU7 + 10, "v0.5.0");
        assert!(!wrong.reachable && wrong.incompatible);
        assert_eq!(wrong.last_error.as_deref(), Some(WRONG_CHAIN));

        for old in ["v0.4.9", "0.4.0", "", "garbage"] {
            let h = seen(ZNetwork::Mainnet, "main", NU6_3, MAIN_TIP, old);
            assert!(h.reachable && h.incompatible, "{old}");
            assert_eq!(h.last_error.as_deref(), Some(OLD_PROTOCOL));
        }
        for new in ["v0.5.0", "0.5", "v0.6.1-rc2", "v1.0.0"] {
            assert!(protocol_at_least(new, MIN_PROTOCOL), "{new}");
        }

        let garbled = seen(ZNetwork::Mainnet, "main", "zz", MAIN_TIP, "v0.5.0");
        assert_eq!(garbled.last_error.as_deref(), Some(BAD_BRANCH));
        assert!(branch_ok(ZNetwork::Mainnet, &garbled));
    }

    #[test]
    fn ok_degraded_offline() {
        let (a, b) = (main_at(MAIN_TIP), main_at(MAIN_TIP + 1));
        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", Some(&a)), row("stardust", Some(&b))]), Overall::Ok);

        let down = ServerHealth::unreachable("connect: timed out", 1_000);
        let rows = [row("zec.rocks", Some(&a)), row("stardust", Some(&down))];
        assert_eq!(overall(ZNetwork::Mainnet, &rows), Overall::Degraded);

        let mut rows = [row("zec.rocks", Some(&a)), row("stardust", Some(&b))];
        rows[1].suspect = true;
        assert_eq!(overall(ZNetwork::Mainnet, &rows), Overall::Degraded);

        let old = seen(ZNetwork::Mainnet, "main", NU6_3, MAIN_TIP, "v0.4.0");
        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", Some(&a)), row("stardust", Some(&old))]), Overall::Degraded);

        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", Some(&down)), row("stardust", Some(&down))]), Overall::Offline);
        let wrong = seen(ZNetwork::Mainnet, "test", NU7, TEST_NU7, "v0.5.0");
        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", Some(&wrong))]), Overall::Offline);

        // Disabled servers do not count; unchecked ones count only once polled.
        let mut rows = [row("zec.rocks", Some(&a)), row("stardust", Some(&down))];
        rows[1].enabled = false;
        assert_eq!(overall(ZNetwork::Mainnet, &rows), Overall::Ok);
        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", Some(&a)), row("stardust", None)]), Overall::Ok);
        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", None)]), Overall::Offline);
    }

    #[test]
    fn disagreement_between_operators() {
        let (a, far) = (main_at(MAIN_TIP), main_at(MAIN_TIP + 3));
        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", Some(&a)), row("stardust", Some(&far))]), Overall::Disagreement);
        // Within one operator a lagging host is not a disagreement.
        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", Some(&a)), row("zec.rocks", Some(&far))]), Overall::Ok);
        let near = main_at(MAIN_TIP + 2);
        assert_eq!(overall(ZNetwork::Mainnet, &[row("zec.rocks", Some(&a)), row("stardust", Some(&near))]), Overall::Ok);

        // Above NU7 the tolerance is 6 blocks; below it, still 2.
        let t = |tip| seen(ZNetwork::Testnet, "test", NU7, tip, "v0.5.0");
        let (x, y) = (t(TEST_NU7 + 10), t(TEST_NU7 + 16));
        assert_eq!(overall(ZNetwork::Testnet, &[row("p", Some(&x)), row("q", Some(&y))]), Overall::Ok);
        let z = t(TEST_NU7 + 17);
        assert_eq!(overall(ZNetwork::Testnet, &[row("p", Some(&x)), row("q", Some(&z))]), Overall::Disagreement);
        let before = seen(ZNetwork::Testnet, "test", "37a5165b", TEST_NU7 - 3, "v0.5.0");
        let after = t(TEST_NU7 + 1);
        assert_eq!(overall(ZNetwork::Testnet, &[row("p", Some(&before)), row("q", Some(&after))]), Overall::Disagreement);
    }

    #[test]
    fn update_required_on_unexpected_branch() {
        // Mainnet has no NU7 in this build, so a server already on it means we are behind.
        let ahead = seen(ZNetwork::Mainnet, "main", NU7, MAIN_TIP, "v0.5.0");
        let a = main_at(MAIN_TIP);
        let rows = [row("zec.rocks", Some(&a)), row("stardust", Some(&ahead))];
        assert_eq!(overall(ZNetwork::Mainnet, &rows), Overall::UpdateRequired);
        // It outranks disagreement and degraded.
        let far = seen(ZNetwork::Mainnet, "main", NU7, MAIN_TIP + 50, "v0.5.0");
        let down = ServerHealth::unreachable("x", 1);
        let rows = [row("zec.rocks", Some(&a)), row("stardust", Some(&far)), row("other", Some(&down))];
        assert_eq!(overall(ZNetwork::Mainnet, &rows), Overall::UpdateRequired);
        // Testnet past NU7 must report 77190ad9 at tip + 1; the tip's own branch passes too.
        let fine = seen(ZNetwork::Testnet, "test", NU7, TEST_NU7 + 100, "v0.5.0");
        assert!(branch_ok(ZNetwork::Testnet, &fine));
        let edge = seen(ZNetwork::Testnet, "test", "37a5165b", TEST_NU7 - 1, "v0.5.0");
        assert!(branch_ok(ZNetwork::Testnet, &edge));
        let stale = seen(ZNetwork::Testnet, "test", "37a5165b", TEST_NU7 + 100, "v0.5.0");
        assert_eq!(overall(ZNetwork::Testnet, &[row("zec.rocks", Some(&stale))]), Overall::UpdateRequired);
    }
}
