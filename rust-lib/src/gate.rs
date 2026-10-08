//! Who may call what: reads are open, mutations take the wallet backend, and the route
//! table and mismatch reports also take the wallet core. `callers.json` widens it for tests.

use serde::Deserialize;

pub const BACKEND: &str = "zcash_wallet_backend";
pub const CORE: &str = "zcash_wallet_core_module";

/// What a method requires of its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Open,
    Backend,
    BackendOrCore,
}

/// The caller as the host reported it, mirrored so this file needs no SDK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Unknown,
    Host,
    Module(String),
    Other,
}

/// Callers admitted beyond the defaults, to every gated method.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Callers {
    #[serde(default)]
    pub modules: Vec<String>,
    /// Admits calls that carry a host anchor, such as `logosctl call`.
    #[serde(default)]
    pub allow_host: bool,
}

impl Callers {
    /// Absent or unreadable file: the defaults only, so a typo never opens the door.
    pub fn from_file(contents: Option<&str>) -> Self {
        contents.and_then(|t| serde_json::from_str(t).ok()).unwrap_or_default()
    }

    pub fn admits(&self, access: Access, caller: &Caller) -> bool {
        if access == Access::Open {
            return true;
        }
        match caller {
            Caller::Module(name) if !name.is_empty() => {
                name == BACKEND
                    || (access == Access::BackendOrCore && name == CORE)
                    || self.modules.iter().any(|m| m == name)
            }
            Caller::Host => self.allow_host,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str) -> Caller {
        Caller::Module(name.into())
    }

    #[test]
    fn defaults() {
        let c = Callers::default();
        for who in [m(BACKEND), m(CORE), m("zcash_wallet_ui"), Caller::Host, Caller::Unknown, Caller::Other] {
            assert!(c.admits(Access::Open, &who));
        }
        assert!(c.admits(Access::Backend, &m(BACKEND)));
        assert!(!c.admits(Access::Backend, &m(CORE)));
        assert!(c.admits(Access::BackendOrCore, &m(BACKEND)));
        assert!(c.admits(Access::BackendOrCore, &m(CORE)));
        for who in [m("zcash_wallet_ui"), m(""), Caller::Host, Caller::Unknown, Caller::Other] {
            assert!(!c.admits(Access::Backend, &who), "{who:?}");
            assert!(!c.admits(Access::BackendOrCore, &who), "{who:?}");
        }
    }

    #[test]
    fn file_widens_every_gated_method() {
        let c = Callers::from_file(Some(r#"{"modules":["probe"],"allowHost":true}"#));
        for a in [Access::Backend, Access::BackendOrCore] {
            assert!(c.admits(a, &m("probe")) && c.admits(a, &Caller::Host) && c.admits(a, &m(BACKEND)));
            assert!(!c.admits(a, &Caller::Unknown) && !c.admits(a, &m("other")));
        }
        assert!(!c.admits(Access::Backend, &m(CORE)));
    }

    #[test]
    fn unreadable_file_admits_only_the_defaults() {
        assert_eq!(Callers::from_file(None), Callers::default());
        for text in [r#"{"modules":["probe"],"typo":1}"#, "not json", r#"{"allowHost":"yes"}"#] {
            let c = Callers::from_file(Some(text));
            assert_eq!(c, Callers::default(), "{text}");
            assert!(!c.admits(Access::Backend, &m("probe")) && !c.admits(Access::Backend, &Caller::Host));
            assert!(c.admits(Access::Backend, &m(BACKEND)));
        }
    }
}
