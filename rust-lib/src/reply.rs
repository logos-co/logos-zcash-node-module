//! Replies cross as flat JSON strings: `{"ok":true,...}` or `{"ok":false,"error":"..."}`.

use serde_json::Value;

pub const NOT_AUTHORIZED: &str = r#"{"ok":false,"error":"not authorized"}"#;

/// `{"ok":true}` followed by the fields of `fields`, which must be an object.
pub fn ok(fields: Value) -> String {
    let mut out = String::from("{\"ok\":true");
    if let Value::Object(map) = fields {
        for (k, v) in map {
            out.push(',');
            out.push_str(&Value::String(k).to_string());
            out.push(':');
            out.push_str(&v.to_string());
        }
    }
    out.push('}');
    out
}

pub fn err(msg: impl std::fmt::Display) -> String {
    format!("{{\"ok\":false,\"error\":{}}}", Value::String(msg.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn shapes() {
        assert_eq!(ok(json!({"b": 1, "a": "x"})), r#"{"ok":true,"a":"x","b":1}"#);
        assert_eq!(ok(json!({})), r#"{"ok":true}"#);
        assert_eq!(err("no \"proxy\""), r#"{"ok":false,"error":"no \"proxy\""}"#);
        let v: Value = serde_json::from_str(NOT_AUTHORIZED).unwrap();
        assert_eq!(v, json!({"ok": false, "error": "not authorized"}));
    }
}
