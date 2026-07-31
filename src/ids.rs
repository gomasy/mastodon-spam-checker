//! Mastodon account IDs.
//!
//! IDs arrive as decimal strings and are kept that way: they are snowflake-style values that
//! already exceed what a signed 32-bit integer holds, and every consumer (URL paths, Redis keys,
//! cursors) needs the string form anyway. Ordering and validation therefore work on the digits.

use anyhow::{Result, bail};

/// Orders two decimal ID strings numerically without parsing them.
///
/// Plain lexicographic order would sort `"100"` before `"20"`; comparing length first restores
/// numeric order for the unpadded decimal strings Mastodon emits.
pub fn numeric_id_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Whether `id` is a non-empty run of ASCII digits.
///
/// IDs are interpolated into Mastodon API paths and Redis keys, so anything else is rejected
/// before it can steer a request at a different endpoint or key.
pub fn is_numeric_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
}

/// [`is_numeric_id`] as a `Result`, for call sites that surface the failure to a user.
pub fn validate_account_id(id: &str) -> Result<()> {
    if !is_numeric_id(id) {
        bail!("account ID must contain digits only");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_ids_are_ordered_without_integer_conversion() {
        let mut ids = vec!["20".to_string(), "3".to_string(), "100".to_string()];
        ids.sort_by(|a, b| numeric_id_cmp(a, b));
        assert_eq!(ids, ["3", "20", "100"]);
    }

    #[test]
    fn account_ids_are_numeric() {
        assert!(validate_account_id("123").is_ok());
        assert!(validate_account_id("12/action").is_err());
        assert!(validate_account_id("").is_err());
        assert!(!is_numeric_id("１２３"), "full-width digits are not ASCII");
    }
}
