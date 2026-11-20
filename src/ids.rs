//! Mastodon account IDs, kept as unpadded decimal strings.

use anyhow::{Result, bail};

/// Numeric order for unpadded decimal strings, without parsing.
pub fn numeric_id_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// IDs go into URL paths and Redis keys, so only ASCII digits are accepted.
pub fn is_numeric_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit())
}

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
