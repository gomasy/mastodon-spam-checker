/// Shortens `s` to at most `max_chars` characters, marking a cut with a trailing ellipsis.
pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if s.char_indices().nth(max_chars).is_none() {
        return s.to_string();
    }
    let mut truncated: String = s.chars().take(max_chars - 1).collect();
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_chars_keeps_short_strings() {
        assert_eq!(truncate_chars("abc", 3), "abc");
        assert_eq!(truncate_chars("", 10), "");
    }

    #[test]
    fn truncate_chars_truncates_by_chars_not_bytes() {
        assert_eq!(truncate_chars("あいうえお", 3), "あい…");
        assert_eq!(truncate_chars("あいうえお", 3).chars().count(), 3);
        assert_eq!(truncate_chars("abc", 0), "");
    }

    #[test]
    fn truncate_chars_is_exact_at_the_boundary() {
        assert_eq!(truncate_chars("あいう", 3), "あいう");
        assert_eq!(truncate_chars("あいうえ", 3), "あい…");
        assert_eq!(truncate_chars("a", 1), "a");
        assert_eq!(truncate_chars("ab", 1), "…");
    }
}
