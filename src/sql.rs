/// Splits SQL on top-level `;`, honouring quotes, dollar quotes and comments.
/// Statements holding nothing but whitespace and comments are dropped.
pub fn split_statements(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut statements = Vec::new();
    let mut start = 0;
    let mut has_code = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b';' => {
                if has_code {
                    statements.push(sql[start..i].trim().to_owned());
                }
                i += 1;
                start = i;
                has_code = false;
                continue;
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                i = sql[i..].find('\n').map_or(bytes.len(), |n| i + n + 1);
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let mut depth = 1;
                i += 2;
                while i < bytes.len() && depth > 0 {
                    if bytes[i..].starts_with(b"/*") {
                        depth += 1;
                        i += 2;
                    } else if bytes[i..].starts_with(b"*/") {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                continue;
            }
            b'\'' => {
                let escapes = i > 0
                    && matches!(bytes[i - 1], b'E' | b'e')
                    && (i < 2 || !is_ident_byte(bytes[i - 2]));
                i = skip_quoted(bytes, i, b'\'', escapes);
            }
            b'"' => i = skip_quoted(bytes, i, b'"', false),
            // `$` may also continue an identifier, as in `a$$b`.
            b'$' if i == 0 || !(is_ident_byte(bytes[i - 1]) || bytes[i - 1] == b'$') => {
                let tag_end = bytes[i + 1..]
                    .iter()
                    .position(|b| !is_ident_byte(*b))
                    .map(|n| i + 1 + n);
                match tag_end {
                    Some(end)
                        if bytes[end] == b'$'
                            && bytes.get(i + 1).is_none_or(|b| !b.is_ascii_digit()) =>
                    {
                        let tag = &sql[i..=end];
                        i = sql[end + 1..]
                            .find(tag)
                            .map_or(bytes.len(), |n| end + 1 + n + tag.len());
                    }
                    _ => i += 1,
                }
            }
            b if b.is_ascii_whitespace() => {
                i += 1;
                continue;
            }
            _ => i += 1,
        }
        has_code = true;
    }
    if has_code {
        statements.push(sql[start..].trim().to_owned());
    }
    statements
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

/// The index just past the quoted run opening at `open`, where a doubled quote is an escape.
fn skip_quoted(bytes: &[u8], open: usize, quote: u8, backslash_escapes: bool) -> usize {
    let mut i = open + 1;
    while i < bytes.len() {
        if backslash_escapes && bytes[i] == b'\\' {
            i += 2;
        } else if bytes[i] == quote {
            if bytes.get(i + 1) == Some(&quote) {
                i += 2;
            } else {
                return i + 1;
            }
        } else {
            i += 1;
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::split_statements;

    #[test]
    fn splits_on_top_level_semicolons() {
        assert_eq!(
            split_statements(
                "TRUNCATE account_warnings CASCADE; SELECT setval('account_warnings_id_seq', 1, false); VACUUM FULL account_warnings;"
            ),
            [
                "TRUNCATE account_warnings CASCADE",
                "SELECT setval('account_warnings_id_seq', 1, false)",
                "VACUUM FULL account_warnings",
            ]
        );
    }

    #[test]
    fn keeps_a_single_statement_whole() {
        assert_eq!(
            split_statements("UPDATE accounts SET note = '' WHERE id = $1"),
            ["UPDATE accounts SET note = '' WHERE id = $1"]
        );
    }

    #[test]
    fn ignores_semicolons_in_quotes_and_comments() {
        let sql = "SELECT 'a;b', \"x;y\", E'it\\';s', $$c;d$$, $t$e;$$f$t$ FROM t WHERE id = $1 -- g;h\n\
                   /* i; /* j; */ k; */ ; DELETE FROM u WHERE id = $1";
        let statements = split_statements(sql);
        assert_eq!(statements.len(), 2, "{statements:?}");
        assert!(statements[0].starts_with("SELECT 'a;b'"));
        assert!(statements[0].ends_with("k; */"));
        assert_eq!(statements[1], "DELETE FROM u WHERE id = $1");
    }

    #[test]
    fn treats_dollars_inside_identifiers_as_plain() {
        assert_eq!(
            split_statements("SELECT a$$b FROM t; SELECT 1"),
            ["SELECT a$$b FROM t", "SELECT 1"]
        );
    }

    #[test]
    fn drops_empty_and_comment_only_statements() {
        assert_eq!(
            split_statements(" ; -- nothing\n; /* still nothing */ ;SELECT 1;;"),
            ["SELECT 1"]
        );
        assert!(split_statements("  ;  -- x").is_empty());
    }
}
