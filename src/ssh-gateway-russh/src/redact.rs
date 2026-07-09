//! Token redaction for logs.
//!
//! The SSH username on this gateway IS the access token, so it must never
//! reach a log line in full at any level. Every log site that mentions a
//! token goes through [`redact_token`].

/// Maximum number of leading characters of a token that may appear in logs;
/// enough to correlate audit events without being replayable.
const REDACT_PREFIX_CHARS: usize = 8;

/// Returns at most the first [`REDACT_PREFIX_CHARS`] characters of `token`
/// followed by `…`. Safe on empty and multi-byte (non-ASCII) input.
pub fn redact_token(token: &str) -> String {
    let mut prefix = String::with_capacity(REDACT_PREFIX_CHARS + '…'.len_utf8());
    prefix.extend(token.chars().take(REDACT_PREFIX_CHARS));
    prefix.push('…');
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_token_keeps_only_eight_char_prefix() {
        let token = "boxlite-secret-token-abcdef0123456789";
        let redacted = redact_token(token);
        assert_eq!(redacted, "boxlite-…");
        assert!(!redacted.contains(token));
    }

    #[test]
    fn output_never_exceeds_prefix_plus_ellipsis() {
        for token in ["", "a", "12345678", "123456789", &"x".repeat(4096)] {
            let redacted = redact_token(token);
            assert!(redacted.chars().count() <= REDACT_PREFIX_CHARS + 1);
            assert!(redacted.ends_with('…'));
        }
    }

    #[test]
    fn empty_token_is_just_ellipsis() {
        assert_eq!(redact_token(""), "…");
    }

    #[test]
    fn unicode_token_is_cut_on_char_boundaries() {
        let token = "密密密密密密密密密密密密";
        let redacted = redact_token(token);
        assert_eq!(redacted, "密密密密密密密密…");
        assert!(!redacted.contains(token));
    }
}
