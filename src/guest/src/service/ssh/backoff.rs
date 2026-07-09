//! Backoff for repeated vsock `accept()` errors.
//!
//! A persistent kernel-level fault (e.g. FD exhaustion) must not busy-loop
//! the accept task at 100% CPU. [`next_accept_error_backoff`] doubles from
//! MIN up to MAX; the caller resets to MIN on the next successful accept —
//! the standard accept-loop idiom (e.g. Go's `net/http.Server.Serve`).

use std::time::Duration;

pub(super) const ACCEPT_ERROR_BACKOFF_MIN: Duration = Duration::from_millis(10);
const ACCEPT_ERROR_BACKOFF_MAX: Duration = Duration::from_secs(1);

pub(super) fn next_accept_error_backoff(current: Duration) -> Duration {
    (current * 2).min(ACCEPT_ERROR_BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_each_step() {
        assert_eq!(
            next_accept_error_backoff(ACCEPT_ERROR_BACKOFF_MIN),
            Duration::from_millis(20)
        );
        assert_eq!(
            next_accept_error_backoff(Duration::from_millis(20)),
            Duration::from_millis(40)
        );
    }

    #[test]
    fn caps_at_max_and_does_not_overflow_with_more_steps() {
        let mut backoff = ACCEPT_ERROR_BACKOFF_MIN;
        for _ in 0..64 {
            backoff = next_accept_error_backoff(backoff);
        }
        assert_eq!(backoff, ACCEPT_ERROR_BACKOFF_MAX);
    }

    #[test]
    fn min_is_below_max() {
        assert!(ACCEPT_ERROR_BACKOFF_MIN < ACCEPT_ERROR_BACKOFF_MAX);
    }
}
