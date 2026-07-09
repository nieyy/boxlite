//! In-process counters, named per the design doc:
//!
//! - `ssh_gateway_connections_total`
//! - `ssh_gateway_route_failures_total{reason}`
//!
//! Kept as a simple atomic registry (no exporter dependency); `snapshot()`
//! serves tests and the periodic log line emitted by `main`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tracing::info;

/// Metric name of the accepted-connection counter.
pub const CONNECTIONS_TOTAL: &str = "ssh_gateway_connections_total";

/// Metric name of the fail-closed routing counter (labelled by reason).
pub const ROUTE_FAILURES_TOTAL: &str = "ssh_gateway_route_failures_total";

/// In-process metric registry shared by all connections of one gateway.
#[derive(Debug, Default)]
pub struct Metrics {
    connections_total: AtomicU64,
    route_failures: Mutex<HashMap<&'static str, u64>>,
}

impl Metrics {
    /// One accepted public SSH connection.
    pub fn record_connection(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }

    /// One fail-closed routing decision; `reason` is a
    /// [`crate::token::RouteError::reason`] label.
    pub fn record_route_failure(&self, reason: &'static str) {
        let mut failures = self.route_failures.lock().expect("metrics mutex poisoned");
        *failures.entry(reason).or_insert(0) += 1;
    }

    /// Consistent point-in-time copy of all counters.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            connections_total: self.connections_total.load(Ordering::Relaxed),
            route_failures: self
                .route_failures
                .lock()
                .expect("metrics mutex poisoned")
                .clone(),
        }
    }

    /// Emits the counters as one structured log event.
    pub fn log_snapshot(&self) {
        let snapshot = self.snapshot();
        info!(
            ssh_gateway_connections_total = snapshot.connections_total,
            ssh_gateway_route_failures_total = ?snapshot.route_failures,
            "gateway metrics"
        );
    }
}

/// Point-in-time counter values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub connections_total: u64,
    pub route_failures: HashMap<&'static str, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_and_snapshot() {
        let metrics = Metrics::default();
        metrics.record_connection();
        metrics.record_connection();
        metrics.record_route_failure("token_invalid");
        metrics.record_route_failure("token_invalid");
        metrics.record_route_failure("box_stopped");

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.connections_total, 2);
        assert_eq!(snapshot.route_failures.get("token_invalid"), Some(&2));
        assert_eq!(snapshot.route_failures.get("box_stopped"), Some(&1));
    }
}
