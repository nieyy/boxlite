//! `boxlite-ssh-gateway` binary: config parsing, tracing init, TCP listener,
//! periodic metric logging, and graceful shutdown on SIGTERM/SIGINT.

use std::process::ExitCode;
use std::time::Duration;

use boxlite_ssh_gateway::{Gateway, GatewayConfig};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// How often the in-process counters are written to the log.
const METRICS_LOG_INTERVAL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config = GatewayConfig::parse();
    let listen_addr = config.listen_addr;

    let gateway = match Gateway::new(config).await {
        Ok(gateway) => gateway,
        Err(e) => {
            error!(error = %e, "gateway startup failed");
            return ExitCode::FAILURE;
        }
    };

    let listener = match TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(addr = %listen_addr, error = %e, "cannot bind SSH listener");
            return ExitCode::FAILURE;
        }
    };
    info!(addr = %listen_addr, "SSH gateway listening");

    let metrics = gateway.metrics();
    let metrics_logger = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(METRICS_LOG_INTERVAL);
        ticker.tick().await; // first tick fires immediately; skip it
        loop {
            ticker.tick().await;
            metrics.log_snapshot();
        }
    });

    let exit = tokio::select! {
        result = gateway.run(listener) => {
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    error!(error = %e, "SSH listener failed");
                    ExitCode::FAILURE
                }
            }
        }
        _ = shutdown_signal() => {
            info!("shutdown signal received; stopping listener");
            ExitCode::SUCCESS
        }
    };

    metrics_logger.abort();
    gateway.metrics().log_snapshot();
    exit
}

/// Resolves on SIGINT (Ctrl-C) or SIGTERM.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(sigterm) => sigterm,
            Err(e) => {
                error!(error = %e, "cannot install SIGTERM handler; falling back to Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
