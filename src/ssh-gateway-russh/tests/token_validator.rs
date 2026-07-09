//! Token validator tests: fail-closed behavior through the `HostedApi` trait
//! seam, socket-level behavior of the real HTTP client, and log redaction.

mod common;

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boxlite_ssh_gateway::token::{
    HttpHostedApi, RouteError, RunnerRecord, SshAccessValidation, TokenValidator,
};
use common::{valid_validation, StubHostedApi, BOX_ID, TOKEN, TOKEN_ID};

fn validator(api: Arc<StubHostedApi>) -> TokenValidator {
    TokenValidator::new(api, "http")
}

// ---------------------------------------------------------------------------
// Trait-seam tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_token_yields_routing_decision() {
    let api = StubHostedApi::valid("runner.internal:3003");
    let decision = validator(api)
        .validate(TOKEN)
        .await
        .expect("valid token must route");
    assert_eq!(decision.box_id, BOX_ID);
    assert_eq!(decision.runner_base_url, "http://runner.internal:3003");
    assert_eq!(decision.unix_user, "root");
    assert_eq!(decision.token_id, TOKEN_ID);
}

#[tokio::test]
async fn invalid_token_is_rejected() {
    let api = StubHostedApi::invalid();
    let error = validator(api)
        .validate(TOKEN)
        .await
        .expect_err("must reject");
    assert_eq!(error, RouteError::TokenInvalid);
}

#[tokio::test]
async fn valid_with_empty_box_id_is_rejected() {
    let api = StubHostedApi::with_fallback(
        Ok(SshAccessValidation {
            box_id: String::new(),
            ..valid_validation()
        }),
        "runner.internal",
    );
    let error = validator(api)
        .validate(TOKEN)
        .await
        .expect_err("must reject");
    assert_eq!(error, RouteError::TokenInvalid);
}

#[tokio::test]
async fn missing_unix_user_is_rejected() {
    let api = StubHostedApi::with_fallback(
        Ok(SshAccessValidation {
            unix_user: None,
            ..valid_validation()
        }),
        "runner.internal",
    );
    let error = validator(api)
        .validate(TOKEN)
        .await
        .expect_err("must reject");
    assert_eq!(error, RouteError::TokenInvalid);
}

#[tokio::test]
async fn non_root_unix_user_is_rejected() {
    let api = StubHostedApi::with_fallback(
        Ok(SshAccessValidation {
            unix_user: Some("ubuntu".into()),
            ..valid_validation()
        }),
        "runner.internal",
    );
    let error = validator(api)
        .validate(TOKEN)
        .await
        .expect_err("must reject");
    assert_eq!(error, RouteError::TokenInvalid);
}

#[tokio::test]
async fn missing_token_id_is_rejected() {
    let api = StubHostedApi::with_fallback(
        Ok(SshAccessValidation {
            token_id: None,
            ..valid_validation()
        }),
        "runner.internal",
    );
    let error = validator(api)
        .validate(TOKEN)
        .await
        .expect_err("must reject");
    assert_eq!(error, RouteError::TokenInvalid);
}

#[tokio::test]
async fn hosted_api_error_fails_closed() {
    let api = StubHostedApi::with_fallback(Err("boom".into()), "runner.internal");
    let error = validator(api)
        .validate(TOKEN)
        .await
        .expect_err("must reject");
    assert_eq!(error, RouteError::HostedApiUnavailable);
}

#[tokio::test]
async fn runner_without_domain_fails_closed() {
    let api = StubHostedApi::valid("runner.internal");
    api.set_runner(Ok(RunnerRecord {
        id: "runner-1".into(),
        domain: None,
    }));
    let error = validator(api)
        .validate(TOKEN)
        .await
        .expect_err("must reject");
    assert_eq!(error, RouteError::RunnerResolutionFailed);
}

#[tokio::test]
async fn runner_lookup_error_fails_closed() {
    let api = StubHostedApi::valid("runner.internal");
    api.set_runner(Err("lookup failed".into()));
    let error = validator(api)
        .validate(TOKEN)
        .await
        .expect_err("must reject");
    assert_eq!(error, RouteError::HostedApiUnavailable);
}

#[tokio::test]
async fn validation_never_logs_the_full_token() {
    let capture = common::install_global_capture();
    // Unique to this test: the process-wide capture is attributed via the
    // redacted prefix of a token no other test uses.
    const CANARY_TOKEN: &str = "canary99-validator-token-abcdefghijklmnop";

    let api = StubHostedApi::valid("runner.internal");
    api.push_validation(Ok(valid_validation()));
    api.push_validation(Ok(SshAccessValidation {
        valid: false,
        box_id: String::new(),
        unix_user: None,
        token_id: None,
    }));
    api.push_validation(Err("hosted api down".into()));

    let validator = validator(api);
    let _ = validator.validate(CANARY_TOKEN).await;
    let _ = validator.validate(CANARY_TOKEN).await;
    let _ = validator.validate(CANARY_TOKEN).await;

    let logs = capture.contents();
    let prefix: String = CANARY_TOKEN.chars().take(8).collect();
    assert!(
        logs.contains(&prefix),
        "redacted prefix expected for audit correlation"
    );
    assert!(
        !logs.contains(CANARY_TOKEN),
        "full token leaked into logs: {logs}"
    );
    // No event from any concurrently running test may carry the shared
    // token in full either.
    assert!(!logs.contains(TOKEN), "shared test token leaked into logs");
}

// ---------------------------------------------------------------------------
// Socket-level tests of the real HTTP client
// ---------------------------------------------------------------------------

/// One-shot HTTP stub recording request lines; `responses` are served in
/// connection order.
fn spawn_http_stub(responses: Vec<String>) -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    let request_lines = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&request_lines);
    std::thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            let text = String::from_utf8_lossy(&head);
            if let Some(line) = text.split("\r\n").next() {
                recorded.lock().unwrap().push(line.to_string());
            }
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (addr, request_lines)
}

fn json_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn http_client_sends_token_in_query_and_parses_response() {
    let validate_body =
        format!(r#"{{"valid":true,"boxId":"{BOX_ID}","unixUser":"root","tokenId":"{TOKEN_ID}"}}"#);
    let runner_body = r#"{"id":"runner-1","domain":"runner.internal:3003"}"#;
    let (addr, request_lines) = spawn_http_stub(vec![
        json_response(&validate_body),
        json_response(runner_body),
    ]);

    let api = HttpHostedApi::new(
        &format!("http://{addr}"),
        "hosted-secret",
        Duration::from_secs(5),
    )
    .expect("client");
    let validator = TokenValidator::new(Arc::new(api), "http");
    let decision = validator.validate(TOKEN).await.expect("must route");
    assert_eq!(decision.box_id, BOX_ID);
    assert_eq!(decision.runner_base_url, "http://runner.internal:3003");

    let lines = request_lines.lock().unwrap().clone();
    assert_eq!(lines.len(), 2, "one validate call, one runner lookup");
    assert!(
        lines[0].starts_with(&format!("GET /box/ssh-access/validate?token={TOKEN} ")),
        "validate URL must carry the token: {}",
        lines[0]
    );
    assert!(
        lines[1].starts_with(&format!("GET /runners/by-box/{BOX_ID} ")),
        "runner lookup URL must carry the box id: {}",
        lines[1]
    );
}

#[tokio::test]
async fn http_500_fails_closed() {
    let (addr, _) = spawn_http_stub(vec![
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_string(),
    ]);
    let api = HttpHostedApi::new(
        &format!("http://{addr}"),
        "hosted-secret",
        Duration::from_secs(5),
    )
    .expect("client");
    let validator = TokenValidator::new(Arc::new(api), "http");
    let error = validator.validate(TOKEN).await.expect_err("must reject");
    assert_eq!(error, RouteError::HostedApiUnavailable);
}

#[tokio::test]
async fn hosted_api_timeout_fails_closed() {
    // Listener that accepts but never answers.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream); // keep the connection open, silently
        }
    });

    let api = HttpHostedApi::new(
        &format!("http://{addr}"),
        "hosted-secret",
        Duration::from_millis(300),
    )
    .expect("client");
    let validator = TokenValidator::new(Arc::new(api), "http");
    let error = validator.validate(TOKEN).await.expect_err("must reject");
    assert_eq!(error, RouteError::HostedApiUnavailable);
}
