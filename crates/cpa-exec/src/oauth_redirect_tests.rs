//! Credential POSTs must not replay secrets at a redirect destination. These exercise
//! public acquisition paths with a second loopback server as the redirect recipient.

use std::future::Future;
use std::time::Duration;

use crate::codex_testkit::{Mock, Reply, json};

async fn rejects_secret_redirect<F, Fut>(path: &str, body_fragment: &str, exchange: F)
where
    F: Fn(wreq::Client, String) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    for status in [307, 308] {
        let origin = Mock::start().await;
        let sink = Mock::start().await;
        origin.script(
            path,
            vec![Reply {
                status,
                headers: vec![("Location".into(), format!("{}/stolen", sink.url))],
                body: "response-secret-do-not-echo".into(),
            }],
        );
        sink.script(
            "/stolen",
            vec![json(
                200,
                r#"{"access_token":"sink-token","expires_in":3600,"token":"sink-token","api_key":"sink-key"}"#,
            )],
        );
        // Request-level redirect rejection must also protect injected clients whose
        // default redirect policy follows redirects.
        let client = wreq::Client::builder().no_proxy().build().unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), exchange(client, origin.url.clone()))
            .await
            .expect("credential exchange timed out")
            .unwrap_err();
        assert!(!error.contains("response-secret-do-not-echo"), "{error}");
        let sent = origin.take();
        assert_eq!(sent.len(), 1, "{status}: the credential endpoint must be called once");
        assert_eq!(sent[0].method, "POST");
        assert!(String::from_utf8_lossy(&sent[0].body).contains(body_fragment));
        assert!(
            sink.take().is_empty(),
            "{status}: credential body reached a different origin"
        );
    }
}

#[tokio::test]
async fn antigravity_refresh_does_not_follow_redirects() {
    rejects_secret_redirect("/token", "refresh_token=home-refresh", |client, origin| async move {
        crate::antigravity_auth::OAuth::with_endpoints(client, &format!("{origin}/token"), &origin, &origin, &origin)
            .refresh("home-refresh")
            .await
            .map(|_| ())
            .map_err(|error| String::from_utf8_lossy(&error.body).into_owned())
    })
    .await;
}

#[tokio::test]
async fn antigravity_code_exchange_does_not_follow_redirects() {
    rejects_secret_redirect("/token", "code=authorization-code", |client, origin| async move {
        crate::antigravity_auth::OAuth::with_endpoints(client, &format!("{origin}/token"), &origin, &origin, &origin)
            .exchange_code("authorization-code", "http://127.0.0.1/callback")
            .await
            .map(|_| ())
            .map_err(|error| error.message)
    })
    .await;
}

#[tokio::test]
async fn kimi_refresh_does_not_follow_redirects() {
    rejects_secret_redirect(
        "/api/oauth/token",
        "refresh_token=home-refresh",
        |client, origin| async move {
            crate::kimi_auth::DeviceFlow::new(client, "kimi.com", "test-device")
                .with_oauth_host(&origin)
                .refresh("home-refresh")
                .await
                .map(|_| ())
                .map_err(|error| String::from_utf8_lossy(&error.body).into_owned())
        },
    )
    .await;
}

#[tokio::test]
async fn xai_refresh_does_not_follow_redirects() {
    rejects_secret_redirect("/token", "refresh_token=home-refresh", |client, origin| async move {
        crate::xai_auth::XaiAuth::new(client)
            .with_issuer_origin(&origin)
            .refresh("home-refresh", "https://auth.x.ai/token")
            .await
            .map(|_| ())
            .map_err(|error| String::from_utf8_lossy(&error.body).into_owned())
    })
    .await;
}

#[tokio::test]
async fn meta_mint_does_not_follow_redirects() {
    rejects_secret_redirect("/mint", "dca:home-grant", |client, origin| async move {
        crate::meta_auth::MetaAuth::new(client)
            .with_mint_url(&format!("{origin}/mint"))
            .mint_api_key("dca:home-grant")
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    })
    .await;
}

#[tokio::test]
async fn devin_code_exchange_does_not_follow_redirects() {
    rejects_secret_redirect("/auth/cli/token", "pkce-verifier", |client, origin| async move {
        crate::devin_auth::DevinAuth::new(client)
            .with_api_base(&origin)
            .exchange_code("authorization-code", "pkce-verifier")
            .await
            .map(|_| ())
    })
    .await;
}

#[tokio::test]
async fn devin_account_status_does_not_redirect_its_session_token() {
    rejects_secret_redirect(
        crate::devin_auth::USER_STATUS_PATH,
        "permanent-session-token",
        |client, origin| async move {
            crate::devin_auth::DevinAuth::new(client)
                .with_server_base(&origin)
                .fetch_user_status("permanent-session-token", "test-device")
                .await
                .map(|_| ())
        },
    )
    .await;
}

#[tokio::test]
async fn vertex_assertion_exchange_does_not_follow_redirects() {
    rejects_secret_redirect("/token", "assertion=", |client, origin| async move {
        crate::vertex_auth::access_token(&client, &vertex_account(&format!("{origin}/token")), 1_700_000_000)
            .await
            .map(|_| ())
    })
    .await;
}

fn vertex_account(token_url: &str) -> serde_json::Map<String, serde_json::Value> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("../tests/fixtures/vertex_go.json")).unwrap();
    serde_json::json!({
        "type": "service_account",
        "client_email": "test@example.invalid",
        "private_key": fixture["keys"]["pkcs8"],
        "token_uri": token_url,
    })
    .as_object()
    .unwrap()
    .clone()
}

#[tokio::test]
async fn vertex_rejected_assertion_does_not_echo_secrets_into_the_log_diagnostic() {
    let mock = Mock::start().await;
    mock.script(
        "/token",
        vec![json(
            400,
            r#"{"error":"invalid_grant","error_description":"fake-assertion-secret fake-token-secret"}"#,
        )],
    );
    let client = wreq::Client::builder().no_proxy().build().unwrap();
    let error =
        crate::vertex_auth::access_token(&client, &vertex_account(&format!("{}/token", mock.url)), 1_700_000_000)
            .await
            .unwrap_err();
    // Deliberate redaction from Go: the caller logs this returned error, so only
    // status context may survive a token endpoint that echoes credential material.
    assert_eq!(error, "oauth2: cannot fetch token: 400 Bad Request");
    let sent = mock.take();
    assert_eq!(sent.len(), 1);
    assert!(String::from_utf8_lossy(&sent[0].body).contains("assertion="));
}
