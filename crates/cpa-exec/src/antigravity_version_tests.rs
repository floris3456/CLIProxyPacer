//! internal/misc/antigravity_version_test.go, plus the refresh rules and manifest
//! decoding. Manifests come from a loopback mock; nothing reaches the Hub updater.

use std::sync::{Arc, LazyLock, Mutex};

use super::*;

/// Runs `f` with this thread's cached version set (each test thread has its own).
fn with_cached<T>(version: &str, expiry: Option<Instant>, f: impl FnOnce() -> T) -> T {
    let saved = {
        let mut cached = write();
        let saved = (cached.version.clone(), cached.expiry);
        cached.version = version.into();
        cached.expiry = expiry;
        saved
    };
    let out = f();
    let mut cached = write();
    (cached.version, cached.expiry) = saved;
    out
}

fn fresh() -> Option<Instant> {
    Some(Instant::now() + Duration::from_secs(3600))
}

#[test]
fn latest_version_falls_back_until_fetched() {
    with_cached("", None, || assert_eq!(latest_version(), FALLBACK_VERSION));
    // A value past its expiry is not trusted.
    with_cached("2.2.1", Some(Instant::now() - Duration::from_secs(1)), || {
        assert_eq!(latest_version(), FALLBACK_VERSION)
    });
}

#[test]
fn fallback_meets_backend_floor() {
    let parts: Vec<u32> = FALLBACK_VERSION.split('.').map(|p| p.parse().unwrap()).collect();
    assert!(parts[0] > 2 || (parts[0] == 2 && parts[1] >= 23), "{FALLBACK_VERSION}");
}

/// Values Go computed with its never-refreshed cache (tests/reference/antigravity).
#[test]
fn user_agents_match_go() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/antigravity_go.json")).unwrap();
    let go = &fixture["user_agents"];
    with_cached(FALLBACK_VERSION, None, || {
        // The immutable capture predates Hub's version floor and structured build
        // metadata. Only its generated default changes; configured identities keep
        // the recorded semantics. The exact current identity is checked below.
        let recorded_version = go["latest"].as_str().unwrap();
        let recorded_default = go["user_agent"].as_str().unwrap();
        assert_eq!(recorded_version, "2.9.1");
        assert_eq!(recorded_default, "antigravity/hub/2.9.1 darwin/arm64");
        let current_default = user_agent();
        let expected = |value: &serde_json::Value| value.as_str().unwrap().replace(recorded_default, &current_default);
        let cases = go["cases"].as_array().unwrap();
        assert!(cases.len() >= 12);
        for case in cases {
            let input = case["in"].as_str().unwrap();
            assert_eq!(
                request_user_agent(input),
                expected(&case["request"]),
                "request {input:?}"
            );
            assert_eq!(
                load_code_assist_user_agent(input),
                expected(&case["load_code_assist"]),
                "load {input:?}"
            );
            assert_eq!(
                onboard_user_user_agent(input),
                expected(&case["onboard_user"]),
                "onboard {input:?}"
            );
            let version = case["version"].as_str().unwrap();
            let version = if version == recorded_version {
                FALLBACK_VERSION
            } else {
                version
            };
            assert_eq!(version_from_user_agent(input), version, "version {input:?}");
        }
    });
}

#[test]
fn default_identity_uses_matching_version_and_changelist() {
    with_cached("", None, || {
        let expected = "antigravity/hub/2.24.0 (aidev_client; os_type=darwin; arch=arm64; cl=1000335682)";
        assert_eq!(latest_version(), "2.24.0");
        assert_eq!(user_agent(), expected);
        assert_eq!(request_user_agent(""), expected);
        assert_eq!(load_code_assist_user_agent(""), expected);
        let onboard = onboard_user_user_agent("");
        assert_eq!(onboard, format!("{expected} google-api-nodejs-client/10.3.0"));
        assert_eq!(version_from_user_agent(&onboard), "2.24.0");
    });
    with_cached("2.23.0", fresh(), || {
        assert_eq!(
            user_agent(),
            "antigravity/hub/2.23.0 (aidev_client; os_type=darwin; arch=arm64; cl=998057262)"
        );
    });
}

#[test]
fn fetched_version_never_borrows_another_releases_changelist() {
    with_cached("2.25.0", fresh(), || {
        let expected = "antigravity/hub/2.25.0 (aidev_client; os_type=darwin; arch=arm64)";
        assert_eq!(user_agent(), expected);
        assert_eq!(request_user_agent(""), expected);
        assert_eq!(load_code_assist_user_agent(""), expected);
        assert_eq!(
            onboard_user_user_agent(""),
            format!("{expected} google-api-nodejs-client/10.3.0")
        );
        assert_eq!(version_from_user_agent("curl/8"), "2.25.0");
        // Non-ASCII before the suffix must not break the cut.
        assert_eq!(
            request_user_agent("antigravity/İ google-api-nodejs-client/1"),
            "antigravity/İ"
        );
    });
}

#[test]
fn refresh_keeps_a_trusted_value_and_falls_back_after_expiry() {
    let now = Instant::now();
    with_cached(FALLBACK_VERSION, None, || {
        refresh(Ok("2.2.1".into()), now);
        assert_eq!(latest_version(), "2.2.1");
        // A failed refresh keeps the fetched value while it is trusted.
        refresh(Err("down".into()), now + Duration::from_secs(60));
        assert_eq!(read().version, "2.2.1");
        // After the six hours the fallback replaces it, trusted for six more.
        let later = now + CACHE_TTL + Duration::from_secs(1);
        refresh(Err("down".into()), later);
        assert_eq!(read().version, FALLBACK_VERSION);
        assert_eq!(read().expiry, Some(later + CACHE_TTL));
    });
}

#[test]
fn manifest_versions_decode_like_go() {
    assert_eq!(
        manifest_version(b"version: 2.2.1\npath: Antigravity-arm64-mac.zip\n"),
        Ok("2.2.1".into())
    );
    assert_eq!(manifest_version(b"version: \" 10.0.30 \"\n"), Ok("10.0.30".into()));
    for (raw, error) in [
        (&b""[..], "antigravity Hub updater manifest returned empty version"),
        (b"path: x\n", "antigravity Hub updater manifest returned empty version"),
        (
            b"version: 2.2\n",
            "antigravity Hub updater manifest returned invalid version \"2.2\"",
        ),
        (
            b"version: 2.2.1-beta\n",
            "antigravity Hub updater manifest returned invalid version \"2.2.1-beta\"",
        ),
        (
            b"version: 2..1\n",
            "antigravity Hub updater manifest returned invalid version \"2..1\"",
        ),
    ] {
        assert_eq!(
            manifest_version(raw),
            Err(error.to_owned()),
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
    assert!(
        manifest_version(b"[1, 2]")
            .unwrap_err()
            .starts_with("decode antigravity Hub updater manifest")
    );
    assert!(
        manifest_version(b"version: [1]")
            .unwrap_err()
            .starts_with("decode antigravity Hub updater manifest")
    );
}

/// A loopback manifest server answering `status` with `body`, recording request heads.
async fn manifest_server(status: u16, body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hub/latest-arm64-mac.yml", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            log.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(reply.as_bytes()).await;
        }
    });
    (url, seen)
}

#[tokio::test]
async fn fetch_reads_the_hub_manifest() {
    let (url, seen) = manifest_server(200, "version: 2.2.1\npath: Antigravity-arm64-mac.zip\n").await;
    assert_eq!(fetch_latest(&url).await, Ok("2.2.1".into()));
    let head = seen.lock().unwrap()[0].clone();
    assert!(head.starts_with("GET /hub/latest-arm64-mac.yml HTTP/1.1\r\n"), "{head}");
    assert!(head.contains("\r\nUser-Agent: electron-builder\r\n"), "{head}");
    assert!(head.contains("\r\nCache-Control: no-cache\r\n"), "{head}");
}

#[tokio::test]
async fn fetch_reports_a_status_error() {
    let (url, _) = manifest_server(500, "temporary outage\n").await;
    assert_eq!(
        fetch_latest(&url).await,
        Err("antigravity Hub updater manifest returned status 500".into())
    );
}

#[tokio::test]
async fn fetch_reads_at_most_4096_bytes() {
    // The version line sits beyond the limit, so Go never sees it.
    static BODY: LazyLock<String> = LazyLock::new(|| format!("# {}\nversion: 2.2.1\n", "x".repeat(4100)));
    let (url, _) = manifest_server(200, BODY.as_str()).await;
    assert_eq!(
        fetch_latest(&url).await,
        Err("antigravity Hub updater manifest returned empty version".into())
    );
}
