use super::*;
use serde_json::json;
use std::path::PathBuf;

struct AuthFile {
    dir: PathBuf,
    path: PathBuf,
}

impl AuthFile {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("cpa-shared-refresh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("codex.json");
        std::fs::write(
            &path,
            json!({
                "type":"codex", "access_token":"original", "refresh_token":"original-grant",
                "expired":"2000-01-01T00:00:00Z", "note":"keep this",
                "siwc":{"access_token":"inactive-siwc", "refresh_token":"inactive-grant"}
            })
            .to_string(),
        )
        .unwrap();
        Self { dir, path }
    }
}

impl Drop for AuthFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn runtime(dir: &Path, token_url: &str) -> Arc<Runtime> {
    let mut cfg = Config::parse("").unwrap();
    cfg.auth_dir = dir.to_owned();
    let client = wreq::Client::new();
    let oauth = cpa_exec::codex_oauth::CodexOAuth::with_endpoints(client.clone(), token_url, token_url, token_url);
    Arc::new(crate::testing::runtime(
        cfg.clone(),
        cpa_core::config::credentials::from_auth_dir(&cfg)
            .into_iter()
            .map(crate::testing::local)
            .collect(),
        Executors {
            claude: cpa_exec::claude::ClaudeExecutor::new("http://127.0.0.1:1").unwrap(),
            codex: cpa_exec::codex::CodexExecutor::with_client(client, oauth),
            devices: Default::default(),
            openai: Default::default(),
            google: Default::default(),
        },
    ))
}

fn unauthorized() -> Outcome {
    Outcome::Failure(ExecError::local(401, FailureScope::Credential, "unauthorized"))
}

/// A second server process loads the old grant while the first request is in flight.
/// Cancelling that first caller must not release ownership before rotation is saved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_refresh_survives_cancellation_and_second_process() {
    use std::io::Write as _;
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt as _, BufReader};

    const CHILD: &str = "CPA_SHARED_REFRESH_TEST_CHILD";
    const ENDPOINT: &str = "CPA_SHARED_REFRESH_TEST_ENDPOINT";
    if let Some(dir) = std::env::var_os(CHILD) {
        let rt = runtime(Path::new(&dir), &std::env::var(ENDPOINT).unwrap());
        assert_eq!(
            rt.store.get("codex.json").unwrap().str("access_token"),
            Some("original")
        );
        println!("REFRESH_CHILD_LOADED");
        std::io::stdout().flush().unwrap();
        let current = rt.prepare_credential("codex.json", &rt.config(), None).await.unwrap();
        assert_eq!(current.str("access_token"), Some("rotated"));
        assert_eq!(current.str("refresh_token"), Some("rotated-grant"));
        assert_eq!(current.str("note"), Some("keep this"));
        println!("REFRESH_CHILD_FINISHED");
        return;
    }

    async fn marker(lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>, expected: &str) {
        loop {
            let line = lines.next_line().await.unwrap().expect("child exited before marker");
            if line.ends_with(expected) {
                return;
            }
        }
    }

    let file = AuthFile::new();
    let calls = Arc::new(AtomicU64::new(0));
    let answer = Arc::new(tokio::sync::Semaphore::new(0));
    let (hit_tx, mut hit) = tokio::sync::mpsc::unbounded_channel();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post({
            let calls = calls.clone();
            let answer = answer.clone();
            move |body: String| {
                let calls = calls.clone();
                let answer = answer.clone();
                let hit = hit_tx.clone();
                async move {
                    assert_eq!(
                        calls.fetch_add(1, Ordering::SeqCst),
                        0,
                        "the shared grant must rotate once"
                    );
                    assert!(body.contains("original-grant"));
                    hit.send(()).unwrap();
                    answer.acquire().await.unwrap().forget();
                    axum::Json(json!({"access_token":"rotated", "refresh_token":"rotated-grant", "expires_in":864000}))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let rt = runtime(&file.dir, &endpoint);
    let first = tokio::spawn({
        let rt = rt.clone();
        async move { rt.prepare_credential("codex.json", &rt.config(), None).await }
    });
    tokio::time::timeout(Duration::from_secs(10), hit.recv())
        .await
        .unwrap()
        .unwrap();
    let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "runtime::auth_safety_tests::shared_refresh_survives_cancellation_and_second_process",
            "--nocapture",
        ])
        .env(CHILD, &file.dir)
        .env(ENDPOINT, &endpoint)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    tokio::time::timeout(Duration::from_secs(10), marker(&mut lines, "REFRESH_CHILD_LOADED"))
        .await
        .unwrap();
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(CredentialFileLease::try_acquire(&file.path).unwrap().is_none());
    assert!(
        tokio::time::timeout(Duration::from_millis(150), marker(&mut lines, "REFRESH_CHILD_FINISHED"))
            .await
            .is_err()
    );
    answer.add_permits(1);
    tokio::time::timeout(Duration::from_secs(10), marker(&mut lines, "REFRESH_CHILD_FINISHED"))
        .await
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let disk: Value = serde_json::from_slice(&std::fs::read(&file.path).unwrap()).unwrap();
    assert_eq!(disk["refresh_token"], "rotated-grant");
    assert_eq!(disk["siwc"]["refresh_token"], "inactive-grant");
    assert_eq!(rt.store.get("codex.json").unwrap().str("access_token"), Some("rotated"));
    server.abort();
}

#[tokio::test]
async fn rejected_token_stays_blocked_after_failed_refresh_cooldown_reset_and_metadata_edit() {
    let file = AuthFile::new();
    let calls = Arc::new(AtomicU64::new(0));
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post({
            let calls = calls.clone();
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { (axum::http::StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable") }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let rt = runtime(&file.dir, &endpoint);
    let selection = Selection::new("codex", "test-model");
    let lease = rt.store.select(selection.clone()).unwrap();
    let late = rt.store.select(selection.clone()).unwrap();
    assert!(
        rt.refresh_after_unauthorized_for_lease(&lease, &rt.config())
            .await
            .is_none()
    );
    lease.complete(unauthorized());
    assert!(calls.load(Ordering::SeqCst) > 0);
    rt.store.reset_cooldown("codex.json");
    assert!(rt.store.select(selection.clone()).is_none());
    let current = rt.store.get("codex.json").unwrap();
    let patch = MetadataPatch {
        set: json!({"note":"changed", "expired":"2099-01-01T00:00:00Z"})
            .as_object()
            .unwrap()
            .clone(),
        remove: vec![],
    };
    let changed = rt.store.apply_patch("codex.json", current.revision, &patch).unwrap();
    assert!(rt.store.token_rejected(&changed));
    assert!(
        rt.store.select(selection.clone()).is_none(),
        "metadata must not revive a rejected token"
    );
    rt.store.upsert((*changed).clone());
    assert!(
        rt.store.select(selection.clone()).is_none(),
        "re-registering the same token keeps its rejection"
    );
    let changed = rt.store.get("codex.json").unwrap();
    let patch = MetadataPatch {
        set: json!({"access_token":"replacement", "refresh_token":"replacement-grant"})
            .as_object()
            .unwrap()
            .clone(),
        remove: vec![],
    };
    rt.store.apply_patch("codex.json", changed.revision, &patch).unwrap();
    late.complete(unauthorized());
    assert!(
        rt.store.select(selection).is_some(),
        "a late failure cannot reject a replacement token"
    );
    server.abort();
}

#[test]
fn token_rejection_obeys_registration_fences_but_not_metadata_revisions() {
    let file = AuthFile::new();
    let mut cfg = Config::parse("").unwrap();
    cfg.auth_dir = file.dir.clone();
    let store = CredentialStore::new(cpa_core::config::credentials::from_auth_dir(&cfg));
    let selection = Selection::new("codex", "test-model");
    let lease = store.select(selection.clone()).unwrap();
    let mut edited = (*store.get("codex.json").unwrap()).clone();
    edited
        .metadata
        .insert("note".into(), "metadata changed during request".into());
    store.upsert(edited);
    lease.complete(unauthorized());
    assert!(
        store.select(selection.clone()).is_none(),
        "same-token failures survive a metadata revision"
    );

    let replacement = (*store.get("codex.json").unwrap()).clone();
    store.reconcile(vec![]);
    store.reconcile(vec![replacement.clone()]);
    let old_registration = store.select(selection.clone()).unwrap();
    store.reconcile(vec![]);
    store.reconcile(vec![replacement]);
    old_registration.complete(unauthorized());
    assert!(
        store.select(selection).is_some(),
        "an old registration cannot poison a recreated credential"
    );
}

#[test]
fn routine_persistence_and_metadata_patches_do_not_restore_another_process_old_tokens() {
    let file = AuthFile::new();
    let mut cfg = Config::parse("").unwrap();
    cfg.auth_dir = file.dir.clone();
    let store = CredentialStore::new(cpa_core::config::credentials::from_auth_dir(&cfg));
    let old = store.get("codex.json").unwrap();
    let mut external = old.metadata.clone();
    external.insert("access_token".into(), "external-token".into());
    external.insert("refresh_token".into(), "external-grant".into());
    std::fs::write(&file.path, serde_json::to_vec(&external).unwrap()).unwrap();
    store.persist_credential(&old);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&file.path).unwrap()).unwrap()["refresh_token"],
        "external-grant"
    );
    let patch = MetadataPatch {
        set: json!({"note":"new note"}).as_object().unwrap().clone(),
        remove: vec![],
    };
    let current = store.apply_patch("codex.json", old.revision, &patch).unwrap();
    assert_eq!(current.str("refresh_token"), Some("external-grant"));
    let disk: Value = serde_json::from_slice(&std::fs::read(&file.path).unwrap()).unwrap();
    assert_eq!(disk["access_token"], "external-token");
    assert_eq!(disk["note"], "new note");
}

#[test]
fn shared_file_reread_preserves_normalized_provider_and_proxy_selection() {
    let file = AuthFile::new();
    std::fs::write(
        &file.path,
        json!({
            "type":" CoDeX ", "access_token":"token", "refresh_token":"grant",
            "proxy-url":"http://127.0.0.1:12345"
        })
        .to_string(),
    )
    .unwrap();
    let mut cfg = Config::parse("").unwrap();
    cfg.auth_dir = file.dir.clone();
    let store = CredentialStore::new(cpa_core::config::credentials::from_auth_dir(&cfg));
    let lease = CredentialFileLease::acquire_blocking(&file.path).unwrap();
    let (_, registered) = store.get_registered("codex.json").unwrap();
    let (current, _) = store
        .read_refresh_file("codex.json", registered.registration, Some(&lease), None)
        .unwrap();
    assert_eq!(current.provider, "codex");
    assert_eq!(current.str("proxy_url"), Some("http://127.0.0.1:12345"));
    assert_eq!(current.attributes["proxy_url"], "http://127.0.0.1:12345");
    assert!(!current.metadata.contains_key("proxy-url"));
}

#[tokio::test]
async fn refresh_is_fenced_when_native_file_ownership_changes() {
    let file = AuthFile::new();
    let original_file = std::fs::read(&file.path).unwrap();
    let answer = Arc::new(tokio::sync::Semaphore::new(0));
    let (hit_tx, mut hit) = tokio::sync::mpsc::unbounded_channel();
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post({
            let answer = answer.clone();
            move |body: String| {
                let answer = answer.clone();
                let hit = hit_tx.clone();
                async move {
                    assert!(body.contains("original-grant"));
                    hit.send(()).unwrap();
                    answer.acquire().await.unwrap().forget();
                    axum::Json(json!({
                        "access_token":"late-token", "refresh_token":"late-grant", "expires_in":3600
                    }))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let rt = runtime(&file.dir, &endpoint);
    let pending = tokio::spawn({
        let rt = rt.clone();
        async move { rt.prepare_credential("codex.json", &rt.config(), None).await }
    });
    tokio::time::timeout(Duration::from_secs(5), hit.recv())
        .await
        .unwrap()
        .unwrap();
    let (before, registered) = rt.store.get_registered("codex.json").unwrap();
    let mut parsed = (*before).clone();
    parsed.parsed_by_plugin = true;
    rt.store.upsert(parsed);
    let (current, now) = rt.store.get_registered("codex.json").unwrap();
    assert_eq!(current.metadata, before.metadata, "only source ownership changed");
    assert!(current.revision > before.revision);
    assert!(now.credential_version > registered.credential_version);
    assert!(native_credential_file(&current).is_none());
    answer.add_permits(1);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap()
            .is_err(),
        "the final locked reread must reject the ownership change"
    );

    // The lower commit fence must also reject it. Both Codex token partitions still
    // match, which would otherwise allow a credential-version change to be rebased.
    let patch = MetadataPatch {
        set: json!({"access_token":"late-token", "refresh_token":"late-grant"})
            .as_object()
            .unwrap()
            .clone(),
        remove: vec![],
    };
    let committed = commit_refresh(
        &rt.store,
        &before.id,
        &before,
        RefreshFence {
            registered,
            plugin: false,
        },
        &patch,
        |_| {},
        None,
    );
    assert!(matches!(committed, Err(PatchError::NotFound)), "{committed:?}");
    assert_eq!(rt.store.get("codex.json").unwrap().metadata, before.metadata);
    assert_eq!(std::fs::read(&file.path).unwrap(), original_file);
    assert!(rt.store.unauthorized().refreshed.is_empty());

    // The reverse handoff cannot start native refresh using the plugin's lack of a
    // file lease. Its next preparation must acquire the native file lease first.
    rt.store.upsert((*before).clone());
    let (native, restored) = rt.store.get_registered("codex.json").unwrap();
    assert_eq!(restored.registration, now.registration);
    assert!(native_credential_file(&native).is_some());
    assert!(matches!(
        rt.store.read_refresh_file(&native.id, now.registration, None, None),
        Err(PatchError::NotFound)
    ));
    server.abort();
}

#[test]
fn confirmed_outer_refresh_can_revalidate_the_same_token_without_clearing_siwc() {
    for edit_during_refresh in [false, true] {
        let file = AuthFile::new();
        let mut cfg = Config::parse("").unwrap();
        cfg.auth_dir = file.dir.clone();
        let store = CredentialStore::new(cpa_core::config::credentials::from_auth_dir(&cfg));
        let selection = Selection::new("codex", "test-model");
        store.select(selection.clone()).unwrap().complete(unauthorized());
        let (current, registered) = store.get_registered("codex.json").unwrap();
        assert!(store.token_rejected(&current));
        if edit_during_refresh {
            let mut edited = (*current).clone();
            edited.metadata.insert("note".into(), "edited while refreshing".into());
            store.upsert(edited);
        }
        let patch = MetadataPatch {
            set: json!({"access_token":"original", "refresh_token":"rotated-grant"})
                .as_object()
                .unwrap()
                .clone(),
            remove: vec![],
        };
        let current = commit_refresh(
            &store,
            &current.id,
            &current,
            RefreshFence {
                registered,
                plugin: false,
            },
            &patch,
            |_| {},
            None,
        )
        .unwrap();
        assert!(
            !store.token_rejected(&current),
            "successful outer refresh follows Go's revalidation exception"
        );
        let patch = MetadataPatch {
            set: json!({"use_siwc":true}).as_object().unwrap().clone(),
            remove: vec![],
        };
        store.apply_patch(&current.id, current.revision, &patch).unwrap();
        store.select(selection.clone()).unwrap().complete(unauthorized());
        let (current, registered) = store.get_registered("codex.json").unwrap();
        let patch = MetadataPatch {
            set: json!({"access_token":"different-outer", "refresh_token":"next-grant"})
                .as_object()
                .unwrap()
                .clone(),
            remove: vec![],
        };
        let current = commit_refresh(
            &store,
            &current.id,
            &current,
            RefreshFence {
                registered,
                plugin: false,
            },
            &patch,
            |_| {},
            None,
        )
        .unwrap();
        store.reset_cooldown(&current.id);
        assert!(store.token_rejected(&current));
        assert!(
            store.select(selection).is_none(),
            "outer recovery cannot revive rejected SIWC"
        );
    }
}

#[test]
fn late_rejections_remain_recorded_without_refreshing_an_unrelated_selected_token() {
    for header_override in [false, true] {
        let file = AuthFile::new();
        let mut cfg = Config::parse("").unwrap();
        cfg.auth_dir = file.dir.clone();
        let store = CredentialStore::new(cpa_core::config::credentials::from_auth_dir(&cfg));
        let selection = Selection::new("codex", "test-model");
        let old = store.select(selection.clone()).unwrap();
        let mut changed = (*old.credential).clone();
        if header_override {
            changed
                .attributes
                .insert("header:Authorization".into(), "Bearer operator-token".into());
        } else {
            changed.metadata.insert("use_siwc".into(), true.into());
        }
        store.upsert(changed);
        old.complete(unauthorized());
        assert!(store.select(selection.clone()).is_some());
        assert!(
            store.unauthorized().pending.is_empty(),
            "the active token was not rejected"
        );

        let mut restored = (*store.get("codex.json").unwrap()).clone();
        restored.attributes.remove("header:Authorization");
        restored.metadata.insert("use_siwc".into(), false.into());
        store.upsert(restored);
        assert!(
            store.select(selection).is_none(),
            "switching back retains the rejected token"
        );
        assert!(store.unauthorized().pending.contains_key("codex.json"));
    }
}
