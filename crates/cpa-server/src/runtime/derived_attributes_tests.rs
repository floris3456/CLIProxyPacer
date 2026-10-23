use super::*;
use serde_json::json;
use std::path::PathBuf;

struct AuthFile {
    dir: PathBuf,
    path: PathBuf,
}

impl AuthFile {
    fn new(document: Value) -> Self {
        let dir = std::env::temp_dir().join(format!("cpa-derived-attributes-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = Self {
            path: dir.join("account.json"),
            dir,
        };
        file.write(document);
        file
    }

    fn write(&self, document: Value) {
        std::fs::write(&self.path, document.to_string()).unwrap();
    }

    fn store(&self) -> Arc<CredentialStore> {
        let mut cfg = Config::parse("").unwrap();
        cfg.auth_dir = self.dir.clone();
        CredentialStore::new(cpa_core::config::credentials::from_auth_dir(&cfg))
    }
}

impl Drop for AuthFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn shared_file_adoption_updates_kimi_endpoint_headers_and_routing_attributes() {
    let file = AuthFile::new(json!({
        "type":"kimi", "access_token":"old-token", "refresh_token":"old-grant",
        "domain":"kimi.com", "base_url":"https://api.kimi.com/coding/old",
        "headers":{"Authorization":"Bearer old-override", "X-Old":"remove"},
        "fingerprint_profile":"node", "proxy_url":"http://127.0.0.1:12340",
        "prefix":"old", "model_aliases":[{"name":"kimi-k2", "alias":"old-alias"}],
        "excluded_models":["old-model"], "priority":2, "weight":3, "note":"old note"
    }));
    let store = file.store();
    let (_, registration) = store.get_registered("account.json").unwrap();
    let lease = CredentialFileLease::acquire_blocking(&file.path).unwrap();
    file.write(json!({
        "type":"kimi", "access_token":"new-token", "refresh_token":"new-grant",
        "domain":"ai", "headers":{"authorization":"Bearer new-override", "X-New":"add"},
        "fingerprint-profile":" CHROME ", "proxy-url":"http://127.0.0.1:12341",
        "prefix":"/new/", "model-aliases":[{"name":"kimi-k2", "alias":"new-alias"}],
        "excluded-models":[" NEW-MODEL "], "priority":4, "weight":5, "note":"new note"
    }));
    let (current, _) = store
        .read_refresh_file("account.json", registration.registration, Some(&lease), None)
        .unwrap();

    assert_eq!(current.str("access_token"), Some("new-token"));
    assert_eq!(
        cpa_exec::kimi_auth::resolve_domain(&current),
        cpa_exec::kimi_auth::DOMAIN_AI
    );
    assert_eq!(current.attributes["domain"], "kimi.ai");
    assert_eq!(current.attributes["base_url"], "https://api.kimi.ai/coding");
    assert_eq!(current.attributes["header:authorization"], "Bearer new-override");
    assert_eq!(current.attributes["header:X-New"], "add");
    assert!(!current.attributes.contains_key("header:Authorization"));
    assert!(!current.attributes.contains_key("header:X-Old"));
    assert_eq!(current.attributes["fingerprint_profile"], "chrome");
    assert_eq!(current.attributes["proxy_url"], "http://127.0.0.1:12341");
    assert_eq!(current.attributes["prefix"], "new");
    assert_eq!(current.attributes["excluded_models"], "new-model");
    assert_eq!(current.attributes["priority"], "4");
    assert_eq!(current.attributes["weight"], "5");
    assert_eq!(current.attributes["note"], "new note");
    assert_eq!(
        serde_json::from_str::<Value>(&current.attributes["model_aliases"]).unwrap(),
        json!([{"name":"kimi-k2", "alias":"new-alias"}])
    );
}

#[test]
fn final_file_adoption_preserves_concurrent_edits_and_explicit_execution_overrides() {
    let file = AuthFile::new(json!({
        "type":"kimi", "access_token":"original-token", "refresh_token":"original-grant",
        "domain":"kimi.com", "headers":{"Authorization":"Bearer file-old", "X-Trace":"file-old"},
        "fingerprint_profile":"node", "proxy_url":"http://127.0.0.1:12340", "note":"original note"
    }));
    let store = file.store();
    let mut baseline = (*store.get("account.json").unwrap()).clone();
    for (key, value) in [
        ("base_url", "http://127.0.0.1:12342/coding"),
        ("proxy_url", "direct"),
        ("fingerprint_profile", "test-profile"),
        ("header:authorization", "Bearer execution-override"),
        ("header:X-Trace", "execution-trace"),
        ("token_url", "http://127.0.0.1:12343/token"),
    ] {
        baseline.attributes.insert(key.into(), value.into());
    }
    store.upsert(baseline.clone());
    let mut edited = baseline.clone();
    edited.metadata.insert("note".into(), "memory note".into());
    edited.attributes.insert("note".into(), "memory note".into());
    store.upsert(edited);
    let (_, registration) = store.get_registered("account.json").unwrap();
    let lease = CredentialFileLease::acquire_blocking(&file.path).unwrap();
    file.write(json!({
        "type":"kimi", "access_token":"disk-token", "refresh_token":"disk-grant",
        "domain":"kimi.ai", "base-url":"https://api.kimi.ai/coding/new",
        "headers":{"AUTHORIZATION":"Bearer file-new", "X-Trace":"file-new", "X-New":"new"},
        "fingerprint_profile":"chrome", "proxy_url":"http://127.0.0.1:12344", "note":"disk note"
    }));
    let (current, _) = store
        .read_refresh_file("account.json", registration.registration, Some(&lease), Some(&baseline))
        .unwrap();

    assert_eq!(current.str("access_token"), Some("disk-token"));
    assert_eq!(current.str("refresh_token"), Some("disk-grant"));
    assert_eq!(current.str("note"), Some("memory note"));
    assert_eq!(current.attributes["note"], "memory note");
    assert_eq!(current.str("base_url"), Some("https://api.kimi.ai/coding/new"));
    assert_eq!(current.attributes["domain"], "kimi.ai");
    assert_eq!(current.attributes["base_url"], "http://127.0.0.1:12342/coding");
    assert_eq!(current.attributes["proxy_url"], "direct");
    assert_eq!(current.attributes["fingerprint_profile"], "test-profile");
    assert_eq!(current.attributes["token_url"], "http://127.0.0.1:12343/token");
    assert_eq!(current.attributes["header:X-Trace"], "execution-trace");
    assert_eq!(current.attributes["header:X-New"], "new");
    let authorization: Vec<_> = current
        .attributes
        .iter()
        .filter(|(name, _)| {
            name.strip_prefix("header:")
                .is_some_and(|name| name.eq_ignore_ascii_case("authorization"))
        })
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(authorization, [("header:authorization", "Bearer execution-override")]);
}

#[test]
fn direct_patch_adopts_removed_file_headers_fingerprint_and_codex_plan() {
    let file = AuthFile::new(json!({
        "type":"codex", "access_token":"old-token", "plan_type":"plus",
        "headers":{"Authorization":"Bearer obsolete-override"},
        "fingerprint_profile":"node", "proxy_url":"http://127.0.0.1:12340",
        "prefix":"old", "model_aliases":[{"name":"gpt-5", "alias":"old-alias"}],
        "excluded_models":["old-model"], "priority":2, "weight":3
    }));
    let store = file.store();
    let current = store.get("account.json").unwrap();
    file.write(json!({"type":"codex", "access_token":"new-token", "prefix":"invalid/prefix"}));
    let current = store
        .apply_patch(
            "account.json",
            current.revision,
            &MetadataPatch {
                set: json!({"note":"local patch"}).as_object().unwrap().clone(),
                remove: Vec::new(),
            },
        )
        .unwrap();

    assert_eq!(current.str("access_token"), Some("new-token"));
    assert_eq!(current.str("note"), Some("local patch"));
    assert_eq!(current.attributes["prefix"], "");
    assert_eq!(current.attributes["note"], "local patch");
    for key in [
        "header:Authorization",
        "fingerprint_profile",
        "proxy_url",
        "plan_type",
        "model_aliases",
        "excluded_models",
        "priority",
        "file_priority",
        "weight",
    ] {
        assert!(!current.attributes.contains_key(key), "stale file attribute {key}");
    }
    assert!(!cpa_exec::token_identity::has_auth_override(&current));
}
