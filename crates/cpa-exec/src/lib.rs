//! Upstream executors. One module per provider; each owns its wire format, auth headers
//! and HTTP client profile. [`Executors`] dispatches on `Credential::provider`.
//!
//! Each call gets the config snapshot current when the request started, so a hot reload
//! never changes behaviour halfway through one execution.
//!
//! Credential preparation (token refresh, device identity creation) is a two-step
//! contract so the runtime can single-flight it: [`Executors::readiness`] is a cheap
//! check, and [`Executors::prepare`] does the work and returns a [`MetadataPatch`] that
//! the runtime commits. Executors never write credential files themselves.
//!
//! Requests wait on [`Readiness::PrepareNow`] for missing identity, a required mint,
//! or an expired access token that can refresh. Valid tokens refresh in the background
//! inside the provider's lead. An unexpected upstream 401 allows one refresh-and-retry
//! unless a request-scoped error rule handles it.

pub mod aistudio;
pub mod antigravity;
pub mod antigravity_auth;
mod antigravity_compaction;
pub mod antigravity_credits;
mod antigravity_models;
mod antigravity_replay;
mod antigravity_request;
pub mod antigravity_version;
pub mod catalog_etag;
pub mod claude;
pub mod claude_login;
pub mod codex;
mod codex_capture;
pub mod codex_catalog_updater;
mod codex_client;
mod codex_images;
mod codex_json;
pub mod codex_live;
pub mod codex_oauth;
pub mod codex_quota;
mod codex_replay;
mod codex_request;
mod codex_response;
pub mod codex_siwc;
pub mod codex_siwc_bind;
mod codex_sse;
#[cfg(test)]
mod codex_testkit;
mod codex_tls;
mod codex_tokens;
mod codex_ws;
pub mod devin;
pub mod devin_auth;
pub mod devin_models;
mod devin_payload;
mod devin_request;
mod devin_wire;
pub mod gemini;
mod gemini_payload;
mod gemini_stream;
mod home_replay;
pub mod kimi;
pub mod kimi_auth;
#[cfg(test)]
mod kimi_fixture;
mod kimi_http;
mod kimi_replay;
pub mod meta;
pub mod meta_auth;
mod meta_codex;
mod meta_wire;
pub mod oauth;
#[cfg(test)]
mod oauth_redirect_tests;
pub mod openai_compat;
mod openai_compat_go;
mod openai_compat_http;
pub mod openai_compat_multipart;
mod openai_compat_payload;
#[cfg(test)]
mod openai_compat_usage;
mod payload_barrier;
mod payload_media;
pub mod proxy;
mod quota;
mod rawjson;
mod replay;
#[cfg(test)]
mod test_tls;
mod tls;
mod tokenizer;
mod tokens;
mod translate;
mod upstream;
pub mod vertex;
pub mod vertex_auth;
mod wire;
mod ws_observation;
pub mod wsrelay;
pub mod xai;
pub mod xai_auth;
mod xai_replay;
mod xai_request;
mod xai_response;
pub mod xai_url;
mod xai_ws;

use cpa_core::config::Config;
use cpa_core::credential::{Credential, MetadataPatch};
use cpa_core::exec::{ExecError, ExecRequest, ExecResponse, ExecSession, FailureScope};

/// Go `Auth.ExpirationTime`, `authLastRefreshTimestamp` and `authPreferredInterval`, for
/// the server's plugin refresh schedule (Go `shouldRefresh` for providers without a lead).
pub use kimi_http::{expiration, last_refresh, preferred_interval};
/// Go `helps.EnsureResponsesUsageDetails`, for paths outside the executors (plugin
/// executors' Responses payloads and stream chunks).
pub use openai_compat_payload::ensure_responses_usage_details;
pub use xai_ws::websockets_enabled;

/// What a credential needs before or around use. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Usable as is; nothing to refresh.
    Ready,
    /// Usable now; the background refresh loop should prepare it.
    RefreshSoon,
    /// Unusable until prepared; requests wait on the single-flighted preparation.
    PrepareNow,
}

/// Expiry of the token used for inference, not a different Codex token partition.
/// API keys and tokens with unknown expiry are left to their provider's validation.
pub fn access_token_expired(credential: &Credential, now: chrono::DateTime<chrono::Utc>) -> bool {
    if credential.provider == "codex" && codex_siwc::enabled(credential) {
        return !codex_siwc::access_token(credential).is_empty() && !codex_siwc::access_usable(credential, now);
    }
    let api_key = credential
        .attributes
        .get("api_key")
        .map(String::as_str)
        .unwrap_or_default();
    let stored = credential.str("access_token").unwrap_or_default();
    let token = match credential.provider.as_str() {
        "claude" if api_key.is_empty() && stored.contains("sk-ant-oat") => stored,
        "codex" if api_key.is_empty() && !cpa_core::registry::dynamic::is_api_key(credential) => stored,
        xai::PROVIDER if api_key.trim().is_empty() && !cpa_core::registry::dynamic::is_api_key(credential) => stored,
        antigravity::PROVIDER => stored,
        p if kimi::PROVIDERS.contains(&p) => {
            if stored.trim().is_empty() && credential.attributes.get("access_token").is_none_or(String::is_empty) {
                return false;
            }
            kimi::access_token(credential)
        }
        // These fields are API keys, mint grants, or unused on other providers.
        _ => return false,
    };
    !token.trim().is_empty() && kimi_http::token_expiration(token, credential).is_some_and(|expiry| expiry <= now)
}

pub struct Executors {
    pub claude: claude::ClaudeExecutor,
    pub codex: codex::CodexExecutor,
    /// Device-login providers (Kimi, Meta, Devin). `Default` builds production clients.
    pub devices: DeviceExecutors,
    /// API-key upstreams speaking OpenAI wire formats (OpenAI-compatible providers, xAI).
    pub openai: OpenAIExecutors,
    /// Google-family providers (Gemini API keys, native Interactions keys).
    pub google: GoogleExecutors,
}

/// Google-family executors, grouped like [`DeviceExecutors`].
#[derive(Default)]
pub struct GoogleExecutors {
    /// `gemini` and `gemini-interactions` API keys.
    pub gemini: gemini::GeminiExecutor,
    /// `vertex` service accounts and API keys.
    pub vertex: vertex::VertexExecutor,
    /// `aistudio` sessions on the `/v1/ws` relay, which the server route shares.
    pub aistudio: aistudio::AiStudioExecutor,
    /// `antigravity` OAuth credentials.
    pub antigravity: antigravity::AntigravityExecutor,
}

/// OpenAI-wire executors, grouped like [`DeviceExecutors`].
#[derive(Default)]
pub struct OpenAIExecutors {
    pub compat: openai_compat::OpenAICompatExecutor,
    pub xai: xai::XaiExecutor,
}

/// Executors for the device-login providers, grouped so adding one does not touch every
/// [`Executors`] construction site.
#[derive(Default)]
pub struct DeviceExecutors {
    pub kimi: kimi::KimiExecutor,
    pub meta: meta::MetaExecutor,
    pub devin: devin::DevinExecutor,
}

impl Executors {
    pub async fn execute(
        &self,
        credential: &Credential,
        req: ExecRequest,
        cfg: &Config,
    ) -> Result<ExecResponse, ExecError> {
        proxy::Proxy::effective(credential, cfg).validate()?;
        match credential.provider.as_str() {
            "claude" => self.claude.execute(credential, req, cfg).await,
            "codex" => self.codex.execute(credential, req, cfg).await,
            p if kimi::PROVIDERS.contains(&p) => self.devices.kimi.execute(&self.claude, credential, req, cfg).await,
            meta::PROVIDER => self.devices.meta.execute(credential, req, cfg).await,
            devin::PROVIDER => self.devices.devin.execute(credential, req, cfg).await,
            p if openai_compat::handles(p) => self.openai.compat.execute(credential, req, cfg).await,
            p if gemini::handles(p) => self.google.gemini.execute(credential, req, cfg).await,
            p if vertex::handles(p) => self.google.vertex.execute(credential, req, cfg).await,
            p if aistudio::handles(p) => self.google.aistudio.execute(credential, req, cfg).await,
            antigravity::PROVIDER => self.google.antigravity.execute(credential, req, cfg).await,
            xai::PROVIDER => self.openai.xai.execute(credential, req, cfg, false).await,
            other => Err(no_executor(other)),
        }
    }

    /// The Images API (`/v1/images/generations`, `/v1/images/edits`) for providers that
    /// serve it directly. `request_path` is the inbound route; `req.stream` asks for the
    /// upstream event stream passed through raw.
    pub async fn images(
        &self,
        credential: &Credential,
        req: ExecRequest,
        request_path: &str,
        cfg: &Config,
    ) -> Result<ExecResponse, ExecError> {
        proxy::Proxy::effective(credential, cfg).validate()?;
        match credential.provider.as_str() {
            "codex" => self.codex.images(credential, req, request_path, cfg).await,
            p if openai_compat::handles(p) => self.openai.compat.images(credential, req, request_path, cfg).await,
            xai::PROVIDER => self.openai.xai.images(credential, req, request_path, cfg).await,
            other => Err(no_executor(other)),
        }
    }

    /// The Videos API (`/v1/videos*`, `/openai/v1/videos*`) for providers that serve it.
    /// `request_path` is the inbound route; a route other than generations, edits or
    /// extensions polls the job named by the body's `request_id`.
    pub async fn videos(
        &self,
        credential: &Credential,
        req: ExecRequest,
        request_path: &str,
        cfg: &Config,
    ) -> Result<ExecResponse, ExecError> {
        proxy::Proxy::effective(credential, cfg).validate()?;
        match credential.provider.as_str() {
            xai::PROVIDER => self.openai.xai.videos(credential, req, request_path, cfg).await,
            other => Err(no_executor(other)),
        }
    }

    /// The OpenAI speech routes (`/v1/audio/speech`, `/v1/tts`): Go's `openai-speech`
    /// source, which only the xAI executor serves.
    pub async fn speech(
        &self,
        credential: &Credential,
        req: ExecRequest,
        cfg: &Config,
    ) -> Result<ExecResponse, ExecError> {
        proxy::Proxy::effective(credential, cfg).validate()?;
        match credential.provider.as_str() {
            xai::PROVIDER => self.openai.xai.speech(credential, req, cfg).await,
            other => Err(no_executor(other)),
        }
    }

    /// One turn of a downstream Responses WebSocket session. Codex and xAI credentials
    /// with `websockets` keep a pooled upstream socket per session; every other credential
    /// runs an ordinary execution and cannot continue upstream state, so a continuation
    /// turn fails with [`ExecError::replay_required`].
    pub async fn execute_in_session(
        &self,
        credential: &Credential,
        req: ExecRequest,
        cfg: &Config,
        session: &ExecSession,
    ) -> Result<ExecResponse, ExecError> {
        proxy::Proxy::effective(credential, cfg).validate()?;
        match credential.provider.as_str() {
            "codex" => self.codex.execute_in_session(credential, req, cfg, session).await,
            xai::PROVIDER => self.openai.xai.execute_in_session(credential, req, cfg, session).await,
            _ if session.continuation => Err(ExecError::replay_required()),
            _ => self.execute(credential, req, cfg).await,
        }
    }

    /// Whether `credential` keeps upstream conversation state on a session socket, so
    /// the next turn may be sent as an incremental continuation.
    pub fn session_upstream(&self, credential: &Credential) -> bool {
        match credential.provider.as_str() {
            "codex" => codex::CodexExecutor::upstream_websocket(credential),
            xai::PROVIDER => xai::XaiExecutor::session_upstream(credential),
            _ => false,
        }
    }

    /// Resolves when an upstream socket held for session `id` is lost; pending forever
    /// when no executor holds one.
    pub fn session_closed(&self, id: &str) -> impl std::future::Future<Output = ExecError> + Send + 'static {
        let codex = self.codex.session_closed(id);
        let xai = self.openai.xai.session_closed(id);
        async move {
            tokio::select! {
                error = codex => error,
                error = xai => error,
            }
        }
    }

    /// Releases everything executors hold for session `id`.
    pub fn close_session(&self, id: &str) {
        self.codex.close_session(id);
        self.openai.xai.close_session(id);
    }

    /// Go `CloseCodexWebsocketSessionsForAuthID` and `CloseXAIWebsocketSessionsForAuthID`
    /// for the credential store: given a removed credential's id, ends only the upstream
    /// WebSocket sessions that credential serves.
    pub fn credential_session_closer(&self) -> impl Fn(&str) + Send + Sync + 'static {
        let codex = self.codex.ws.clone();
        let xai = self.openai.xai.ws.clone();
        move |id| {
            codex.close_credential(id);
            xai.close_credential(id);
        }
    }

    /// Whether an executor serves this provider. Credentials of other providers never
    /// enter selection (Go skips auths whose executor is not registered).
    pub fn supports(&self, provider: &str) -> bool {
        matches!(
            provider,
            "claude" | "codex" | meta::PROVIDER | xai::PROVIDER | devin::PROVIDER
        ) || kimi::PROVIDERS.contains(&provider)
            || openai_compat::handles(provider)
            || gemini::handles(provider)
            || vertex::handles(provider)
            || aistudio::handles(provider)
            || antigravity::handles(provider)
    }

    /// Go `authHasRefreshCredential`: whether an upstream 401 on `credential` should be
    /// followed by one forced [`Self::prepare`] and a retry (Go
    /// `tryRefreshAfterUnauthorized`). A refresh token qualifies for every provider;
    /// Meta re-mints its API key from its device token. Providers that recover from a
    /// 401 another way add an arm here.
    pub fn has_refresh_credential(&self, credential: &Credential) -> bool {
        let filled = |v: Option<&str>| v.is_some_and(|v| !v.trim().is_empty());
        if filled(credential.str("refresh_token")) || filled(credential.str("refreshToken")) {
            return true;
        }
        // Go `CodexSIWCNeedsRefresh`'s hasRefresh: a `siwc` refresh token and client ID.
        // ponytail: Go asks it of every provider; Codex only until the Claude replay.
        if credential.provider == "codex" && codex_siwc::refresh_due(credential, chrono::Utc::now()).is_some() {
            return true;
        }
        credential.provider.trim().eq_ignore_ascii_case("meta")
            && (filled(credential.str("dca_token"))
                || filled(credential.attributes.get("dca_token").map(String::as_str)))
    }

    /// Whether `credential` needs preparation, and whether requests must wait for it.
    /// Must be cheap and side-effect free. Providers without request-time preparation
    /// report `RefreshSoon` whenever `needs_prepare` holds.
    pub fn readiness(&self, credential: &Credential, cfg: &Config) -> Readiness {
        let now = chrono::Utc::now();
        if self.has_refresh_credential(credential) && access_token_expired(credential, now) {
            return Readiness::PrepareNow;
        }
        if !self.needs_prepare_at(credential, cfg, now) {
            return Readiness::Ready;
        }
        match credential.provider.as_str() {
            "claude" if oauth::needs_identity(credential) => Readiness::PrepareNow,
            meta::PROVIDER if self.devices.meta.must_mint(credential) => Readiness::PrepareNow,
            antigravity::PROVIDER if self.google.antigravity.must_prepare(credential) => Readiness::PrepareNow,
            _ => Readiness::RefreshSoon,
        }
    }

    /// Whether `credential` needs any preparation (`readiness` is not `Ready`). Must be
    /// cheap and side-effect free. Providers implement this; the runtime reads
    /// [`Self::readiness`].
    pub fn needs_prepare(&self, credential: &Credential, cfg: &Config) -> bool {
        self.needs_prepare_at(credential, cfg, chrono::Utc::now())
    }

    /// [`Self::needs_prepare`] as of `now`. Once true it stays true as time passes until
    /// the credential is prepared: every provider compares an expiry or a last refresh
    /// with the clock.
    pub fn needs_prepare_at(&self, credential: &Credential, cfg: &Config, now: chrono::DateTime<chrono::Utc>) -> bool {
        match credential.provider.as_str() {
            "claude" => self.claude.needs_prepare_at(credential, cfg, now),
            "codex" => self.codex.needs_prepare_at(credential, cfg, now),
            p if kimi::PROVIDERS.contains(&p) => self.devices.kimi.needs_prepare_at(credential, cfg, now),
            meta::PROVIDER => self.devices.meta.needs_prepare_at(credential, cfg, now),
            xai::PROVIDER => self.openai.xai.needs_prepare_at(credential, cfg, now),
            devin::PROVIDER => self.devices.devin.needs_prepare_at(credential, cfg, now),
            antigravity::PROVIDER => self.google.antigravity.needs_prepare_at(credential, cfg, now),
            _ => false,
        }
    }

    /// The earliest time within `horizon` of `now` at which `credential` needs
    /// preparation (`now` if it already does), to one second. Bisects
    /// [`Self::needs_prepare_at`], so every provider's own rule decides; about a dozen
    /// cheap evaluations for a credential that comes due inside the horizon, one for
    /// the rest.
    pub fn prepare_due(
        &self,
        credential: &Credential,
        cfg: &Config,
        now: chrono::DateTime<chrono::Utc>,
        horizon: chrono::Duration,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        if self.needs_prepare_at(credential, cfg, now) {
            return Some(now);
        }
        let (mut lo, mut hi) = (now, now + horizon);
        if !self.needs_prepare_at(credential, cfg, hi) {
            return None;
        }
        while hi - lo > chrono::Duration::seconds(1) {
            let mid = lo + (hi - lo) / 2;
            if self.needs_prepare_at(credential, cfg, mid) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        Some(hi)
    }

    /// The runtime registered models for `credentials` (Go `registerModelsForAuth`):
    /// providers that probe capabilities after registration start here. Must not block.
    pub fn models_registered(&self, credentials: &[std::sync::Arc<Credential>], cfg: &Config) {
        self.google.antigravity.models_registered(credentials, cfg);
    }

    /// [`Self::prepare`] for a credential whose access token an upstream rejected, or a
    /// management refresh: Codex refreshes even when not due (Go marks the token rejected
    /// or forces the refresh). Other providers prepare as usual; most of them (Claude
    /// once its identity is known, Kimi, Meta, Devin) refresh whenever asked.
    pub async fn prepare_forced(&self, credential: &Credential, cfg: &Config) -> Result<MetadataPatch, ExecError> {
        match credential.provider.as_str() {
            "codex" => {
                proxy::Proxy::effective(credential, cfg).validate()?;
                self.codex.refresh_now(credential, cfg).await
            }
            _ => self.prepare(credential, cfg).await,
        }
    }

    /// [`Self::prepare_forced`] for a management refresh (Go `IsForceRefreshContext`):
    /// Codex refreshes every token partition that can refresh.
    pub async fn prepare_management(&self, credential: &Credential, cfg: &Config) -> Result<MetadataPatch, ExecError> {
        match credential.provider.as_str() {
            "codex" => {
                proxy::Proxy::effective(credential, cfg).validate()?;
                self.codex.refresh_all(credential, cfg).await
            }
            _ => self.prepare_forced(credential, cfg).await,
        }
    }

    /// Prepares `credential` and returns the metadata change to commit.
    pub async fn prepare(&self, credential: &Credential, cfg: &Config) -> Result<MetadataPatch, ExecError> {
        proxy::Proxy::effective(credential, cfg).validate()?;
        match credential.provider.as_str() {
            "claude" => self.claude.prepare(credential, cfg).await,
            "codex" => self.codex.prepare(credential, cfg).await,
            p if kimi::PROVIDERS.contains(&p) => self.devices.kimi.prepare(credential, cfg).await,
            meta::PROVIDER => self.devices.meta.prepare(credential, cfg).await,
            xai::PROVIDER => self.openai.xai.prepare(credential, cfg).await,
            devin::PROVIDER => self.devices.devin.prepare(credential, cfg).await,
            antigravity::PROVIDER => self.google.antigravity.prepare(credential, cfg).await,
            other => Err(no_executor(other)),
        }
    }
}

fn no_executor(provider: &str) -> ExecError {
    ExecError::local(
        500,
        FailureScope::Credential,
        format!("no executor for provider {provider:?}"),
    )
}

#[cfg(test)]
mod readiness_tests {
    use super::{Executors, Readiness, access_token_expired, claude};
    use cpa_core::config::Config;
    use cpa_core::credential::Credential;
    use std::path::Path;

    fn credential(metadata: serde_json::Value) -> Credential {
        Credential::from_file(
            Path::new("/auth"),
            Path::new("/auth/a.json"),
            metadata.as_object().unwrap().clone(),
        )
        .unwrap()
    }

    fn rfc3339(offset: chrono::Duration) -> String {
        (chrono::Utc::now() + offset).to_rfc3339()
    }

    #[tokio::test]
    async fn invalid_proxy_blocks_provider_dispatch_and_preparation() {
        use cpa_core::exec::{Caller, ExecRequest, FailureScope, Operation};
        use cpa_core::format::Format;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let executors = Executors {
            claude: claude::ClaudeExecutor::new(&endpoint).unwrap(),
            codex: Default::default(),
            devices: Default::default(),
            openai: Default::default(),
            google: Default::default(),
        };
        let request = ExecRequest {
            operation: Operation::Generate,
            source_format: Format::OpenAI,
            response_format: Format::OpenAI,
            requested_model: "test-model".into(),
            model: "test-model".into(),
            original_body: "{}".into(),
            body: "{}".into(),
            stream: false,
            stream_payloads: false,
            alt: None,
            session: None,
            execution_session: None,
            derived_session: None,
            request_path: String::new(),
            headers: Default::default(),
            caller: Caller {
                principal: String::new(),
                source: "",
                provider: String::new(),
            },
            resolved_model: None,
            usage: Default::default(),
        };
        let cfg = Config::default();
        for provider in [
            "claude",
            "codex",
            "kimi",
            "meta",
            "devin",
            "gemini",
            "vertex",
            "aistudio",
            "antigravity",
            "xai",
            "openai",
        ] {
            let mut c = credential(serde_json::json!({
                "type": provider, "access_token": "test-token", "refresh_token": "test-refresh"
            }));
            c.attributes.insert("base_url".into(), endpoint.clone());
            c.attributes
                .insert("proxy_url".into(), "unsupported://user:secret@proxy.invalid".into());
            let dispatch = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                executors.execute(&c, request.clone(), &cfg),
            )
            .await
            .expect("proxy rejection must precede I/O")
            .err()
            .expect("invalid proxy accepted");
            let preparation = executors.prepare(&c, &cfg).await.unwrap_err();
            for error in [dispatch, preparation] {
                assert_eq!(error.status, 502, "{provider}");
                assert_eq!(error.scope, FailureScope::Transport, "{provider}");
                assert!(!error.to_string().contains("secret"));
            }
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept())
                .await
                .is_err()
        );
    }

    /// Valid tokens refresh in the background; missing identity and expired tokens
    /// must be prepared before dispatch.
    #[test]
    fn missing_identity_and_expired_tokens_block_requests() {
        let executors = Executors {
            claude: claude::ClaudeExecutor::new("http://127.0.0.1:1").unwrap(),
            codex: Default::default(),
            devices: Default::default(),
            openai: Default::default(),
            google: Default::default(),
        };
        let cfg = Config::default();
        let pool = serde_json::json!(["a".repeat(64)]);
        let identified = |expired: String| {
            credential(serde_json::json!({
                "type": "claude",
                "access_token": "sk-ant-oat01-fake",
                "refresh_token": "fake-refresh",
                "claude_device_ids": pool,
                "account_uuid": "fake-account",
                "expired": expired,
            }))
        };
        let cases = [
            (identified(rfc3339(chrono::Duration::days(2))), Readiness::Ready),
            (identified(rfc3339(chrono::Duration::hours(1))), Readiness::RefreshSoon),
            (identified(rfc3339(-chrono::Duration::hours(1))), Readiness::PrepareNow),
            (
                credential(serde_json::json!({
                    "type": "claude",
                    "access_token": "sk-ant-oat01-fake",
                    "refresh_token": "fake-refresh",
                    "expired": rfc3339(-chrono::Duration::hours(1)),
                })),
                Readiness::PrepareNow,
            ),
            (
                credential(serde_json::json!({"type": "claude", "access_token": "sk-ant-api03-fake"})),
                Readiness::Ready,
            ),
            (
                credential(serde_json::json!({
                    "type": "kimi",
                    "access_token": "fake-access",
                    "refresh_token": "fake-refresh",
                    "expired": rfc3339(-chrono::Duration::hours(1)),
                })),
                Readiness::PrepareNow,
            ),
            // Antigravity: requests wait for the project ID and for a token valid five
            // more minutes (Go's inline refresh); otherwise the token refreshes 30
            // minutes ahead in the background.
            (
                credential(serde_json::json!({
                    "type": "antigravity",
                    "access_token": "fake-access",
                    "refresh_token": "fake-refresh",
                    "expired": rfc3339(chrono::Duration::hours(5)),
                })),
                Readiness::PrepareNow,
            ),
            (
                credential(serde_json::json!({
                    "type": "antigravity",
                    "project_id": "proj-1",
                    "access_token": "fake-access",
                    "refresh_token": "fake-refresh",
                    "expired": rfc3339(chrono::Duration::minutes(20)),
                })),
                Readiness::RefreshSoon,
            ),
            (
                credential(serde_json::json!({
                    "type": "antigravity",
                    "project_id": "proj-1",
                    "access_token": "fake-access",
                    "refresh_token": "fake-refresh",
                    "expired": rfc3339(chrono::Duration::minutes(6)),
                })),
                Readiness::RefreshSoon,
            ),
            (
                credential(serde_json::json!({
                    "type": "antigravity",
                    "project_id": "proj-1",
                    "access_token": "fake-access",
                    "refresh_token": "fake-refresh",
                    "expired": rfc3339(chrono::Duration::minutes(4)),
                })),
                Readiness::PrepareNow,
            ),
            (
                credential(serde_json::json!({
                    "type": "antigravity",
                    "project_id": "proj-1",
                    "refresh_token": "fake-refresh",
                    "expired": rfc3339(chrono::Duration::minutes(40)),
                })),
                Readiness::PrepareNow,
            ),
            (
                credential(serde_json::json!({
                    "type": "antigravity",
                    "project_id": "proj-1",
                    "access_token": "fake-access",
                })),
                Readiness::PrepareNow,
            ),
            (
                credential(serde_json::json!({
                    "type": "antigravity",
                    "project_id": "proj-1",
                    "access_token": "fake-access",
                    "refresh_token": "fake-refresh",
                    "expired": rfc3339(chrono::Duration::minutes(40)),
                })),
                Readiness::Ready,
            ),
        ];
        for (i, (c, expected)) in cases.iter().enumerate() {
            assert_eq!(executors.readiness(c, &cfg), *expected, "case {i}");
        }
    }

    #[test]
    fn expiry_checks_the_selected_token_partition() {
        let now = chrono::Utc::now();
        let past = (now - chrono::Duration::hours(1)).to_rfc3339();
        let future = (now + chrono::Duration::days(7)).to_rfc3339();
        let mut c = credential(serde_json::json!({
            "type": "codex", "access_token": "outer", "expired": past,
            "use_siwc": true,
            "siwc": {"access_token": "inner", "expired": future}
        }));
        assert!(
            !access_token_expired(&c, now),
            "inactive outer expiry must not block SIWC"
        );
        c.metadata.insert("use_siwc".into(), false.into());
        assert!(access_token_expired(&c, now));
        c.metadata.insert("expired".into(), future.into());
        c.metadata.get_mut("siwc").unwrap()["expired"] = past.into();
        assert!(
            !access_token_expired(&c, now),
            "inactive SIWC expiry must not block outer"
        );
        c.metadata.insert("use_siwc".into(), true.into());
        assert!(access_token_expired(&c, now));
        c.attributes.insert("api_key".into(), "configured-api-key".into());
        assert!(
            access_token_expired(&c, now),
            "SIWC takes precedence over the outer API key"
        );
        c.metadata.insert("use_siwc".into(), false.into());
        assert!(!access_token_expired(&c, now), "API keys do not use OAuth expiry");
    }

    #[test]
    fn expiry_ignores_inactive_tokens_and_api_key_fields() {
        let now = chrono::Utc::now();
        let past = (now - chrono::Duration::hours(1)).to_rfc3339();
        for provider in [
            "gemini",
            "vertex",
            "meta",
            "devin",
            "openai",
            "aistudio",
            "plugin-provider",
        ] {
            let c =
                credential(serde_json::json!({"type":provider,"access_token":"inactive-or-api-key","expired":past}));
            assert!(!access_token_expired(&c, now), "{provider}");
        }
        let mut c = credential(serde_json::json!({"type":"kimi","access_token":"selected-oauth-token","expired":past}));
        c.attributes.insert("api_key".into(), "inactive-key".into());
        assert!(access_token_expired(&c, now), "Kimi selects its metadata token first");
        c.metadata.remove("access_token");
        assert!(
            !access_token_expired(&c, now),
            "Kimi API-key fallback has no OAuth expiry"
        );
        c.metadata.insert("access_token".into(), "selected-oauth-token".into());
        c.provider = "antigravity".into();
        assert!(access_token_expired(&c, now), "Antigravity ignores API-key attributes");
        c.provider = "claude".into();
        c.attributes.clear();
        c.metadata.insert("access_token".into(), "sk-ant-api03-key".into());
        assert!(
            !access_token_expired(&c, now),
            "a Claude API key is not an OAuth access token"
        );
    }

    /// The refresh loop sleeps until `prepare_due`: each provider's own lead before
    /// expiry (Claude 4 h, Kimi 5 min), to the second, `now` once due, and nothing past
    /// the horizon.
    #[test]
    fn prepare_due_finds_each_providers_deadline() {
        let executors = Executors {
            claude: claude::ClaudeExecutor::new("http://127.0.0.1:1").unwrap(),
            codex: Default::default(),
            devices: Default::default(),
            openai: Default::default(),
            google: Default::default(),
        };
        let cfg = Config::default();
        let now = chrono::Utc::now();
        let horizon = chrono::Duration::hours(1);
        let with_expiry = |provider: &str, expiry: chrono::DateTime<chrono::Utc>| {
            credential(serde_json::json!({
                "type": provider,
                "access_token": "fake-access",
                "refresh_token": "fake-refresh",
                "expired": expiry.to_rfc3339(),
            }))
        };
        let near = |got: Option<chrono::DateTime<chrono::Utc>>, want: chrono::DateTime<chrono::Utc>| {
            let got = got.expect("due inside the horizon");
            assert!((got - want).num_milliseconds().abs() <= 1000, "{got} vs {want}");
        };
        let offset = chrono::Duration::seconds(1337);
        let claude = with_expiry("claude", now + chrono::Duration::hours(4) + offset);
        near(executors.prepare_due(&claude, &cfg, now, horizon), now + offset);
        let kimi = with_expiry("kimi", now + chrono::Duration::minutes(5) + offset);
        near(executors.prepare_due(&kimi, &cfg, now, horizon), now + offset);
        let due = with_expiry("claude", now - chrono::Duration::hours(1));
        assert_eq!(executors.prepare_due(&due, &cfg, now, horizon), Some(now));
        let later = with_expiry("claude", now + chrono::Duration::hours(6));
        assert_eq!(executors.prepare_due(&later, &cfg, now, horizon), None);
        let api_key = credential(serde_json::json!({"type": "claude", "access_token": "sk-ant-api03-fake"}));
        assert_eq!(executors.prepare_due(&api_key, &cfg, now, horizon), None);
    }

    /// Go `authHasRefreshCredential`.
    #[test]
    fn refresh_credentials_follow_go() {
        let executors = Executors {
            claude: claude::ClaudeExecutor::new("http://127.0.0.1:1").unwrap(),
            codex: Default::default(),
            openai: Default::default(),
            google: Default::default(),
            devices: Default::default(),
        };
        let has = |m: serde_json::Value| executors.has_refresh_credential(&credential(m));
        assert!(has(serde_json::json!({"type": "claude", "refresh_token": "fake"})));
        assert!(has(serde_json::json!({"type": "kimi", "refreshToken": "fake"})));
        assert!(!has(serde_json::json!({"type": "claude", "refresh_token": "  "})));
        // A Sign in with ChatGPT partition needs its refresh token and client ID.
        assert!(has(
            serde_json::json!({"type": "codex", "siwc": {"refresh_token": "fake", "client_id": "c"}})
        ));
        assert!(!has(
            serde_json::json!({"type": "codex", "siwc": {"refresh_token": "fake"}})
        ));
        assert!(
            !has(serde_json::json!({"type": "claude", "siwc": {"refresh_token": "fake", "client_id": "c"}})),
            "SIWC is Codex's"
        );
        assert!(has(serde_json::json!({"type": "meta", "dca_token": "fake"})));
        assert!(
            !has(serde_json::json!({"type": "claude", "dca_token": "fake"})),
            "dca_token is Meta's"
        );
        let mut meta = credential(serde_json::json!({"type": "meta"}));
        assert!(!executors.has_refresh_credential(&meta));
        meta.attributes.insert("dca_token".into(), "fake".into());
        assert!(executors.has_refresh_credential(&meta));
    }
}
