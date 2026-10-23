//! The Antigravity capability probe (sdk/cliproxy/antigravity_models.go): after an
//! Antigravity credential registers its models, `fetchAvailableModels` tells which of
//! them support native web search. The result lands in the model registry
//! (`cpa_core::registry::dynamic::set_web_search_hints`), which marks those models.
//!
//! Probes are shared like Go's: one result per base URLs and proxy for 5 minutes (1
//! minute after a failure), one probe at a time per key, and a 1-minute backoff for a
//! credential whose token was rejected.
// ponytail: Go probes on each registration, which also resets the flags until the probe
// lands; here a credential is probed when the registry first sees a new revision of it,
// and its previous hints stay until the new probe finishes. Config reloads alone do not
// re-probe.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;
use cpa_common::gostr::{GoStr, trim_space};
use cpa_common::json::{self as gj, Kind};
use cpa_core::config::Config;
use cpa_core::credential::Credential;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use sha2::{Digest, Sha256};

use crate::proxy::{self, GoClients, GoHeaders, Proxy};

const DAILY_BASE_URL: &str = "https://daily-cloudcode-pa.googleapis.com";
const MODELS_PATH: &str = "/v1internal:fetchAvailableModels";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const CACHE_TTL: Duration = Duration::from_secs(300);
const FAILURE_TTL: Duration = Duration::from_secs(60);

type Hints = HashSet<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Success,
    AuthError,
    Transient,
}

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// One probe's outcome as its singleflight shares it: the hints, the status and the
/// token it probed with (Go's `antigravityProbeResult`).
type Shared = (Hints, Status, String);

/// Go's package-level probe caches, behind one clock.
pub(crate) struct Capabilities {
    clock: Clock,
    /// `antigravityCapabilityProbeTimeout`, for the whole probe.
    timeout: Duration,
    /// Probe results by base URLs and proxy, with their expiry.
    cache: Mutex<HashMap<String, (Hints, Instant)>>,
    /// Credentials (`id#sha256(token)`) whose token a probe rejected, with the expiry.
    failures: Mutex<HashMap<String, Instant>>,
    /// The probe in flight per cache key, whose result every concurrent caller shares
    /// (Go's singleflight group): the hints, the status and the token it probed with.
    flights: Mutex<HashMap<String, Arc<tokio::sync::OnceCell<Shared>>>>,
    /// Callers inside `fetch` past the caches (`antigravityProbeInFlight`).
    in_flight: std::sync::atomic::AtomicUsize,
}

impl Capabilities {
    pub(crate) fn new(clock: Clock) -> Self {
        Self {
            clock,
            timeout: PROBE_TIMEOUT,
            cache: Mutex::default(),
            failures: Mutex::default(),
            flights: Mutex::default(),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    /// `purgeExpiredAntigravityCacheLocked`.
    fn purge(&self, now: Instant) {
        lock(&self.cache).retain(|_, (_, expires)| now < *expires);
        lock(&self.failures).retain(|_, expires| now < *expires);
    }

    fn cached(&self, key: &str, now: Instant) -> Option<Hints> {
        lock(&self.cache)
            .get(key)
            .filter(|(_, expires)| now < *expires)
            .map(|(hints, _)| hints.clone())
    }

    /// `fetchAntigravityModelCapabilityHintsForAuth`: the web-search model IDs for
    /// `credential`, empty on any failure. Concurrent callers of one cache key share the
    /// probe in flight; a caller whose token differs from a rejected probe's retries
    /// with its own, one with the same token backs off.
    pub(crate) async fn fetch(&self, client: &wreq::Client, credential: &Credential, proxy_url: &str) -> Hints {
        let token = credential.str("access_token").map(str::trim).unwrap_or_default();
        if token.is_empty() {
            return Hints::new();
        }
        let urls = base_urls(credential);
        let key = format!("{}#{proxy_url}", urls.join("|"));
        let failure_key = format!(
            "{}#{}",
            credential.id,
            Sha256::digest(token.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        loop {
            let now = self.now();
            if lock(&self.failures)
                .get(&failure_key)
                .is_some_and(|expires| now < *expires)
            {
                return Hints::new();
            }
            if let Some(hints) = self.cached(&key, now) {
                return hints;
            }
            self.in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let flight = lock(&self.flights).entry(key.clone()).or_default().clone();
            let (hints, status, probed) = flight
                .get_or_init(|| async {
                    let result = self.lead(client, &urls, &key, token).await;
                    let mut flights = lock(&self.flights);
                    if flights.get(&key).is_some_and(|current| Arc::ptr_eq(current, &flight)) {
                        flights.remove(&key);
                    }
                    result
                })
                .await
                .clone();
            self.in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            if status != Status::AuthError {
                return hints;
            }
            if probed != token {
                // Another account's token was rejected: probe with ours.
                continue;
            }
            self.purge(now);
            lock(&self.failures).insert(failure_key, self.now() + FAILURE_TTL);
            return Hints::new();
        }
    }

    /// The singleflight body: the cache once more, else a probe whose success or
    /// transient failure is cached (5 minutes or 1).
    async fn lead(&self, client: &wreq::Client, urls: &[String], key: &str, token: &str) -> Shared {
        let inside = self.now();
        if let Some(hints) = self.cached(key, inside) {
            return (hints, Status::Success, token.to_owned());
        }
        let (hints, status) = probe(client, urls, token, self.timeout).await;
        if status != Status::AuthError {
            let ttl = if status == Status::Success {
                CACHE_TTL
            } else {
                FAILURE_TTL
            };
            self.purge(inside);
            lock(&self.cache).insert(key.to_owned(), (hints.clone(), self.now() + ttl));
        }
        (hints, status, token.to_owned())
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The process-wide caches (Go's package state).
pub(crate) fn shared() -> &'static Capabilities {
    static SHARED: LazyLock<Capabilities> = LazyLock::new(|| Capabilities::new(Arc::new(Instant::now)));
    &SHARED
}

/// `antigravityModelBaseURLs`: `base_urls` (comma separated), else the credential's
/// base URL, else the daily endpoint.
fn base_urls(credential: &Credential) -> Vec<String> {
    let trim = |s: &str| s.trim().trim_end_matches('/').to_owned();
    if let Some(raw) = credential.attributes.get("base_urls").filter(|r| !r.trim().is_empty()) {
        let urls: Vec<String> = raw.split(',').map(trim).filter(|u| !u.is_empty()).collect();
        if !urls.is_empty() {
            return urls;
        }
    }
    let own = credential
        .attributes
        .get("base_url")
        .map(|v| trim(v))
        .filter(|v| !v.is_empty())
        .or_else(|| credential.str("base_url").map(trim).filter(|v| !v.is_empty()));
    vec![own.unwrap_or_else(|| DAILY_BASE_URL.to_owned())]
}

/// `probeAntigravityModelCapabilityHints`: every base URL at once within 5 seconds; the
/// first answer naming models wins, else the first successful one.
async fn probe(client: &wreq::Client, urls: &[String], token: &str, timeout: Duration) -> (Hints, Status) {
    let all = async {
        if let [url] = urls {
            return fetch_one(client, url, token, timeout).await;
        }
        let mut pending: FuturesUnordered<_> = urls.iter().map(|url| fetch_one(client, url, token, timeout)).collect();
        let (mut first, mut status) = (None, Status::Transient);
        while let Some((hints, outcome)) = pending.next().await {
            match outcome {
                Status::Success if !hints.is_empty() => return (hints, Status::Success),
                Status::Success => {
                    first.get_or_insert(hints);
                }
                Status::AuthError => status = Status::AuthError,
                Status::Transient => {}
            }
        }
        match first {
            Some(hints) => (hints, Status::Success),
            None => (Hints::new(), status),
        }
    };
    tokio::time::timeout(timeout, all)
        .await
        .unwrap_or((Hints::new(), Status::Transient))
}

/// `fetchAntigravityModelHintsFromURL`.
async fn fetch_one(client: &wreq::Client, base: &str, token: &str, timeout: Duration) -> (Hints, Status) {
    let mut headers = GoHeaders::new();
    headers.set("Content-Type", "application/json");
    headers.set("Authorization", format!("Bearer {token}"));
    headers.set("User-Agent", crate::antigravity_version::user_agent());
    // req.Close.
    headers.set("Connection", "close");
    let url = format!("{}{MODELS_PATH}", base.trim_end_matches('/'));
    let body = Some(Bytes::from_static(b"{}"));
    // A plain http.Client: redirects are followed.
    let Ok(answer) = proxy::request(client, wreq::Method::POST, &url, headers, body, Some(timeout)).await else {
        return (Hints::new(), Status::Transient);
    };
    if matches!(answer.status, 401 | 403) {
        return (Hints::new(), Status::AuthError);
    }
    let Ok(body) = proxy::read_all(answer.body, usize::MAX, false).await else {
        return (Hints::new(), Status::Transient);
    };
    if !(200..300).contains(&answer.status) {
        return (Hints::new(), Status::Transient);
    }
    match parse(&body) {
        Some(hints) => (hints, Status::Success),
        None => (Hints::new(), Status::Transient),
    }
}

/// `parseAntigravityModelCapabilityHints`: `json.Unmarshal` into
/// `{WebSearchModelIDs []string "json:webSearchModelIds"}` (keys match case-insensitively,
/// the last match wins, `null` leaves the field empty), lowercased and trimmed.
fn parse(body: &[u8]) -> Option<Hints> {
    if !gj::std_valid(body) {
        return None;
    }
    let root = gj::parse(body);
    match root.kind {
        Kind::Null => return Some(Hints::new()),
        Kind::Json if root.is_object() => {}
        _ => return None,
    }
    let mut ids: Vec<Vec<u8>> = Vec::new();
    let mut ok = true;
    root.each(|key, value| {
        if !key.str().go_eq_fold("webSearchModelIds") {
            return true;
        }
        match value.kind {
            Kind::Null => ids.clear(),
            Kind::Json if value.is_array() => {
                ids.clear();
                for item in value.array() {
                    match item.kind {
                        Kind::String => ids.push(item.bytes().into_owned()),
                        Kind::Null => ids.push(Vec::new()),
                        _ => ok = false,
                    }
                }
            }
            _ => ok = false,
        }
        true
    });
    ok.then(|| {
        ids.iter()
            .map(|id| String::from_utf8_lossy(trim_space(id)).go_lower())
            .filter(|id| !id.is_empty())
            .collect()
    })
}

/// Which credential revisions the registry has seen, so each new revision is probed once.
#[derive(Default)]
pub(crate) struct Probes {
    seen: Mutex<HashMap<String, (u64, u64)>>,
    next: std::sync::atomic::AtomicU64,
}

impl Probes {
    /// `asyncProbeAntigravityCapabilities` for the credentials of a fresh registration:
    /// each enabled Antigravity credential with a new revision is probed in the
    /// background, and its result replaces the credential's hints unless a newer probe
    /// for it started meanwhile. Hints of credentials that left the set are dropped.
    pub(crate) fn registered(self: &Arc<Self>, clients: &GoClients, credentials: &[Arc<Credential>], cfg: &Config) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let present: HashSet<&str> = credentials
            .iter()
            .filter(|c| c.provider == crate::antigravity::PROVIDER)
            .map(|c| c.id.as_str())
            .collect();
        let mut seen = lock(&self.seen);
        seen.retain(|id, _| {
            let keep = present.contains(id.as_str());
            if !keep {
                cpa_core::registry::dynamic::set_web_search_hints(id, Hints::new());
            }
            keep
        });
        for credential in credentials {
            if credential.provider != crate::antigravity::PROVIDER || credential.disabled {
                continue;
            }
            if seen
                .get(&credential.id)
                .is_some_and(|(revision, _)| *revision == credential.revision)
            {
                continue;
            }
            let proxy_url = Proxy::effective_url(credential, cfg);
            let Ok(client) = clients.get_checked(&Proxy::parse(&proxy_url)) else {
                tracing::warn!("antigravity model probe skipped: invalid proxy transport");
                continue;
            };
            let ticket = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            seen.insert(credential.id.clone(), (credential.revision, ticket));
            let (probes, credential) = (self.clone(), credential.clone());
            runtime.spawn(async move {
                let hints = shared().fetch(&client, &credential, &proxy_url).await;
                // Checked and published under one lock, so a newer registration's
                // probe always lands last (Go's ApplyClientModelCapabilities epoch).
                let seen = lock(&probes.seen);
                if seen.get(&credential.id).map(|(_, t)| *t) == Some(ticket) {
                    cpa_core::registry::dynamic::set_web_search_hints(&credential.id, hints);
                }
            });
        }
    }
}

#[cfg(test)]
#[path = "antigravity_models_tests.rs"]
mod tests;
