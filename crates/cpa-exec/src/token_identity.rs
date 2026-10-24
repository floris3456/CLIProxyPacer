//! Identities of native access tokens for the runtime's rejected-token gate.
//!
//! These follow the token each executor selects, rather than assuming that a metadata
//! `access_token` is used. Ordinary API keys, provider grants and unrelated metadata
//! are outside this gate. An identity contains only a digest and never formats it.

use std::fmt;

use cpa_core::credential::Credential;
use sha2::{Digest, Sha256};

/// An opaque identity used only for equality. Neither the token nor its digest is
/// included in diagnostics, and this type has no serialization implementation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TokenId([u8; 32]);

impl TokenId {
    fn new(token: &str) -> Option<Self> {
        (!token.trim().is_empty()).then(|| Self(Sha256::digest(token.as_bytes()).into()))
    }
}

impl fmt::Debug for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenId([redacted])")
    }
}

/// The native token partitions currently present. `selected` is the token inference
/// uses; Codex also retains the inactive partition so a mode switch cannot forget a
/// rejection. Other native providers have only `outer`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Identities {
    pub outer: Option<TokenId>,
    pub siwc: Option<TokenId>,
    pub selected: Option<TokenId>,
}

/// Identifies the access token used for inference, without exposing its value.
pub fn selected(credential: &Credential) -> Option<TokenId> {
    identities(credential).selected
}

/// An operator-supplied authentication header can replace the native token, even
/// with a request-dependent header reference. Its failures cannot be attributed to
/// a stored managed token. Blank overrides are ignored just as on the wire.
pub fn has_auth_override(credential: &Credential) -> bool {
    credential.attributes.iter().any(|(key, value)| {
        key.strip_prefix("header:").is_some_and(|name| {
            let name = name.trim();
            (name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-api-key"))
                && !value.trim().is_empty()
        })
    })
}

/// Native token partitions and the one selected by the current executors. An auth
/// header override selects no managed token, but retains the underlying partitions
/// so removing the override cannot revive a rejected token. Plugins and ordinary
/// API keys remain outside this gate.
pub fn identities(credential: &Credential) -> Identities {
    let overridden = has_auth_override(credential);
    let attr = |key: &str| credential.attributes.get(key).map(String::as_str).unwrap_or_default();
    let stored = credential.str("access_token").unwrap_or_default();
    if credential.provider == "codex" {
        let view = crate::codex_request::View::new(credential);
        let outer = (!view.api_key)
            .then(|| {
                TokenId::new(if attr("api_key").is_empty() {
                    stored
                } else {
                    attr("api_key")
                })
            })
            .flatten();
        let siwc = TokenId::new(crate::codex_siwc::access_token(credential));
        return Identities {
            outer,
            siwc,
            selected: if overridden {
                None
            } else if view.siwc {
                siwc
            } else {
                outer
            },
        };
    }
    let outer = match credential.provider.as_str() {
        "claude" => crate::claude::ClaudeView::new(credential).ok().and_then(|view| {
            // Claude also accepts an OAuth token in the API-key attribute. An opaque
            // metadata bearer is tracked even when it has no parseable expiry.
            (view.access_token.contains("sk-ant-oat")
                || (attr("api_key").is_empty() && !cpa_core::registry::dynamic::is_api_key(credential)))
            .then(|| TokenId::new(view.access_token))
            .flatten()
        }),
        crate::antigravity::PROVIDER => TokenId::new(stored.trim()),
        p if crate::kimi::PROVIDERS.contains(&p) => {
            // `kimiCreds`: metadata access token, then attribute access token, then
            // an ordinary API key (the last case is deliberately outside this gate).
            if !stored.trim().is_empty() || !attr("access_token").is_empty() {
                TokenId::new(crate::kimi::access_token(credential))
            } else {
                None
            }
        }
        crate::xai::PROVIDER if !cpa_core::registry::dynamic::is_api_key(credential) => {
            TokenId::new(&crate::xai::creds(credential).0)
        }
        crate::meta::PROVIDER
            if !crate::meta::is_config_api_key(credential)
                && (!stored.trim().is_empty() || crate::meta::dca_token(credential).is_some()) =>
        {
            // A DCA token mints a key; it is never the inference token. `metaCreds`
            // selects the non-DCA minted key with the executor's real precedence.
            TokenId::new(&crate::meta::creds(credential).1)
        }
        _ => None,
    };
    Identities {
        outer,
        siwc: None,
        selected: if overridden { None } else { outer },
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;

    use super::*;

    fn credential(metadata: serde_json::Value) -> Credential {
        Credential::from_file(
            Path::new("/auth"),
            Path::new("/auth/a.json"),
            metadata.as_object().unwrap().clone(),
        )
        .unwrap()
    }

    #[test]
    fn native_identity_follows_the_selected_token_and_ignores_shadowed_metadata() {
        let mut claude = credential(json!({"type":"claude", "access_token":"opaque-claude-token"}));
        assert_eq!(
            selected(&claude),
            TokenId::new(crate::claude::ClaudeView::new(&claude).unwrap().access_token)
        );
        claude.attributes.insert("api_key".into(), "ordinary-key".into());
        assert_eq!(selected(&claude), None);
        claude
            .attributes
            .insert("api_key".into(), "sk-ant-oat-selected-token".into());
        assert_eq!(
            selected(&claude),
            TokenId::new(crate::claude::ClaudeView::new(&claude).unwrap().access_token)
        );

        let mut kimi = credential(json!({"type":"kimi", "access_token":"metadata-token"}));
        kimi.attributes.insert("access_token".into(), "attribute-token".into());
        kimi.attributes.insert("api_key".into(), "unused-key".into());
        assert_eq!(selected(&kimi), TokenId::new("metadata-token"));
        kimi.metadata.remove("access_token");
        assert_eq!(selected(&kimi), TokenId::new("attribute-token"));
        kimi.attributes.remove("access_token");
        assert_eq!(selected(&kimi), None);

        let mut xai = credential(json!({"type":"xai", "access_token":" metadata-token "}));
        assert_eq!(selected(&xai), TokenId::new(&crate::xai::creds(&xai).0));
        xai.attributes.insert("api_key".into(), "ordinary-key".into());
        assert_eq!(selected(&xai), None);
        xai.attributes.insert("auth_kind".into(), "oauth".into());
        assert_eq!(selected(&xai), TokenId::new(&crate::xai::creds(&xai).0));

        let meta = credential(json!({
            "type":"meta", "access_token":"shadowed-token", "api_key":"minted-key", "dca_token":"dca:grant"
        }));
        assert_eq!(selected(&meta), TokenId::new(&crate::meta::creds(&meta).1));
        assert_eq!(
            selected(&credential(json!({"type":"meta", "access_token":"dca:grant"}))),
            None
        );
        for provider in ["gemini", "vertex", "devin", "aistudio", "openai", "plugin-provider"] {
            assert_eq!(
                selected(&credential(json!({"type":provider, "access_token":"unused-token"}))),
                None
            );
        }
    }

    #[test]
    fn codex_retains_both_partitions_but_identifies_only_the_selected_wire_token() {
        let mut c = credential(json!({
            "type":"codex", "access_token":"outer-token", "siwc":{"access_token":"siwc-token"}
        }));
        let outer = identities(&c);
        assert_eq!(outer.selected, TokenId::new(crate::codex_request::View::new(&c).token));
        assert_ne!(outer.outer, outer.siwc);
        c.metadata.insert("use_siwc".into(), true.into());
        let siwc = identities(&c);
        assert_eq!(siwc.outer, outer.outer);
        assert_eq!(siwc.siwc, outer.siwc);
        assert_eq!(siwc.selected, TokenId::new(crate::codex_request::View::new(&c).token));
        c.attributes.insert("api_key".into(), "ordinary-key".into());
        assert_eq!(identities(&c).outer, None);
        assert_eq!(selected(&c), siwc.selected);
        c.metadata.insert("use_siwc".into(), false.into());
        assert_eq!(selected(&c), None);
    }

    #[test]
    fn token_identity_diagnostics_never_include_token_or_digest() {
        let identity = TokenId::new("private-test-token").unwrap();
        assert_eq!(format!("{identity:?}"), "TokenId([redacted])");
    }

    #[test]
    fn explicit_auth_headers_cannot_reject_a_shadowed_managed_token() {
        let mut c = credential(json!({"type":"claude", "access_token":"sk-ant-oat-managed-token"}));
        let managed = identities(&c);
        assert!(managed.selected.is_some());
        for name in ["Authorization", "aUtHoRiZaTiOn", " X-Api-Key "] {
            let key = format!("header:{name}");
            for value in ["Bearer operator-token", "$X-Upstream-Token"] {
                c.attributes.insert(key.clone(), value.into());
                assert!(has_auth_override(&c));
                assert_eq!(
                    identities(&c),
                    Identities {
                        selected: None,
                        ..managed
                    }
                );
            }
            c.attributes.remove(&key);
            assert_eq!(
                identities(&c),
                managed,
                "removing the override restores managed tracking"
            );
        }
        c.attributes.insert("header:Authorization".into(), " \t ".into());
        c.attributes
            .insert("header:X-Client-Request-Id".into(), "operator-id".into());
        assert!(!has_auth_override(&c));
        assert_eq!(identities(&c), managed);
    }
}
