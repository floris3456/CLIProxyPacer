//! Runtime-only rejection of exact native access tokens, independent of cooldowns.
//!
//! The store serializes these operations with credential publication. The caller
//! checks registration fences and request-scoped error rules before `reject`; a
//! credential revision alone is not a token identity. No tokens are retained here.

use std::collections::HashMap;

use cpa_core::credential::Credential;
use cpa_exec::token_identity::{self, TokenId};

/// Why a published credential changed. Go permits a successful outer-token refresh
/// to revalidate that same token; metadata edits and SIWC refreshes do not do so.
#[derive(Debug, Clone, Copy)]
pub(crate) enum UpdateKind {
    Registration,
    /// `outer_confirmed` means an actual successful outer refresh was applied. An
    /// identity-only prepare, a discarded refresh, or an SIWC-only patch passes false.
    Refresh {
        outer_confirmed: bool,
    },
}

#[derive(Debug, Clone, Default)]
struct RejectedCredential {
    provider: String,
    outer: Option<TokenId>,
    siwc: Option<TokenId>,
}

/// At most two rejected token identities per credential. Removal or token replacement
/// forgets that partition; a same-token re-registration preserves it.
#[derive(Debug, Clone, Default)]
pub(crate) struct RejectedTokens {
    entries: HashMap<String, RejectedCredential>,
}

impl RejectedTokens {
    /// Whether the credential's selected native token is still rejected. Most
    /// selection candidates have no entry, so that path performs no token hashing.
    pub(crate) fn is_rejected(&self, current: &Credential) -> bool {
        let Some(entry) = self
            .entries
            .get(&current.id)
            .filter(|entry| entry.provider == current.provider)
        else {
            return false;
        };
        let tokens = token_identity::identities(current);
        let Some(selected) = tokens.selected else {
            return false;
        };
        (entry.outer == Some(selected) && tokens.outer == Some(selected))
            || (entry.siwc == Some(selected) && tokens.siwc == Some(selected))
    }

    /// Records an unhandled upstream authentication rejection only while the failed
    /// token is still present in the current credential. The caller must first reject
    /// attempts from a superseded registration, even if their token is unchanged.
    /// Returns whether a new rejection was recorded.
    pub(crate) fn reject(&mut self, current: &Credential, failed_attempt: &Credential) -> bool {
        if current.id != failed_attempt.id || current.provider != failed_attempt.provider {
            return false;
        }
        let Some(failed) = token_identity::selected(failed_attempt) else {
            return false;
        };
        let current_tokens = token_identity::identities(current);
        let outer = current_tokens.outer == Some(failed);
        let siwc = current_tokens.siwc == Some(failed);
        if !outer && !siwc {
            return false;
        }
        let entry = self.entries.entry(current.id.clone()).or_default();
        if entry.provider != current.provider {
            *entry = RejectedCredential {
                provider: current.provider.clone(),
                ..Default::default()
            };
        }
        let changed = (outer && entry.outer != Some(failed)) || (siwc && entry.siwc != Some(failed));
        if outer {
            entry.outer = Some(failed);
        }
        if siwc {
            entry.siwc = Some(failed);
        }
        changed
    }

    /// Called atomically with publication. Token changes clear their own partition;
    /// revisions, refresh-grant changes, and SIWC toggles cannot revive rejected tokens.
    pub(crate) fn reconcile(&mut self, before: &Credential, after: &Credential, kind: UpdateKind) {
        if before.id != after.id || before.provider != after.provider {
            self.remove(&before.id);
            return;
        }
        let Some(entry) = self.entries.get_mut(&after.id) else {
            return;
        };
        let tokens = token_identity::identities(after);
        if entry.outer != tokens.outer || matches!(kind, UpdateKind::Refresh { outer_confirmed: true }) {
            entry.outer = None;
        }
        // Go's separate RejectedSIWCAccessToken survives even a successful refresh
        // returning the same SIWC token, including an outer-only refresh and rebind.
        if entry.siwc != tokens.siwc {
            entry.siwc = None;
        }
        if entry.outer.is_none() && entry.siwc.is_none() {
            self.remove(&after.id);
        }
    }

    pub(crate) fn remove(&mut self, id: &str) {
        self.entries.remove(id);
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

    fn outer(token: &str) -> Credential {
        credential(json!({"type":"codex", "access_token":token, "refresh_token":"refresh-grant"}))
    }

    fn siwc() -> Credential {
        credential(json!({
            "type":"codex", "access_token":"outer-A", "refresh_token":"outer-refresh", "use_siwc":true,
            "siwc":{"access_token":"siwc-A", "refresh_token":"siwc-refresh", "client_id":"client"}
        }))
    }

    #[test]
    fn opaque_rejection_survives_metadata_edits_grant_changes_and_reregistration() {
        let mut state = RejectedTokens::default();
        let old = outer("opaque-token");
        assert!(state.reject(&old, &old));
        assert!(!state.reject(&old, &old));
        let mut current = old.clone();
        current.revision = 99;
        current.metadata.insert("expired".into(), "2099-01-01T00:00:00Z".into());
        current
            .metadata
            .insert("refresh_token".into(), "replacement-grant".into());
        state.reconcile(&old, &current, UpdateKind::Registration);
        assert!(state.is_rejected(&current));
        state.reconcile(&old, &current, UpdateKind::Refresh { outer_confirmed: false });
        assert!(
            state.is_rejected(&current),
            "identity-only preparation cannot revalidate a token"
        );
        state.remove(&current.id);
        assert!(!state.is_rejected(&current));
    }

    #[test]
    fn late_attempts_reject_only_the_token_still_present_not_its_replacement() {
        let mut state = RejectedTokens::default();
        let old = outer("token-A");
        let mut edited = old.clone();
        edited.revision = 2;
        assert!(
            state.reject(&edited, &old),
            "a metadata revision is not a token rotation"
        );
        let mut rotated = outer("token-B");
        rotated.revision = 3;
        state.reconcile(&edited, &rotated, UpdateKind::Registration);
        assert!(!state.is_rejected(&rotated));
        assert!(!state.reject(&rotated, &old));
        assert!(!state.is_rejected(&rotated));
        assert!(state.entries.is_empty());
        let mut other = rotated.clone();
        other.id = "other.json".into();
        assert!(!state.reject(&rotated, &other));
    }

    #[test]
    fn same_outer_token_is_revalidated_only_by_a_confirmed_outer_refresh() {
        let mut state = RejectedTokens::default();
        let c = outer("opaque-token");
        state.reject(&c, &c);
        state.reconcile(&c, &c, UpdateKind::Registration);
        assert!(state.is_rejected(&c));
        state.reconcile(&c, &c, UpdateKind::Refresh { outer_confirmed: true });
        assert!(!state.is_rejected(&c));
        assert!(state.reject(&c, &c), "a later 401 rejects the revalidated token again");
    }

    #[test]
    fn authentication_header_overrides_do_not_forget_rejected_native_partitions() {
        for before in [outer("outer-A"), siwc()] {
            let mut state = RejectedTokens::default();
            assert!(state.reject(&before, &before));
            let mut overridden = before.clone();
            overridden
                .attributes
                .insert("header:Authorization".into(), "Bearer operator-token".into());
            state.reconcile(&before, &overridden, UpdateKind::Registration);
            assert!(!state.is_rejected(&overridden));
            assert!(
                !state.reject(&overridden, &overridden),
                "an override's failure cannot condemn a managed token"
            );
            state.reconcile(&overridden, &before, UpdateKind::Registration);
            assert!(
                state.is_rejected(&before),
                "removing the override must not revive the same rejected native token"
            );
        }
    }

    #[test]
    fn siwc_rejection_survives_outer_refresh_mode_switches_and_same_token_rebind() {
        let mut state = RejectedTokens::default();
        let before = siwc();
        state.reject(&before, &before);
        let mut refreshed = before.clone();
        refreshed.metadata.insert("access_token".into(), "outer-B".into());
        state.reconcile(&before, &refreshed, UpdateKind::Refresh { outer_confirmed: true });
        assert!(state.is_rejected(&refreshed));

        let mut off = refreshed.clone();
        off.metadata.insert("use_siwc".into(), false.into());
        state.reconcile(&refreshed, &off, UpdateKind::Registration);
        assert!(!state.is_rejected(&off), "the untouched outer token remains usable");
        state.reconcile(&off, &refreshed, UpdateKind::Registration);
        assert!(state.is_rejected(&refreshed));
        state.reconcile(&refreshed, &refreshed, UpdateKind::Refresh { outer_confirmed: false });
        assert!(
            state.is_rejected(&refreshed),
            "an unchanged SIWC refresh or rebind remains rejected"
        );

        let mut rebound = refreshed.clone();
        rebound.metadata.get_mut("siwc").unwrap()["access_token"] = "siwc-B".into();
        state.reconcile(&refreshed, &rebound, UpdateKind::Registration);
        assert!(!state.is_rejected(&rebound));
        assert!(
            !state.reject(&rebound, &before),
            "late SIWC-A failure cannot reject SIWC-B"
        );
    }

    #[test]
    fn stale_partition_results_do_not_depend_on_which_partition_is_currently_selected() {
        let mut state = RejectedTokens::default();
        let siwc_attempt = siwc();
        let mut current = siwc_attempt.clone();
        current.revision = 2;
        current.metadata.insert("access_token".into(), "outer-B".into());
        current.metadata.insert("use_siwc".into(), false.into());
        assert!(state.reject(&current, &siwc_attempt));
        assert!(!state.is_rejected(&current));
        let outer_attempt = current.clone();
        current.metadata.insert("use_siwc".into(), true.into());
        assert!(state.reject(&current, &outer_attempt));
        assert!(state.is_rejected(&current));
        let mut outer_selected = current.clone();
        outer_selected.metadata.insert("use_siwc".into(), false.into());
        state.reconcile(&current, &outer_selected, UpdateKind::Registration);
        assert!(
            state.is_rejected(&outer_selected),
            "both rejected partitions are retained independently"
        );
        state.reconcile(
            &outer_selected,
            &outer_selected,
            UpdateKind::Refresh { outer_confirmed: true },
        );
        assert!(!state.is_rejected(&outer_selected));
        assert!(
            state.is_rejected(&current),
            "outer recovery cannot clear the SIWC rejection"
        );
    }

    #[test]
    fn ordinary_api_keys_and_unused_tokens_are_not_condemned() {
        let mut state = RejectedTokens::default();
        let mut c = outer("unused-metadata-token");
        c.attributes.insert("api_key".into(), "ordinary-api-key".into());
        assert!(!state.reject(&c, &c));
        assert!(!state.is_rejected(&c));
        assert!(state.entries.is_empty());
    }
}
