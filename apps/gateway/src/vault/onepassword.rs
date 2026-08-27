//! 1Password vault provider.
//!
//! The Service Account token is injected from a runtime-only file and held only
//! in process memory. It is never accepted from the dashboard and is never
//! written to PostgreSQL, so database snapshots cannot become a second secret
//! store. The token file is the broker's unavoidable bootstrap identity; its
//! path comes from `ONEPASSWORD_SERVICE_ACCOUNT_TOKEN_FILE`.
//! 1Password is **not** a hostname-matched vault racer like Bitwarden; it is a
//! *value source* for explicit secrets. A secret with `value_source =
//! "onepassword"` carries an `op://vault/item/field` reference that the
//! [`PolicyEngine`](crate::connect::PolicyEngine) resolves here at request time
//! (instead of decrypting a stored `encrypted_value`).
//!
//! The actual 1Password SDK work (validate token, resolve `op://`, browse
//! vaults/items/fields for the picker) is delegated to the Node "1Password SDK
//! service" via [`super::onepassword_api`]; the gateway never runs the `op` CLI.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use tracing::info;

use super::onepassword_api::{self, OpError};
use super::{PairResult, ProviderStatus, VaultCredential, VaultError, VaultProvider};

// The Node SDK client is hard-rotated every 20s. Keeping this cache at 30s
// bounds the combined stale-value window below one minute without requiring a
// gateway or API restart after a 1Password rotation.
const RESOLVE_CACHE_TTL: Duration = Duration::from_secs(30);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const ERROR_COOLDOWN: Duration = Duration::from_secs(60);
/// How long a successful `status` connectivity check is trusted before re-checking.
const STATUS_OK_TTL: Duration = Duration::from_secs(30);
const EVICTION_INTERVAL: Duration = Duration::from_secs(300);
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(1800);

// ── Config & session types ──────────────────────────────────────────────

const TOKEN_FILE_ENV: &str = "ONEPASSWORD_SERVICE_ACCOUNT_TOKEN_FILE";

fn load_service_account_token(path: &Path) -> Result<Arc<str>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading metadata for {TOKEN_FILE_ENV}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(anyhow!("{TOKEN_FILE_ENV} must name a regular, non-symlink file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o007 != 0 || mode & 0o022 != 0 {
            return Err(anyhow!(
                "{TOKEN_FILE_ENV} permissions are too broad ({mode:o}); require no other access and no group/other write"
            ));
        }
    }
    let token = fs::read_to_string(path).with_context(|| format!("reading {TOKEN_FILE_ENV}"))?;
    let token = token.trim();
    if token.is_empty() {
        return Err(anyhow!("{TOKEN_FILE_ENV} is empty"));
    }
    Ok(Arc::<str>::from(token))
}

/// A cached `op://` resolution. `value: None` is a negative cache entry (the
/// reference resolved to nothing / failed) held for a shorter TTL.
struct CachedRef {
    value: Option<String>,
    expires_at: Instant,
}

struct OnePasswordSession {
    service_account_token: Arc<str>,
    /// `op://vault/item/field` → resolved value, with positive/negative TTLs.
    ref_cache: DashMap<String, CachedRef>,
    last_used: Mutex<Instant>,
    last_error: Mutex<Option<String>>,
    error_until: Mutex<Option<Instant>>,
    /// Timestamp of the last successful connectivity check (positive `status` cache).
    last_ok: Mutex<Option<Instant>>,
}

impl OnePasswordSession {
    /// Whether the session is still within its post-error cooldown window (set
    /// when a `Transient` 1Password failure was last seen).
    fn in_error_cooldown(&self) -> bool {
        self.error_until
            .lock()
            .expect("session lock poisoned")
            .is_some_and(|t| Instant::now() < t)
    }
}

pub(crate) struct OnePasswordVaultProvider {
    service_account_token: Option<Arc<str>>,
    sessions: Arc<DashMap<String, Arc<OnePasswordSession>>>,
}

// ── Constructor with idle-session eviction ──────────────────────────────

impl OnePasswordVaultProvider {
    pub fn from_env() -> Result<Self> {
        let service_account_token = match std::env::var_os(TOKEN_FILE_ENV) {
            None => None,
            Some(path) => Some(load_service_account_token(Path::new(&path))?),
        };
        Ok(Self::new(service_account_token))
    }

    #[cfg(test)]
    pub(crate) fn without_service_account() -> Self {
        Self::new(None)
    }

    fn new(service_account_token: Option<Arc<str>>) -> Self {
        let sessions: Arc<DashMap<String, Arc<OnePasswordSession>>> = Arc::new(DashMap::new());

        let sessions_clone = Arc::clone(&sessions);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(EVICTION_INTERVAL).await;
                let mut to_evict = Vec::new();
                for entry in sessions_clone.iter() {
                    let last = *entry
                        .value()
                        .last_used
                        .lock()
                        .expect("session lock poisoned");
                    if last.elapsed() > SESSION_IDLE_TIMEOUT {
                        to_evict.push(entry.key().clone());
                    }
                }
                for key in to_evict {
                    if let Some((_, session)) = sessions_clone.remove(&key) {
                        session.ref_cache.clear();
                        info!(workspace_id = %key, "evicted idle 1Password session");
                    }
                }
            }
        });

        Self {
            service_account_token,
            sessions,
        }
    }

    /// Load a session from memory or from the externally injected token. The
    /// workspace key isolates value caches; the bootstrap identity is shared.
    async fn load_session(
        &self,
        workspace_id: &str,
    ) -> Result<Option<Arc<OnePasswordSession>>, VaultError> {
        if let Some(session) = self.sessions.get(workspace_id) {
            *session.last_used.lock().expect("session lock poisoned") = Instant::now();
            return Ok(Some(Arc::clone(&session)));
        }

        let Some(sa_token) = self.service_account_token.as_ref() else {
            return Ok(None);
        };

        let session = Arc::new(OnePasswordSession {
            service_account_token: Arc::clone(sa_token),
            ref_cache: DashMap::new(),
            last_used: Mutex::new(Instant::now()),
            last_error: Mutex::new(None),
            error_until: Mutex::new(None),
            last_ok: Mutex::new(None),
        });
        self.sessions
            .insert(workspace_id.to_string(), Arc::clone(&session));
        Ok(Some(session))
    }

    // ── Value-source resolution (the secret-injection path) ──────────────

    /// Resolve an `op://vault/item/field` reference to its secret value for a
    /// workspace's 1Password connection. Cached by `op_ref` with the same TTL /
    /// cooldown as before. Errors classify so the caller can skip the secret the
    /// same way it skips one whose stored value fails to decrypt.
    ///
    /// There is one 1Password connection per workspace, so the reference resolves
    /// via that workspace's connection (the `workspace_id` session).
    pub(crate) async fn resolve_ref(
        &self,
        workspace_id: &str,
        op_ref: &str,
    ) -> Result<String, VaultError> {
        let session = self
            .load_session(workspace_id)
            .await?
            .ok_or_else(|| VaultError::NotFound("1Password is not connected".into()))?;

        if let Some(cached) = session.ref_cache.get(op_ref) {
            if cached.expires_at > Instant::now() {
                return cached
                    .value
                    .clone()
                    .ok_or_else(|| VaultError::BadRequest(format!("cannot resolve {op_ref}")));
            }
            drop(cached);
            session.ref_cache.remove(op_ref);
        }

        if session.in_error_cooldown() {
            return Err(VaultError::Internal(
                "1Password temporarily unavailable (cooldown)".into(),
            ));
        }

        match onepassword_api::resolve(&session.service_account_token, op_ref).await {
            Ok(value) if !value.is_empty() => {
                *session.last_error.lock().expect("session lock poisoned") = None;
                session.ref_cache.insert(
                    op_ref.to_string(),
                    CachedRef {
                        value: Some(value.clone()),
                        expires_at: Instant::now() + RESOLVE_CACHE_TTL,
                    },
                );
                Ok(value)
            }
            Ok(_) => {
                self.cache_negative(&session, op_ref);
                Err(VaultError::BadRequest(format!(
                    "{op_ref} resolved to an empty value"
                )))
            }
            Err(OpError::NotFound(msg)) | Err(OpError::BadRequest(msg)) => {
                self.cache_negative(&session, op_ref);
                Err(VaultError::BadRequest(msg))
            }
            Err(OpError::Transient(msg)) => {
                *session.last_error.lock().expect("session lock poisoned") = Some(msg.clone());
                *session.error_until.lock().expect("session lock poisoned") =
                    Some(Instant::now() + ERROR_COOLDOWN);
                Err(VaultError::Internal(msg))
            }
        }
    }

    fn cache_negative(&self, session: &OnePasswordSession, op_ref: &str) {
        session.ref_cache.insert(
            op_ref.to_string(),
            CachedRef {
                value: None,
                expires_at: Instant::now() + NEGATIVE_CACHE_TTL,
            },
        );
    }

    // ── Picker passthroughs (browse vaults → items → fields) ─────────────
    // The browser never sees the SA token or field values — it gets only the
    // labels/types the Node service returns.

    pub(crate) async fn list_vaults(
        &self,
        workspace_id: &str,
    ) -> Result<serde_json::Value, VaultError> {
        let session = self.picker_session(workspace_id).await?;
        onepassword_api::list_vaults(&session.service_account_token)
            .await
            .map_err(op_err_to_vault)
    }

    pub(crate) async fn list_items(
        &self,
        workspace_id: &str,
        vault_id: &str,
    ) -> Result<serde_json::Value, VaultError> {
        let session = self.picker_session(workspace_id).await?;
        onepassword_api::list_items(&session.service_account_token, vault_id)
            .await
            .map_err(op_err_to_vault)
    }

    pub(crate) async fn list_fields(
        &self,
        workspace_id: &str,
        vault_id: &str,
        item_id: &str,
    ) -> Result<serde_json::Value, VaultError> {
        let session = self.picker_session(workspace_id).await?;
        onepassword_api::list_fields(&session.service_account_token, vault_id, item_id)
            .await
            .map_err(op_err_to_vault)
    }

    /// Load a connected session for picker calls, or 404 if not paired. Returns
    /// the session so callers borrow the SA token instead of cloning it.
    async fn picker_session(
        &self,
        workspace_id: &str,
    ) -> Result<Arc<OnePasswordSession>, VaultError> {
        self.load_session(workspace_id)
            .await?
            .ok_or_else(|| VaultError::NotFound("1Password is not connected".into()))
    }
}

// ── VaultProvider implementation ─────────────────────────────────────────

#[async_trait]
impl VaultProvider for OnePasswordVaultProvider {
    fn provider_name(&self) -> &'static str {
        "onepassword"
    }

    async fn pair(&self, workspace_id: &str, _params: &serde_json::Value) -> Result<PairResult> {
        let token = self.service_account_token.as_ref().ok_or_else(|| {
            anyhow!(
                "1Password is operator-managed; configure {TOKEN_FILE_ENV} and restart the gateway"
            )
        })?;

        // Pairing is only a live validation of the externally managed token.
        // There is deliberately no database write on this path.
        onepassword_api::validate(token)
            .await
            .map_err(|e| anyhow!("token validation failed: {e}"))?;
        self.sessions.remove(workspace_id);
        Ok(PairResult {
            display_name: Some("1Password (operator managed)".into()),
        })
    }

    /// 1Password is a value-source for explicit secrets (resolved via the
    /// PolicyEngine secret-injection path), not a hostname-matched vault racer,
    /// so it never participates in the Bitwarden-style credential race.
    async fn request_credential(
        &self,
        _workspace_id: &str,
        _hostname: &str,
    ) -> Option<VaultCredential> {
        None
    }

    async fn status(&self, workspace_id: &str) -> ProviderStatus {
        let session = match self.load_session(workspace_id).await {
            Ok(Some(s)) => s,
            Ok(None) => {
                return ProviderStatus {
                    connected: false,
                    name: None,
                    status_data: Some(serde_json::json!({
                        "managed_externally": true,
                        "last_error": format!(
                            "1Password bootstrap is not configured; set {TOKEN_FILE_ENV} and restart the gateway"
                        ),
                    })),
                }
            }
            Err(e) => {
                return ProviderStatus {
                    connected: false,
                    name: None,
                    status_data: Some(serde_json::json!({
                        "managed_externally": true,
                        "last_error": e.to_string(),
                    })),
                }
            }
        };

        let connected = live_check(&session).await;
        let last_err = session
            .last_error
            .lock()
            .expect("session lock poisoned")
            .clone();

        ProviderStatus {
            connected,
            name: None,
            status_data: Some(serde_json::json!({
                "managed_externally": true,
                "last_error": last_err,
            })),
        }
    }

    async fn disconnect(&self, workspace_id: &str) -> Result<()> {
        if let Some((_, session)) = self.sessions.remove(workspace_id) {
            session.ref_cache.clear();
        }
        Err(anyhow!(
            "1Password is operator-managed; remove the runtime token file and restart the gateway"
        ))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Live connectivity check for `status`, gated by the error cooldown and a
/// short positive TTL so dashboard polling doesn't hammer 1Password.
async fn live_check(session: &OnePasswordSession) -> bool {
    if session.in_error_cooldown() {
        return false;
    }
    if session
        .last_ok
        .lock()
        .expect("session lock poisoned")
        .is_some_and(|t| t.elapsed() < STATUS_OK_TTL)
    {
        return true;
    }
    match onepassword_api::validate(&session.service_account_token).await {
        Ok(()) => {
            *session.last_error.lock().expect("session lock poisoned") = None;
            *session.last_ok.lock().expect("session lock poisoned") = Some(Instant::now());
            true
        }
        Err(e) => {
            *session.last_error.lock().expect("session lock poisoned") = Some(e.to_string());
            *session.error_until.lock().expect("session lock poisoned") =
                Some(Instant::now() + ERROR_COOLDOWN);
            false
        }
    }
}

fn op_err_to_vault(e: OpError) -> VaultError {
    match e {
        OpError::NotFound(m) => VaultError::NotFound(m),
        OpError::BadRequest(m) => VaultError::BadRequest(m),
        OpError::Transient(m) => VaultError::Internal(m),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_provider_holds_no_service_account_token() {
        let provider = OnePasswordVaultProvider::without_service_account();
        assert!(provider.service_account_token.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_file_requires_private_permissions_and_nonempty_value() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "onecli-onepassword-bootstrap-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        fs::write(&path, "synthetic-test-value\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(&*load_service_account_token(&path).unwrap(), "synthetic-test-value");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_service_account_token(&path).is_err());

        fs::write(&path, "\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_service_account_token(&path).is_err());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn op_error_maps_to_the_right_vault_error_class() {
        // This mapping is the contract that drives the HTTP status the picker
        // returns (404 / 400 / 500), so pin each classification.
        assert!(matches!(
            op_err_to_vault(OpError::NotFound("x".into())),
            VaultError::NotFound(_)
        ));
        assert!(matches!(
            op_err_to_vault(OpError::BadRequest("x".into())),
            VaultError::BadRequest(_)
        ));
        assert!(matches!(
            op_err_to_vault(OpError::Transient("x".into())),
            VaultError::Internal(_)
        ));
    }

    #[test]
    fn resolved_value_cache_leaves_room_for_sdk_client_refresh() {
        // The API layer's SDK-client maximum age is 20s. This pins the
        // cross-layer production contract at no more than 50s total.
        assert!(RESOLVE_CACHE_TTL + Duration::from_secs(20) <= Duration::from_secs(60));
    }
}
