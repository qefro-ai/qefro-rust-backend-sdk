//! Qefro backend SDK — mirrors `@qefro-ai/backend` (TypeScript).
//!
//! Organizations expose one signed webhook (typically `POST /qefro`).
//! Qefro Runtime calls `ping`, `tools.list`, `tool.invoke`, and `tool.resume`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Package name reported to Qefro Runtime (`X-Qefro-SDK` / protocol payloads).
pub const SDK_NAME: &str = "qefro-backend-sdk";
/// Package version reported to Qefro Runtime (`sdk_version` / `X-Qefro-Version`).
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

type ToolHandler = Arc<dyn Fn(ToolContext) -> ToolFuture + Send + Sync>;
type ToolFuture = Pin<Box<dyn Future<Output = Result<Value>> + Send>>;
type BeforeHook = Arc<dyn Fn(ToolContext) -> HookFuture + Send + Sync>;
type AfterHook = Arc<dyn Fn(ToolContext, Value) -> AfterFuture + Send + Sync>;
type HookFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
type AfterFuture = Pin<Box<dyn Future<Output = Result<Value>> + Send>>;
type MiddlewareFn = Arc<
    dyn Fn(ToolContext, NextFn) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>>
        + Send
        + Sync,
>;
type NextFn = Box<dyn FnOnce(ToolContext) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>> + Send>;

#[derive(Debug, Clone)]
pub struct QefroConfig {
    pub signing_secret: String,
    pub protocol_version: String,
    pub max_timestamp_skew_secs: i64,
    pub endpoint_path: String,
}

impl QefroConfig {
    pub fn new(signing_secret: impl Into<String>) -> Self {
        Self {
            signing_secret: signing_secret.into(),
            protocol_version: "1".into(),
            max_timestamp_skew_secs: 300,
            endpoint_path: "/qefro".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ToolAuthMode {
    None,
    #[default]
    Optional,
    Required,
}

/// Identity attributes the Qefro runtime must resolve before `tool.invoke`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct ToolLookup {
    /// Shorthand for a single required attribute, e.g. `"email"` or `"phone"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// Explicit list, e.g. `["email"]` or `["phone", "customer_id"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
}

/// Normalize `lookup.by` / `lookup.required` into a deduped lowercase attribute list.
pub fn normalize_lookup(lookup: Option<&ToolLookup>) -> Vec<String> {
    let Some(lookup) = lookup else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for item in lookup
        .required
        .iter()
        .cloned()
        .chain(lookup.by.iter().cloned())
    {
        let key = item.trim().to_ascii_lowercase();
        if key.is_empty() || !seen.insert(key.clone()) {
            continue;
        }
        out.push(key);
    }
    out
}

fn normalized_lookup_field(lookup: Option<&ToolLookup>) -> Option<ToolLookup> {
    let attrs = normalize_lookup(lookup);
    if attrs.is_empty() {
        None
    } else {
        Some(ToolLookup {
            by: None,
            required: attrs,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication_methods: Vec<String>,
    #[serde(default)]
    pub auth: ToolAuthMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_auth_method: Option<String>,
    /// What identity the runtime must have before invoking this tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup: Option<ToolLookup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication_methods: Vec<String>,
    #[serde(default)]
    pub auth: ToolAuthMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup: Option<ToolLookup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationContextPayload {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub credential_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePayload {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QefroRequest {
    pub protocol_version: String,
    pub request_id: Uuid,
    #[serde(rename = "type")]
    pub request_type: String,
    pub organization_id: Option<Uuid>,
    pub conversation_id: Option<Uuid>,
    pub channel: Option<String>,
    pub identity: Option<Value>,
    pub tool: Option<String>,
    pub parameters: Option<Value>,
    pub authentication: Option<Value>,
    pub resume_token: Option<String>,
    pub challenge_response: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum QefroResponse {
    Pong {
        protocol_version: String,
        sdk_version: String,
    },
    #[serde(rename = "tools.list")]
    ToolsList {
        tools: Vec<RegisteredTool>,
        protocol_version: String,
        sdk_version: String,
    },
    Result {
        output: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        authentication_context: Option<AuthenticationContextPayload>,
    },
    Challenge {
        resume_token: String,
        challenge: ChallengePayload,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone)]
struct PendingInvocation {
    tool: String,
    conversation_id: Uuid,
    parameters: Value,
    identity: Option<Value>,
    channel: Option<String>,
}

#[derive(Debug, Clone)]
struct StoredAuth {
    customer: Value,
    auth: AuthenticationContextPayload,
    expires_at_epoch_ms: i64,
}

#[derive(Debug, Clone)]
pub struct Conversation {
    pub id: Uuid,
}

#[derive(Clone)]
pub struct ToolContext {
    pub identity: Value,
    pub parameters: Value,
    pub conversation: Conversation,
    pub channel: Option<String>,
    pub authentication: Option<Value>,
    pub auth_response: Option<String>,
    /// Customer resolved for `auth = required` (or via in-handler authorize).
    pub customer: Option<Value>,
    customer_api: Option<CustomerApi>,
}

impl ToolContext {
    /// In-handler customer helpers (mirrors JS `ctx.customer`).
    pub fn customer_api(&self) -> Option<&CustomerApi> {
        self.customer_api.as_ref()
    }

    /// Raise an auth challenge from inside a tool handler (mirrors JS `AuthBuilder.challenge`).
    pub fn raise_challenge(challenge: ChallengePayload) -> Result<Value> {
        Err(ChallengeSignal { challenge }.into())
    }
}

/// Signal an auth challenge from a tool handler (caught like JS `ChallengeSignal`).
#[derive(Debug, Clone)]
pub struct ChallengeSignal {
    pub challenge: ChallengePayload,
}

impl std::fmt::Display for ChallengeSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.challenge.message)
    }
}

impl std::error::Error for ChallengeSignal {}

#[derive(Debug, Clone)]
pub enum AuthOutcome {
    Success {
        customer: Value,
        auth: AuthenticationContextPayload,
    },
    Challenge(ChallengePayload),
    Denied,
    NotFound,
}

/// Helpers matching JS `AuthBuilder`.
#[derive(Debug, Clone)]
pub struct AuthBuilder {
    pub response: Option<String>,
}

impl AuthBuilder {
    pub fn new(response: Option<String>) -> Self {
        Self { response }
    }

    pub fn success(
        &self,
        customer: Value,
        mut auth: AuthenticationContextPayload,
    ) -> AuthOutcome {
        if auth.customer_id.is_none() {
            auth.customer_id = customer
                .get("id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
        AuthOutcome::Success { customer, auth }
    }

    pub fn denied(&self) -> AuthOutcome {
        AuthOutcome::Denied
    }

    pub fn not_found(&self) -> AuthOutcome {
        AuthOutcome::NotFound
    }

    pub fn email_otp(&self, email: &str, message: Option<&str>) -> AuthOutcome {
        AuthOutcome::Challenge(ChallengePayload {
            challenge_type: "email_otp".into(),
            message: message
                .unwrap_or("Enter the OTP sent to your email.")
                .into(),
            destination_hint: Some(mask(email)),
            login_url: None,
        })
    }

    pub fn sms_otp(&self, phone: &str, message: Option<&str>) -> AuthOutcome {
        AuthOutcome::Challenge(ChallengePayload {
            challenge_type: "sms_otp".into(),
            message: message
                .unwrap_or("Enter the OTP sent to your phone.")
                .into(),
            destination_hint: Some(mask(phone)),
            login_url: None,
        })
    }

    pub fn login(&self, url: &str, message: Option<&str>) -> AuthOutcome {
        AuthOutcome::Challenge(ChallengePayload {
            challenge_type: "login".into(),
            message: message
                .unwrap_or("Please continue in your login page.")
                .into(),
            destination_hint: None,
            login_url: Some(url.into()),
        })
    }

    pub fn custom(&self, challenge: ChallengePayload) -> AuthOutcome {
        AuthOutcome::Challenge(challenge)
    }
}

fn mask(value: &str) -> String {
    if value.len() <= 4 {
        return value.to_string();
    }
    format!("{}***{}", &value[..2], &value[value.len() - 2..])
}

#[derive(Debug, Clone)]
pub struct CustomerLookupContext {
    pub identity: Value,
    pub parameters: Value,
    pub conversation: Conversation,
    pub channel: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CustomerAuthorizeContext {
    pub customer: Value,
    pub method: Option<String>,
    pub response: Option<String>,
    pub identity: Value,
    pub parameters: Value,
    pub conversation: Conversation,
    pub channel: Option<String>,
}

#[async_trait]
pub trait CustomerProvider: Send + Sync {
    async fn lookup(&self, ctx: &CustomerLookupContext) -> Result<Option<Value>>;
    async fn authorize(&self, ctx: &CustomerAuthorizeContext) -> Result<AuthOutcome>;
}

#[derive(Clone)]
struct ToolRegistration {
    metadata: ToolMetadata,
    handler: ToolHandler,
}

#[derive(Debug, Clone)]
pub struct ListenOptions {
    pub port: u16,
    pub host: Option<String>,
    pub path: Option<String>,
}

pub struct ListenHandle {
    pub url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl ListenHandle {
    pub async fn close(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

struct Inner {
    config: QefroConfig,
    tools: RwLock<HashMap<String, ToolRegistration>>,
    pending: Mutex<HashMap<String, PendingInvocation>>,
    auth_by_conversation: Mutex<HashMap<Uuid, StoredAuth>>,
    customer_provider: RwLock<Option<Arc<dyn CustomerProvider>>>,
    middlewares: RwLock<Vec<MiddlewareFn>>,
    before_hooks: RwLock<Vec<BeforeHook>>,
    after_hooks: RwLock<Vec<AfterHook>>,
}

/// In-handler customer API (mirrors JS `ctx.customer`).
#[derive(Clone)]
pub struct CustomerApi {
    app: Qefro,
    identity: Value,
    parameters: Value,
    conversation_id: Uuid,
    channel: Option<String>,
    auth_response: Option<String>,
    state: Arc<Mutex<CustomerState>>,
}

#[derive(Debug, Default)]
struct CustomerState {
    current: Option<Value>,
    lookup_completed: bool,
}

impl CustomerApi {
    pub async fn lookup(&self) -> Result<Option<Value>> {
        let provider = self
            .app
            .inner
            .customer_provider
            .read()
            .expect("customer_provider")
            .clone()
            .ok_or_else(|| anyhow!("customer_provider_missing"))?;

        {
            let state = self.state.lock().await;
            if state.lookup_completed {
                return Ok(state.current.clone());
            }
        }

        let customer = provider
            .lookup(&CustomerLookupContext {
                identity: self.identity.clone(),
                parameters: self.parameters.clone(),
                conversation: Conversation {
                    id: self.conversation_id,
                },
                channel: self.channel.clone(),
            })
            .await?;

        let mut state = self.state.lock().await;
        state.current = customer.clone();
        state.lookup_completed = true;
        Ok(customer)
    }

    pub async fn lookup_by_phone(&self, phone: Option<&str>) -> Result<Option<Value>> {
        let provider = self
            .app
            .inner
            .customer_provider
            .read()
            .expect("customer_provider")
            .clone()
            .ok_or_else(|| anyhow!("customer_provider_missing"))?;

        let source = phone
            .map(str::to_string)
            .or_else(|| {
                self.identity
                    .get("phone")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_string)
            });

        let Some(source) = source else {
            let mut state = self.state.lock().await;
            state.lookup_completed = true;
            state.current = None;
            return Ok(None);
        };

        let mut identity = self.identity.clone();
        if let Some(obj) = identity.as_object_mut() {
            obj.insert("phone".into(), json!(source));
        }

        let customer = provider
            .lookup(&CustomerLookupContext {
                identity,
                parameters: self.parameters.clone(),
                conversation: Conversation {
                    id: self.conversation_id,
                },
                channel: self.channel.clone(),
            })
            .await?;

        let mut state = self.state.lock().await;
        state.current = customer.clone();
        state.lookup_completed = true;
        Ok(customer)
    }

    pub async fn authorize(&self, method: Option<String>) -> Result<Value> {
        let provider = self
            .app
            .inner
            .customer_provider
            .read()
            .expect("customer_provider")
            .clone()
            .ok_or_else(|| anyhow!("customer_provider_missing"))?;

        {
            let auth = self.app.inner.auth_by_conversation.lock().await;
            if let Some(existing) = auth.get(&self.conversation_id) {
                if existing.expires_at_epoch_ms > Utc::now().timestamp_millis() {
                    let mut state = self.state.lock().await;
                    state.current = Some(existing.customer.clone());
                    state.lookup_completed = true;
                    return Ok(existing.customer.clone());
                }
            }
        }

        let customer = self
            .lookup()
            .await?
            .ok_or_else(|| anyhow!("customer_not_found"))?;

        let outcome = provider
            .authorize(&CustomerAuthorizeContext {
                customer: customer.clone(),
                method,
                response: self.auth_response.clone(),
                identity: self.identity.clone(),
                parameters: self.parameters.clone(),
                conversation: Conversation {
                    id: self.conversation_id,
                },
                channel: self.channel.clone(),
            })
            .await?;

        self.app
            .consume_auth_outcome(
                outcome,
                self.conversation_id,
                Some(self.state.clone()),
                None,
                None,
                None,
                None,
            )
            .await
    }

    pub async fn get(&self) -> Option<Value> {
        self.state.lock().await.current.clone()
    }

    pub async fn require(&self) -> Result<Value> {
        self.get()
            .await
            .ok_or_else(|| anyhow!("customer_not_found"))
    }
}

#[derive(Clone)]
pub struct Qefro {
    inner: Arc<Inner>,
}

impl Qefro {
    pub fn new(config: QefroConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                tools: RwLock::new(HashMap::new()),
                pending: Mutex::new(HashMap::new()),
                auth_by_conversation: Mutex::new(HashMap::new()),
                customer_provider: RwLock::new(None),
                middlewares: RwLock::new(Vec::new()),
                before_hooks: RwLock::new(Vec::new()),
                after_hooks: RwLock::new(Vec::new()),
            }),
        }
    }

    pub fn customer<P>(&self, provider: P) -> &Self
    where
        P: CustomerProvider + 'static,
    {
        *self.inner.customer_provider.write().expect("customer_provider") =
            Some(Arc::new(provider));
        self
    }

    pub fn tool<F, Fut>(&self, metadata: ToolMetadata, handler: F) -> &Self
    where
        F: Fn(ToolContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        let name = metadata.name.clone();
        let lookup = normalized_lookup_field(metadata.lookup.as_ref());
        let metadata = ToolMetadata {
            lookup,
            ..metadata
        };
        let registration = ToolRegistration {
            metadata,
            handler: Arc::new(move |ctx| Box::pin(handler(ctx))),
        };
        self.inner
            .tools
            .write()
            .expect("tools")
            .insert(name, registration);
        self
    }

    pub fn before<F, Fut>(&self, hook: F) -> &Self
    where
        F: Fn(ToolContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let hook: BeforeHook = Arc::new(move |ctx| Box::pin(hook(ctx)));
        self.inner
            .before_hooks
            .write()
            .expect("before_hooks")
            .push(hook);
        self
    }

    pub fn after<F, Fut>(&self, hook: F) -> &Self
    where
        F: Fn(ToolContext, Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        let hook: AfterHook = Arc::new(move |ctx, out| Box::pin(hook(ctx, out)));
        self.inner
            .after_hooks
            .write()
            .expect("after_hooks")
            .push(hook);
        self
    }

    /// Onion middleware (mirrors JS `app.use`).
    pub fn use_middleware<F>(&self, middleware: F) -> &Self
    where
        F: Fn(ToolContext, NextFn) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        let mw: MiddlewareFn = Arc::new(middleware);
        self.inner.middlewares.write().expect("middlewares").push(mw);
        self
    }

    pub fn verify_signature(&self, signature: &str, timestamp: i64, body: &str) -> bool {
        let now = Utc::now().timestamp();
        if (now - timestamp).abs() > self.inner.config.max_timestamp_skew_secs {
            return false;
        }
        let payload = format!("v1:{timestamp}:{body}");
        let mut mac = HmacSha256::new_from_slice(self.inner.config.signing_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        let expected = format!("v1={}", hex::encode(mac.finalize().into_bytes()));
        let a = expected.as_bytes();
        let b = signature.as_bytes();
        a.len() == b.len() && bool::from(a.ct_eq(b))
    }

    /// Handle a verified protocol request (after signature check).
    pub async fn handle(&self, request: QefroRequest) -> QefroResponse {
        if request.protocol_version != self.inner.config.protocol_version {
            return QefroResponse::Error {
                code: "protocol_mismatch".into(),
                message: "Unsupported protocol version".into(),
            };
        }

        match request.request_type.as_str() {
            "ping" => QefroResponse::Pong {
                protocol_version: self.inner.config.protocol_version.clone(),
                sdk_version: SDK_VERSION.into(),
            },
            "tools.list" => {
                let tools = self.inner.tools.read().expect("tools");
                QefroResponse::ToolsList {
                    tools: tools
                        .values()
                        .map(|r| RegisteredTool {
                            name: r.metadata.name.clone(),
                            description: r.metadata.description.clone(),
                            input_schema: r.metadata.input_schema.clone(),
                            authentication_methods: r.metadata.authentication_methods.clone(),
                            auth: r.metadata.auth,
                            permissions: r.metadata.permissions.clone(),
                            timeout: r.metadata.timeout,
                            lookup: r.metadata.lookup.clone(),
                        })
                        .collect(),
                    protocol_version: self.inner.config.protocol_version.clone(),
                    sdk_version: SDK_VERSION.into(),
                }
            }
            "tool.invoke" => {
                self.invoke(
                    request.tool,
                    request.parameters.unwrap_or_else(|| json!({})),
                    request.conversation_id.unwrap_or_else(Uuid::new_v4),
                    request.identity,
                    request.channel,
                    request.authentication,
                    None,
                )
                .await
            }
            "tool.resume" => {
                let Some(resume_token) = request.resume_token else {
                    return QefroResponse::Error {
                        code: "invalid_request".into(),
                        message: "resume_token is required".into(),
                    };
                };
                let Some(challenge_response) = request.challenge_response else {
                    return QefroResponse::Error {
                        code: "invalid_request".into(),
                        message: "challenge_response is required".into(),
                    };
                };
                let pending = {
                    let mut map = self.inner.pending.lock().await;
                    map.remove(&resume_token)
                };
                let Some(pending) = pending else {
                    return QefroResponse::Error {
                        code: "not_found".into(),
                        message: "resume token not found or expired".into(),
                    };
                };
                self.invoke(
                    Some(pending.tool),
                    pending.parameters,
                    pending.conversation_id,
                    pending.identity,
                    pending.channel,
                    request.authentication,
                    Some(challenge_response),
                )
                .await
            }
            _ => QefroResponse::Error {
                code: "invalid_request".into(),
                message: "Unsupported request type".into(),
            },
        }
    }

    /// Verify signature + protocol headers, then handle (mirrors JS `handleRaw`).
    pub async fn handle_raw(
        &self,
        body: &str,
        headers: &HeaderMap,
    ) -> (StatusCode, QefroResponse) {
        let signature = header_str(headers, "x-qefro-signature");
        let timestamp = header_str(headers, "x-qefro-timestamp")
            .and_then(|t| t.parse::<i64>().ok());

        let protocol_header = header_str(headers, "x-qefro-protocol")
            .or_else(|| header_str(headers, "x-qefro-protocol-version"));
        if let Some(proto) = protocol_header {
            if proto != self.inner.config.protocol_version {
                return (
                    StatusCode::BAD_REQUEST,
                    QefroResponse::Error {
                        code: "protocol_mismatch".into(),
                        message: format!("Unsupported protocol version {proto}"),
                    },
                );
            }
        }

        match (signature, timestamp) {
            (Some(sig), Some(ts)) if self.verify_signature(sig, ts, body) => {}
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    QefroResponse::Error {
                        code: "invalid_signature".into(),
                        message: "Invalid Qefro signature".into(),
                    },
                );
            }
        }

        let request: QefroRequest = match serde_json::from_str(body) {
            Ok(r) => r,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    QefroResponse::Error {
                        code: "invalid_request".into(),
                        message: e.to_string(),
                    },
                );
            }
        };

        (StatusCode::OK, self.handle(request).await)
    }

    /// Start an HTTP server (mirrors JS `listen`).
    pub async fn listen(&self, options: ListenOptions) -> Result<ListenHandle> {
        let host = options
            .host
            .unwrap_or_else(|| "0.0.0.0".to_string());
        let path = options
            .path
            .unwrap_or_else(|| self.inner.config.endpoint_path.clone());
        let path = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };

        let app_state = self.clone();
        let router = Router::new()
            .route(&path, post(http_handler))
            .with_state(app_state);

        let addr = format!("{host}:{}", options.port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        let url = format!("http://{host}:{}{path}", options.port);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let _ = axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = rx.await;
                })
                .await;
        });

        Ok(ListenHandle {
            url,
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    async fn invoke(
        &self,
        tool: Option<String>,
        parameters: Value,
        conversation_id: Uuid,
        identity: Option<Value>,
        channel: Option<String>,
        authentication: Option<Value>,
        auth_response: Option<String>,
    ) -> QefroResponse {
        let Some(tool_name) = tool else {
            return QefroResponse::Error {
                code: "invalid_request".into(),
                message: "tool is required".into(),
            };
        };

        let registration = {
            let tools = self.inner.tools.read().expect("tools");
            tools.get(&tool_name).cloned()
        };
        let Some(registration) = registration else {
            return QefroResponse::Error {
                code: "not_found".into(),
                message: format!("Unknown tool: {tool_name}"),
            };
        };

        let identity_value = identity.clone().unwrap_or_else(|| json!({}));
        let customer_state = Arc::new(Mutex::new(CustomerState::default()));

        {
            let auth = self.inner.auth_by_conversation.lock().await;
            if let Some(stored) = auth.get(&conversation_id) {
                if stored.expires_at_epoch_ms > Utc::now().timestamp_millis() {
                    let mut state = customer_state.lock().await;
                    state.current = Some(stored.customer.clone());
                    state.lookup_completed = true;
                }
            }
        }

        let customer_api = CustomerApi {
            app: self.clone(),
            identity: identity_value.clone(),
            parameters: parameters.clone(),
            conversation_id,
            channel: channel.clone(),
            auth_response: auth_response.clone(),
            state: customer_state.clone(),
        };

        let mut current_customer = customer_state.lock().await.current.clone();

        if registration.metadata.auth == ToolAuthMode::Required {
            match customer_api
                .authorize(registration.metadata.default_auth_method.clone())
                .await
            {
                Ok(customer) => current_customer = Some(customer),
                Err(e) => return map_invoke_error(e, self, &tool_name, &parameters, conversation_id, identity.clone(), channel.clone()).await,
            }
        }

        let ctx = ToolContext {
            identity: identity_value,
            parameters: parameters.clone(),
            conversation: Conversation {
                id: conversation_id,
            },
            channel: channel.clone(),
            authentication,
            auth_response,
            customer: current_customer,
            customer_api: Some(customer_api),
        };

        let before_hooks = self.inner.before_hooks.read().expect("before_hooks").clone();
        for hook in &before_hooks {
            if let Err(e) = hook(ctx.clone()).await {
                return map_invoke_error(e, self, &tool_name, &parameters, conversation_id, identity.clone(), channel.clone()).await;
            }
        }

        let handler = registration.handler.clone();
        let middlewares = self.inner.middlewares.read().expect("middlewares").clone();
        let run_result = run_middlewares(middlewares, ctx.clone(), handler).await;

        let output = match run_result {
            Ok(v) => v,
            Err(e) => {
                return map_invoke_error(
                    e,
                    self,
                    &tool_name,
                    &parameters,
                    conversation_id,
                    identity,
                    channel,
                )
                .await;
            }
        };

        let after_hooks = self.inner.after_hooks.read().expect("after_hooks").clone();
        let mut output = output;
        for hook in &after_hooks {
            match hook(ctx.clone(), output).await {
                Ok(v) => output = v,
                Err(e) => {
                    return map_invoke_error(
                        e,
                        self,
                        &tool_name,
                        &parameters,
                        conversation_id,
                        identity,
                        channel,
                    )
                    .await;
                }
            }
        }

        let auth = {
            let map = self.inner.auth_by_conversation.lock().await;
            map.get(&conversation_id)
                .filter(|v| v.expires_at_epoch_ms > Utc::now().timestamp_millis())
                .map(|v| v.auth.clone())
        };

        QefroResponse::Result {
            output,
            authentication_context: auth,
        }
    }

    async fn consume_auth_outcome(
        &self,
        outcome: AuthOutcome,
        conversation_id: Uuid,
        customer_state: Option<Arc<Mutex<CustomerState>>>,
        // When challenge: stash pending invoke
        pending_tool: Option<&str>,
        pending_parameters: Option<Value>,
        pending_identity: Option<Value>,
        pending_channel: Option<String>,
    ) -> Result<Value> {
        match outcome {
            AuthOutcome::Success { customer, auth } => {
                let ttl = auth.expires_in.unwrap_or(900).max(1);
                self.inner.auth_by_conversation.lock().await.insert(
                    conversation_id,
                    StoredAuth {
                        customer: customer.clone(),
                        auth,
                        expires_at_epoch_ms: Utc::now().timestamp_millis() + ttl * 1000,
                    },
                );
                if let Some(state) = customer_state {
                    let mut s = state.lock().await;
                    s.current = Some(customer.clone());
                    s.lookup_completed = true;
                }
                Ok(customer)
            }
            AuthOutcome::Challenge(challenge) => {
                if let (Some(tool), Some(parameters)) = (pending_tool, pending_parameters) {
                    let resume_token = Uuid::new_v4().to_string();
                    self.inner.pending.lock().await.insert(
                        resume_token.clone(),
                        PendingInvocation {
                            tool: tool.to_string(),
                            conversation_id,
                            parameters,
                            identity: pending_identity,
                            channel: pending_channel,
                        },
                    );
                    // Encode resume in error path via ChallengeSignal — callers for required-auth
                    // use map_invoke_error. For CustomerApi.authorize we raise ChallengeSignal.
                    let _ = resume_token;
                }
                Err(ChallengeSignal { challenge }.into())
            }
            AuthOutcome::Denied => Err(anyhow!("denied")),
            AuthOutcome::NotFound => Err(anyhow!("customer_not_found")),
        }
    }

    pub async fn require_authentication(
        &self,
        conversation_id: Uuid,
        outcome: AuthOutcome,
        tool: &str,
        parameters: Value,
        identity: Option<Value>,
        channel: Option<String>,
    ) -> std::result::Result<Value, QefroResponse> {
        match outcome {
            AuthOutcome::Success { customer, auth } => {
                let ttl = auth.expires_in.unwrap_or(900).max(1);
                self.inner.auth_by_conversation.lock().await.insert(
                    conversation_id,
                    StoredAuth {
                        customer: customer.clone(),
                        auth,
                        expires_at_epoch_ms: Utc::now().timestamp_millis() + ttl * 1000,
                    },
                );
                Ok(customer)
            }
            AuthOutcome::Challenge(challenge) => {
                let resume_token = Uuid::new_v4().to_string();
                self.inner.pending.lock().await.insert(
                    resume_token.clone(),
                    PendingInvocation {
                        tool: tool.to_string(),
                        conversation_id,
                        parameters,
                        identity,
                        channel,
                    },
                );
                Err(QefroResponse::Challenge {
                    resume_token,
                    challenge,
                })
            }
            AuthOutcome::Denied => Err(QefroResponse::Error {
                code: "denied".into(),
                message: "Authentication denied".into(),
            }),
            AuthOutcome::NotFound => Err(QefroResponse::Error {
                code: "customer_not_found".into(),
                message: "Customer not found".into(),
            }),
        }
    }
}

async fn map_invoke_error(
    e: anyhow::Error,
    app: &Qefro,
    tool_name: &str,
    parameters: &Value,
    conversation_id: Uuid,
    identity: Option<Value>,
    channel: Option<String>,
) -> QefroResponse {
    if let Some(signal) = e.downcast_ref::<ChallengeSignal>() {
        let resume_token = Uuid::new_v4().to_string();
        app.inner.pending.lock().await.insert(
            resume_token.clone(),
            PendingInvocation {
                tool: tool_name.to_string(),
                conversation_id,
                parameters: parameters.clone(),
                identity,
                channel,
            },
        );
        return QefroResponse::Challenge {
            resume_token,
            challenge: signal.challenge.clone(),
        };
    }

    let message = e.to_string();
    if message == "denied" {
        return QefroResponse::Error {
            code: "denied".into(),
            message: "Authentication denied".into(),
        };
    }
    if message == "customer_not_found" {
        return QefroResponse::Error {
            code: "customer_not_found".into(),
            message: "Customer not found".into(),
        };
    }
    if message == "customer_provider_missing" {
        return QefroResponse::Error {
            code: "configuration_error".into(),
            message: "Tool requires customer provider. Configure app.customer(...) first.".into(),
        };
    }

    QefroResponse::Error {
        code: "internal_error".into(),
        message,
    }
}

async fn run_middlewares(
    middlewares: Vec<MiddlewareFn>,
    ctx: ToolContext,
    handler: ToolHandler,
) -> Result<Value> {
    fn dispatch(
        i: usize,
        middlewares: Arc<Vec<MiddlewareFn>>,
        ctx: ToolContext,
        handler: ToolHandler,
    ) -> Pin<Box<dyn Future<Output = Result<Value>> + Send>> {
        Box::pin(async move {
            if i == middlewares.len() {
                return handler(ctx).await;
            }
            let mw = middlewares[i].clone();
            let mws = middlewares.clone();
            let h = handler.clone();
            let next: NextFn = Box::new(move |c| dispatch(i + 1, mws, c, h));
            mw(ctx, next).await
        })
    }

    dispatch(0, Arc::new(middlewares), ctx, handler).await
}

fn header_str<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    headers.get(key).and_then(|v| v.to_str().ok())
}

fn protocol_response_headers(app: &Qefro) -> HeaderMap {
    use axum::http::HeaderValue;
    let mut headers = HeaderMap::new();
    let proto = HeaderValue::from_str(&app.inner.config.protocol_version)
        .unwrap_or_else(|_| HeaderValue::from_static("1"));
    headers.insert("X-Qefro-Protocol", proto.clone());
    headers.insert("X-Qefro-Protocol-Version", proto);
    headers.insert("X-Qefro-SDK", HeaderValue::from_static(SDK_NAME));
    headers.insert(
        "X-Qefro-Version",
        HeaderValue::from_static(SDK_VERSION),
    );
    headers
}

async fn http_handler(
    State(app): State<Qefro>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let mut response_headers = protocol_response_headers(&app);
    let body_str = String::from_utf8_lossy(&body);
    let (status, resp) = app.handle_raw(&body_str, &headers).await;
    response_headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    (status, response_headers, Json(resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_lookup_dedupes() {
        let lookup = ToolLookup {
            by: Some("Email".into()),
            required: vec!["phone".into(), "email".into()],
        };
        assert_eq!(
            normalize_lookup(Some(&lookup)),
            vec!["phone".to_string(), "email".to_string()]
        );
    }

    #[test]
    fn signature_roundtrip() {
        let app = Qefro::new(QefroConfig::new("secret"));
        let body = r#"{"protocol_version":"1","request_id":"00000000-0000-0000-0000-000000000001","type":"ping"}"#;
        let ts = Utc::now().timestamp();
        let payload = format!("v1:{ts}:{body}");
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(payload.as_bytes());
        let sig = format!("v1={}", hex::encode(mac.finalize().into_bytes()));
        assert!(app.verify_signature(&sig, ts, body));
        assert!(!app.verify_signature("v1=deadbeef", ts, body));
    }

    #[tokio::test]
    async fn tools_list_includes_lookup() {
        let app = Qefro::new(QefroConfig::new("secret"));
        app.tool(
            ToolMetadata {
                name: "orders".into(),
                lookup: Some(ToolLookup {
                    by: Some("email".into()),
                    required: vec![],
                }),
                ..Default::default()
            },
            |_ctx| async move { Ok(json!({})) },
        );

        let resp = app
            .handle(QefroRequest {
                protocol_version: "1".into(),
                request_id: Uuid::new_v4(),
                request_type: "tools.list".into(),
                organization_id: None,
                conversation_id: None,
                channel: None,
                identity: None,
                tool: None,
                parameters: None,
                authentication: None,
                resume_token: None,
                challenge_response: None,
            })
            .await;

        match resp {
            QefroResponse::ToolsList { tools, .. } => {
                assert_eq!(tools.len(), 1);
                assert_eq!(
                    tools[0].lookup.as_ref().unwrap().required,
                    vec!["email".to_string()]
                );
            }
            other => panic!("unexpected {other:?}"),
        }
    }
}
