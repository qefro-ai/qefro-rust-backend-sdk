use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Package name reported to Qefro Runtime (`X-Qefro-SDK` / protocol payloads).
pub const SDK_NAME: &str = "qefro-backend-sdk";
/// Package version reported to Qefro Runtime (`sdk_version` / `X-Qefro-Version`).
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

type ToolHandler = Arc<dyn Fn(ToolContext) -> ToolFuture + Send + Sync>;
type ToolFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value>> + Send>>;

#[derive(Debug, Clone)]
pub struct QefroConfig {
    pub signing_secret: String,
    pub protocol_version: String,
    pub max_timestamp_skew_secs: i64,
}

impl QefroConfig {
    pub fn new(signing_secret: impl Into<String>) -> Self {
        Self {
            signing_secret: signing_secret.into(),
            protocol_version: "1".into(),
            max_timestamp_skew_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolAuthMode {
    None,
    Optional,
    Required,
}

impl Default for ToolAuthMode {
    fn default() -> Self {
        Self::Optional
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolMetadata {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub authentication_methods: Vec<String>,
    #[serde(default)]
    pub auth: ToolAuthMode,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub default_auth_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredTool {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: Option<Value>,
    #[serde(default)]
    pub authentication_methods: Vec<String>,
    #[serde(default)]
    pub auth: ToolAuthMode,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationContextPayload {
    #[serde(rename = "type")]
    pub credential_type: Option<String>,
    pub access_token: Option<String>,
    pub credential: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: Option<i64>,
    pub customer_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePayload {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub message: String,
    pub destination_hint: Option<String>,
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

#[derive(Clone)]
pub struct ToolContext {
    pub identity: Value,
    pub parameters: Value,
    pub conversation_id: Uuid,
    pub channel: Option<String>,
    pub authentication: Option<Value>,
    pub auth_response: Option<String>,
    pub customer: Option<Value>,
}

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

#[derive(Debug, Clone)]
pub struct CustomerLookupContext {
    pub identity: Value,
    pub parameters: Value,
    pub conversation_id: Uuid,
    pub channel: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CustomerAuthorizeContext {
    pub customer: Value,
    pub method: Option<String>,
    pub response: Option<String>,
    pub identity: Value,
    pub parameters: Value,
    pub conversation_id: Uuid,
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

#[derive(Debug, Clone)]
pub struct ListenHandle {
    pub url: String,
}

pub struct Qefro {
    config: QefroConfig,
    tools: HashMap<String, ToolRegistration>,
    pending: HashMap<String, PendingInvocation>,
    auth_by_conversation: HashMap<Uuid, StoredAuth>,
    customer_provider: Option<Arc<dyn CustomerProvider>>,
}

impl Qefro {
    pub fn new(config: QefroConfig) -> Self {
        Self {
            config,
            tools: HashMap::new(),
            pending: HashMap::new(),
            auth_by_conversation: HashMap::new(),
            customer_provider: None,
        }
    }

    pub fn customer<P>(&mut self, provider: P) -> &mut Self
    where
        P: CustomerProvider + 'static,
    {
        self.customer_provider = Some(Arc::new(provider));
        self
    }

    pub fn tool<F, Fut>(&mut self, metadata: ToolMetadata, handler: F)
    where
        F: Fn(ToolContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Value>> + Send + 'static,
    {
        let name = metadata.name.clone();
        self.tools.insert(
            name,
            ToolRegistration {
                metadata,
                handler: Arc::new(move |ctx| Box::pin(handler(ctx))),
            },
        );
    }

    pub async fn listen(&self, options: ListenOptions) -> Result<ListenHandle> {
        let host = options.host.unwrap_or_else(|| "0.0.0.0".to_string());
        let path = options.path.unwrap_or_else(|| "/qefro".to_string());
        Ok(ListenHandle {
            url: format!("http://{host}:{}{path}", options.port),
        })
    }

    pub fn verify_signature(&self, signature: &str, timestamp: i64, body: &str) -> bool {
        let now = Utc::now().timestamp();
        if (now - timestamp).abs() > self.config.max_timestamp_skew_secs {
            return false;
        }
        let payload = format!("v1:{timestamp}:{body}");
        let mut mac = HmacSha256::new_from_slice(self.config.signing_secret.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        let expected = format!("v1={}", hex::encode(mac.finalize().into_bytes()));
        expected == signature
    }

    pub async fn handle(&mut self, request: QefroRequest) -> QefroResponse {
        if request.protocol_version != self.config.protocol_version {
            return QefroResponse::Error {
                code: "protocol_mismatch".into(),
                message: "Unsupported protocol version".into(),
            };
        }

        match request.request_type.as_str() {
            "ping" => QefroResponse::Pong {
                protocol_version: self.config.protocol_version.clone(),
                sdk_version: SDK_VERSION.into(),
            },
            "tools.list" => QefroResponse::ToolsList {
                tools: self
                    .tools
                    .values()
                    .map(|r| RegisteredTool {
                        name: r.metadata.name.clone(),
                        description: r.metadata.description.clone(),
                        input_schema: r.metadata.input_schema.clone(),
                        authentication_methods: r.metadata.authentication_methods.clone(),
                        auth: r.metadata.auth,
                        permissions: r.metadata.permissions.clone(),
                        timeout: r.metadata.timeout,
                    })
                    .collect(),
                protocol_version: self.config.protocol_version.clone(),
                sdk_version: SDK_VERSION.into(),
            },
            "tool.invoke" => {
                self
                    .invoke(
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
                let Some(pending) = self.pending.remove(&resume_token) else {
                    return QefroResponse::Error {
                        code: "not_found".into(),
                        message: "resume token not found".into(),
                    };
                };
                self
                    .invoke(
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

    async fn invoke(
        &mut self,
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

        let Some(registration) = self.tools.get(&tool_name).cloned() else {
            return QefroResponse::Error {
                code: "not_found".into(),
                message: format!("Unknown tool: {tool_name}"),
            };
        };

        let mut current_customer = self
            .auth_by_conversation
            .get(&conversation_id)
            .filter(|a| a.expires_at_epoch_ms > Utc::now().timestamp_millis())
            .map(|a| a.customer.clone());

        if registration.metadata.auth == ToolAuthMode::Required {
            match self
                .ensure_authorized_customer(
                    &tool_name,
                    &registration.metadata,
                    &parameters,
                    conversation_id,
                    identity.clone(),
                    channel.clone(),
                    auth_response.clone(),
                )
                .await
            {
                Ok(customer) => {
                    current_customer = Some(customer);
                }
                Err(resp) => return resp,
            }
        }

        let ctx = ToolContext {
            identity: identity.clone().unwrap_or_else(|| json!({})),
            parameters: parameters.clone(),
            conversation_id,
            channel,
            authentication,
            auth_response,
            customer: current_customer,
        };

        match (registration.handler)(ctx).await {
            Ok(output) => {
                let auth = self
                    .auth_by_conversation
                    .get(&conversation_id)
                    .filter(|v| v.expires_at_epoch_ms > Utc::now().timestamp_millis())
                    .map(|v| v.auth.clone());
                QefroResponse::Result {
                    output,
                    authentication_context: auth,
                }
            }
            Err(e) => QefroResponse::Error {
                code: "internal_error".into(),
                message: e.to_string(),
            },
        }
    }

    async fn ensure_authorized_customer(
        &mut self,
        tool: &str,
        metadata: &ToolMetadata,
        parameters: &Value,
        conversation_id: Uuid,
        identity: Option<Value>,
        channel: Option<String>,
        auth_response: Option<String>,
    ) -> std::result::Result<Value, QefroResponse> {
        if let Some(existing) = self
            .auth_by_conversation
            .get(&conversation_id)
            .filter(|a| a.expires_at_epoch_ms > Utc::now().timestamp_millis())
        {
            return Ok(existing.customer.clone());
        }

        let Some(provider) = self.customer_provider.as_ref() else {
            return Err(QefroResponse::Error {
                code: "configuration_error".into(),
                message: "Tool requires customer provider. Configure app.customer(...)".into(),
            });
        };

        let lookup = CustomerLookupContext {
            identity: identity.clone().unwrap_or_else(|| json!({})),
            parameters: parameters.clone(),
            conversation_id,
            channel: channel.clone(),
        };

        let Some(customer) = provider.lookup(&lookup).await.map_err(|e| QefroResponse::Error {
            code: "internal_error".into(),
            message: e.to_string(),
        })? else {
            return Err(QefroResponse::Error {
                code: "customer_not_found".into(),
                message: "Customer not found".into(),
            });
        };

        let authorize = CustomerAuthorizeContext {
            customer,
            method: metadata.default_auth_method.clone(),
            response: auth_response,
            identity: identity.unwrap_or_else(|| json!({})),
            parameters: parameters.clone(),
            conversation_id,
            channel,
        };

        let outcome = provider
            .authorize(&authorize)
            .await
            .map_err(|e| QefroResponse::Error {
                code: "internal_error".into(),
                message: e.to_string(),
            })?;

        self.require_authentication(
            conversation_id,
            outcome,
            tool,
            parameters.clone(),
            Some(authorize.identity),
            authorize.channel,
        )
    }

    pub fn require_authentication(
        &mut self,
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
                self.auth_by_conversation.insert(
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
                self.pending.insert(
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