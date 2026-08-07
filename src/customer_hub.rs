//! Optional Customer Hub client — mirrors `@qefro-ai/backend` 1.7.0.
//!
//! Hub participation is gated by `QEFRO_CUSTOMER_HUB_ENABLED` (default false) and
//! `QEFRO_CUSTOMER_HUB_OPTIONAL` (default true). When disabled/optional, hub
//! methods soft-skip (`None` / no-op) instead of failing the tool.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Customer Hub gateway context injected on `tool.invoke` (`platform.customer`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformCustomerContext {
    pub tenant_id: String,
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solution_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Managed storage context (ADR-002) — kept for platform parity; Hub is independent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformStorageContext {
    pub tenant_id: String,
    pub workspace_id: String,
    pub installation_id: String,
    pub solution_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformStorageBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<PlatformStorageContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformCustomerBinding {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<PlatformCustomerContext>,
}

/// Platform capabilities injected on `tool.invoke`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PlatformCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<PlatformStorageBinding>,
    /// Optional Customer Hub binding (`QEFRO_CUSTOMER_HUB_ENABLED`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer: Option<PlatformCustomerBinding>,
}

#[derive(Debug, Default)]
pub struct CustomerState {
    pub current: Option<Value>,
    pub lookup_completed: bool,
}

pub fn env_flag_true(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(raw) if !raw.is_empty() => match raw.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        _ => default,
    }
}

/// Master switch — when false, hub methods soft-skip (never call Hub).
pub fn is_customer_hub_enabled() -> bool {
    env_flag_true("QEFRO_CUSTOMER_HUB_ENABLED", false)
}

/// When true (default), missing hub config returns `None` / no-ops.
pub fn is_customer_hub_optional() -> bool {
    env_flag_true("QEFRO_CUSTOMER_HUB_OPTIONAL", true)
}

pub fn read_identity_phone(identity: &Value) -> Option<String> {
    let obj = identity.as_object()?;
    for key in ["phone", "phone_number", "whatsapp_number", "whatsapp"] {
        if let Some(Value::String(s)) = obj.get(key) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Map a Person / Hub JSON object to the canonical HubCustomer projection.
pub fn hub_customer_from_person(person: Option<&Value>) -> Option<Value> {
    let person = person?.as_object()?;
    let id = person.get("id")?.as_str()?.trim();
    if id.is_empty() {
        return None;
    }

    let phone = person
        .get("phone_number")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            person
                .get("phone")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(str::to_string);

    let whatsapp = person
        .get("whatsapp_number")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| phone.clone());

    let display = person
        .get("display_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            person
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(str::to_string);

    let email = person.get("email").and_then(|v| {
        if v.is_string() {
            Some(v.clone())
        } else if v.is_null() {
            Some(Value::Null)
        } else {
            Some(Value::Null)
        }
    });

    let mut out = Value::Object(person.clone());
    let obj = out.as_object_mut().unwrap();
    obj.insert("id".into(), json!(id));
    obj.insert(
        "phone_number".into(),
        phone.map(Value::String).unwrap_or(Value::Null),
    );
    obj.insert(
        "whatsapp_number".into(),
        whatsapp.map(Value::String).unwrap_or(Value::Null),
    );
    obj.insert(
        "display_name".into(),
        display.map(Value::String).unwrap_or(Value::Null),
    );
    if let Some(email) = email {
        obj.insert("email".into(), email);
    } else {
        obj.insert("email".into(), Value::Null);
    }
    Some(out)
}

pub fn pick_identity(input: Option<&Value>, identity: &Value) -> Map<String, Value> {
    let mut merged = Map::new();
    if let Some(obj) = identity.as_object() {
        for (k, v) in obj {
            merged.insert(k.clone(), v.clone());
        }
    }
    if let Some(Value::Object(obj)) = input {
        for (k, v) in obj {
            merged.insert(k.clone(), v.clone());
        }
    }

    let phone = merged
        .get("phone_number")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            merged
                .get("phone")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(str::to_string);

    let whatsapp = merged
        .get("whatsapp_number")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let email = merged
        .get("email")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let display = merged
        .get("display_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            merged
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(str::to_string);

    let channel = merged
        .get("channel")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if whatsapp.is_some() {
                "whatsapp".into()
            } else if phone.is_some() {
                "sms".into()
            } else if email.is_some() {
                "email".into()
            } else {
                "api".into()
            }
        });

    let identifier = merged
        .get("identifier")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| whatsapp.clone())
        .or_else(|| phone.clone())
        .or_else(|| email.clone())
        .or_else(|| {
            merged
                .get("id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });

    let mut out = Map::new();
    if let Some(id) = merged.get("id").and_then(|v| v.as_str()) {
        out.insert("id".into(), json!(id));
    }
    if let Some(phone) = phone {
        out.insert("phone_number".into(), json!(phone));
    }
    if let Some(whatsapp) = whatsapp {
        out.insert("whatsapp_number".into(), json!(whatsapp));
    }
    if let Some(email) = email {
        out.insert("email".into(), json!(email));
    }
    if let Some(display) = display {
        out.insert("display_name".into(), json!(display));
    }
    out.insert("channel".into(), json!(channel));
    if let Some(identifier) = identifier {
        out.insert("identifier".into(), json!(identifier));
    }
    out
}

fn resolve_hub_endpoint(
    platform: Option<&PlatformCapabilities>,
) -> Option<(String, String, PlatformCustomerContext)> {
    let from_env = std::env::var("QEFRO_CUSTOMER_HUB_URL")
        .ok()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty());

    let customer = platform.and_then(|p| p.customer.as_ref());
    let base_url = customer
        .and_then(|c| c.base_url.as_ref())
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .or(from_env)?;

    let context = customer.and_then(|c| c.context.clone())?;
    if context.tenant_id.is_empty() || context.workspace_id.is_empty() {
        return None;
    }

    let token = customer
        .and_then(|c| c.token.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("QEFRO_SERVICE_TOKEN").ok())
        .or_else(|| std::env::var("QEFRO_INTERNAL_TOKEN").ok())
        .or_else(|| std::env::var("QEFRO_INTERNAL_BEARER").ok())
        .unwrap_or_default();

    Some((base_url, token, context))
}

/// POST `/v1/internal/customer-hub/{op}`. Soft-skip or hard-fail per flags.
pub async fn hub_call(
    platform: Option<&PlatformCapabilities>,
    op: &str,
    body: Value,
) -> Result<Option<Value>> {
    if !is_customer_hub_enabled() {
        if is_customer_hub_optional() {
            return Ok(None);
        }
        return Err(anyhow!("customer_hub_disabled"));
    }

    let Some((base_url, token, context)) = resolve_hub_endpoint(platform) else {
        if is_customer_hub_optional() {
            return Ok(None);
        }
        return Err(anyhow!("customer_hub_unavailable"));
    };

    let mut payload = body;
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("context".into(), serde_json::to_value(&context)?);
    }

    let client = reqwest::Client::new();
    let mut req = client
        .post(format!("{base_url}/v1/internal/customer-hub/{op}"))
        .header("content-type", "application/json")
        .json(&payload);
    if !token.is_empty() {
        req = req.bearer_auth(token);
    }

    let res = match req.send().await {
        Ok(r) => r,
        Err(err) => {
            if is_customer_hub_optional() {
                return Ok(None);
            }
            return Err(anyhow!("customer_hub.{op} failed: {err}"));
        }
    };

    let status = res.status().as_u16();
    let text = res.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        if is_customer_hub_optional() && (status == 404 || status >= 500) {
            return Ok(None);
        }
        return Err(anyhow!("customer_hub.{op} failed ({status}): {text}"));
    }
    if text.is_empty() {
        return Ok(Some(json!({})));
    }
    let parsed: Value = serde_json::from_str(&text)?;
    Ok(Some(parsed))
}

fn current_customer_id(state: &CustomerState) -> Option<String> {
    state
        .current
        .as_ref()
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// `ctx.timeline` — append Customer Hub timeline activities.
#[derive(Clone)]
pub struct TimelineContext {
    pub platform: Option<PlatformCapabilities>,
    pub state: Arc<Mutex<CustomerState>>,
}

impl TimelineContext {
    pub async fn append(&self, input: Value) -> Result<()> {
        let event_type = input
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if event_type.is_empty() {
            return Err(anyhow!("timeline_event_empty"));
        }
        let customer_id = input
            .get("customer_id")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| {
                // fall through to state below
                None
            });
        let customer_id = match customer_id {
            Some(id) => id,
            None => {
                let state = self.state.lock().await;
                match current_customer_id(&state) {
                    Some(id) => id,
                    None if is_customer_hub_optional() => return Ok(()),
                    None => return Err(anyhow!("customer_not_found")),
                }
            }
        };
        let payload = input.get("payload").cloned().unwrap_or_else(|| json!({}));
        let source = input
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("sdk");
        hub_call(
            self.platform.as_ref(),
            "timeline_append",
            json!({
                "customer_id": customer_id,
                "event_type": event_type,
                "payload": payload,
                "source": source,
            }),
        )
        .await?;
        Ok(())
    }
}

/// `ctx.membership` — attach/detach solution membership.
#[derive(Clone)]
pub struct MembershipContext {
    pub platform: Option<PlatformCapabilities>,
    pub state: Arc<Mutex<CustomerState>>,
    pub solution_id: Option<String>,
}

impl MembershipContext {
    async fn customer_id_or_optional(&self, input: Option<&Value>) -> Result<Option<String>> {
        if let Some(id) = input
            .and_then(|v| v.get("customer_id"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            return Ok(Some(id.to_string()));
        }
        let state = self.state.lock().await;
        if let Some(id) = current_customer_id(&state) {
            return Ok(Some(id));
        }
        if is_customer_hub_optional() {
            return Ok(None);
        }
        Err(anyhow!("customer_not_found"))
    }

    pub async fn attach(&self, input: Option<Value>) -> Result<()> {
        let customer_id = match self.customer_id_or_optional(input.as_ref()).await? {
            Some(id) => id,
            None => return Ok(()),
        };
        let solution_id = input
            .as_ref()
            .and_then(|v| v.get("solution_id"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| self.solution_id.clone());
        let role = input
            .as_ref()
            .and_then(|v| v.get("role"))
            .cloned()
            .unwrap_or(Value::Null);
        let metadata = input
            .as_ref()
            .and_then(|v| v.get("metadata"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        hub_call(
            self.platform.as_ref(),
            "membership_attach",
            json!({
                "customer_id": customer_id,
                "solution_id": solution_id,
                "role": role,
                "metadata": metadata,
            }),
        )
        .await?;
        Ok(())
    }

    pub async fn detach(&self, input: Option<Value>) -> Result<()> {
        let customer_id = match self.customer_id_or_optional(input.as_ref()).await? {
            Some(id) => id,
            None => return Ok(()),
        };
        let solution_id = input
            .as_ref()
            .and_then(|v| v.get("solution_id"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| self.solution_id.clone());
        let role = input
            .as_ref()
            .and_then(|v| v.get("role"))
            .cloned()
            .unwrap_or(Value::Null);
        let metadata = input
            .as_ref()
            .and_then(|v| v.get("metadata"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        hub_call(
            self.platform.as_ref(),
            "membership_detach",
            json!({
                "customer_id": customer_id,
                "solution_id": solution_id,
                "role": role,
                "metadata": metadata,
            }),
        )
        .await?;
        Ok(())
    }
}

/// `ctx.consent` — grant/revoke consent purposes.
#[derive(Clone)]
pub struct ConsentContext {
    pub platform: Option<PlatformCapabilities>,
    pub state: Arc<Mutex<CustomerState>>,
}

impl ConsentContext {
    async fn customer_id_or_optional(&self, input: &Value) -> Result<Option<String>> {
        if let Some(id) = input
            .get("customer_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            return Ok(Some(id.to_string()));
        }
        let state = self.state.lock().await;
        if let Some(id) = current_customer_id(&state) {
            return Ok(Some(id));
        }
        if is_customer_hub_optional() {
            return Ok(None);
        }
        Err(anyhow!("customer_not_found"))
    }

    pub async fn grant(&self, input: Value) -> Result<()> {
        let purpose = input
            .get("purpose")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if purpose.is_empty() {
            return Err(anyhow!("consent_purpose_empty"));
        }
        let customer_id = match self.customer_id_or_optional(&input).await? {
            Some(id) => id,
            None => return Ok(()),
        };
        let metadata = input.get("metadata").cloned().unwrap_or_else(|| json!({}));
        hub_call(
            self.platform.as_ref(),
            "consent_grant",
            json!({
                "customer_id": customer_id,
                "purpose": purpose,
                "metadata": metadata,
            }),
        )
        .await?;
        Ok(())
    }

    pub async fn revoke(&self, input: Value) -> Result<()> {
        let purpose = input
            .get("purpose")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if purpose.is_empty() {
            return Err(anyhow!("consent_purpose_empty"));
        }
        let customer_id = match self.customer_id_or_optional(&input).await? {
            Some(id) => id,
            None => return Ok(()),
        };
        let metadata = input.get("metadata").cloned().unwrap_or_else(|| json!({}));
        hub_call(
            self.platform.as_ref(),
            "consent_revoke",
            json!({
                "customer_id": customer_id,
                "purpose": purpose,
                "metadata": metadata,
            }),
        )
        .await?;
        Ok(())
    }
}

/// Seed hub customer projection from a Person snapshot on `tool.invoke`.
pub fn seed_from_person(person: &Value) -> Option<Value> {
    let id = person.get("id")?.as_str()?.to_string();
    if id.is_empty() {
        return None;
    }
    Some(json!({
        "id": id,
        "phone_number": person.get("phone").cloned().unwrap_or(Value::Null),
        "whatsapp_number": person.get("phone").cloned().unwrap_or(Value::Null),
        "display_name": person.get("name").cloned().unwrap_or(Value::Null),
        "email": person.get("email").cloned().unwrap_or(Value::Null),
        "status": person.get("status").cloned().unwrap_or(Value::Null),
        "workspace_id": person.get("workspace_id").cloned().unwrap_or(Value::Null),
    }))
}

#[cfg(test)]
pub(crate) static HUB_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_default_off_optional() {
        let _guard = HUB_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("QEFRO_CUSTOMER_HUB_ENABLED");
        std::env::remove_var("QEFRO_CUSTOMER_HUB_OPTIONAL");
        assert!(!is_customer_hub_enabled());
        assert!(is_customer_hub_optional());
    }

    #[test]
    fn hub_customer_maps_person_fields() {
        let hub = hub_customer_from_person(Some(&json!({
            "id": "p1",
            "name": "Ada",
            "phone": "+1555",
            "email": "a@b.c",
        })))
        .unwrap();
        assert_eq!(hub["id"], "p1");
        assert_eq!(hub["display_name"], "Ada");
        assert_eq!(hub["phone_number"], "+1555");
        assert_eq!(hub["whatsapp_number"], "+1555");
        assert_eq!(hub["email"], "a@b.c");
        assert!(hub_customer_from_person(Some(&json!({"name": "x"}))).is_none());
        assert!(hub_customer_from_person(None).is_none());
    }

    #[tokio::test]
    async fn resolve_soft_skips_when_disabled() {
        let _guard = HUB_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("QEFRO_CUSTOMER_HUB_ENABLED", "false");
        std::env::set_var("QEFRO_CUSTOMER_HUB_OPTIONAL", "true");
        let out = hub_call(None, "resolve", json!({"phone_number": "+1"}))
            .await
            .unwrap();
        assert!(out.is_none());
        std::env::remove_var("QEFRO_CUSTOMER_HUB_ENABLED");
        std::env::remove_var("QEFRO_CUSTOMER_HUB_OPTIONAL");
    }

    #[tokio::test]
    async fn resolve_hard_fails_when_required() {
        let _guard = HUB_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("QEFRO_CUSTOMER_HUB_ENABLED", "true");
        std::env::set_var("QEFRO_CUSTOMER_HUB_OPTIONAL", "false");
        std::env::remove_var("QEFRO_CUSTOMER_HUB_URL");
        let err = hub_call(None, "resolve", json!({"phone_number": "+1"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("customer_hub_unavailable"));
        std::env::remove_var("QEFRO_CUSTOMER_HUB_ENABLED");
        std::env::remove_var("QEFRO_CUSTOMER_HUB_OPTIONAL");
    }
}
