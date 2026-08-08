//! Marketing capability registration (ADR-004 Phase 1).
//!
//! Apps register metadata only — audiences, variables, actions, landing pages,
//! and channels. The platform owns campaigns, delivery, and analytics.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

/// Error from [`validate_marketing_definition`] / [`Qefro::marketing`](crate::Qefro::marketing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketingError {
    Message(String),
}

impl std::fmt::Display for MarketingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MarketingError::Message(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for MarketingError {}

fn err(msg: impl Into<String>) -> MarketingError {
    MarketingError::Message(msg.into())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingAudienceCustomerHub {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "consentPurpose")]
    pub consent_purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attrs: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingAudienceAppQuery {
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingAudience {
    pub id: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "customerHub")]
    pub customer_hub: Option<MarketingAudienceCustomerHub>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "appQuery")]
    pub app_query: Option<MarketingAudienceAppQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "staticFilter")]
    pub static_filter: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingVariable {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub var_type: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingAction {
    pub id: String,
    pub label: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "landingPageId")]
    pub landing_page_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "urlTemplate")]
    pub url_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingLandingPage {
    pub id: String,
    pub label: String,
    pub path: String,
    pub host: String,
}

/// Channel support. `provider` is reserved for multi-provider routing later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingChannel {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// Input to `app.marketing(...)`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct MarketingDefinition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audiences: Vec<MarketingAudience>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variables: Vec<MarketingVariable>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<MarketingAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "landingPages")]
    pub landing_pages: Vec<MarketingLandingPage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<MarketingChannel>,
}

/// Normalized registration nested under `capabilities.list.marketing.metadata`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingRegistration {
    pub version: u32,
    pub audiences: Vec<MarketingAudience>,
    pub variables: Vec<MarketingVariable>,
    pub actions: Vec<MarketingAction>,
    #[serde(rename = "landingPages")]
    pub landing_pages: Vec<MarketingLandingPage>,
    pub channels: Vec<MarketingChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingMetadata {
    pub audiences: Vec<MarketingAudience>,
    pub variables: Vec<MarketingVariable>,
    pub actions: Vec<MarketingAction>,
    #[serde(rename = "landingPages")]
    pub landing_pages: Vec<MarketingLandingPage>,
    pub channels: Vec<MarketingChannel>,
}

/// Wire shape for `capabilities.list.marketing`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarketingCapability {
    pub version: u32,
    pub metadata: MarketingMetadata,
}

const AUDIENCE_SOURCES: &[&str] = &["customer_hub", "app_query", "static_filter"];
const VARIABLE_TYPES: &[&str] = &["string", "number", "datetime", "boolean", "url", "currency"];
const VARIABLE_SOURCES: &[&str] = &["customer_hub", "app_context", "campaign", "literal"];
const ACTION_KINDS: &[&str] = &["url", "deep_link", "quick_reply", "whatsapp_cta", "postback"];
const LANDING_HOSTS: &[&str] = &["app", "platform"];

fn require_non_empty(value: &str, path: &str) -> Result<String, MarketingError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(err(format!("marketing: {path} must be a non-empty string")));
    }
    Ok(trimmed.to_string())
}

fn assert_unique_ids(ids: &[String], kind: &str) -> Result<(), MarketingError> {
    let mut seen = HashSet::new();
    for id in ids {
        if !seen.insert(id.clone()) {
            return Err(err(format!("marketing: duplicate {kind} id \"{id}\"")));
        }
    }
    Ok(())
}

fn validate_audience(a: &MarketingAudience, index: usize) -> Result<MarketingAudience, MarketingError> {
    let id = require_non_empty(&a.id, &format!("audiences[{index}].id"))?;
    let label = require_non_empty(&a.label, &format!("audiences[{index}].label"))?;
    let source = require_non_empty(&a.source, &format!("audiences[{index}].source"))?;
    if !AUDIENCE_SOURCES.contains(&source.as_str()) {
        return Err(err(format!(
            "marketing: audiences[{index}].source must be one of customer_hub|app_query|static_filter"
        )));
    }
    let mut out = MarketingAudience {
        id,
        label,
        description: a
            .description
            .as_ref()
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty()),
        source,
        customer_hub: a.customer_hub.clone(),
        app_query: None,
        static_filter: a.static_filter.clone(),
    };
    if let Some(aq) = &a.app_query {
        let tool = require_non_empty(&aq.tool, &format!("audiences[{index}].appQuery.tool"))?;
        out.app_query = Some(MarketingAudienceAppQuery {
            tool,
            input: aq.input.clone(),
        });
    }
    Ok(out)
}

fn validate_variable(v: &MarketingVariable, index: usize) -> Result<MarketingVariable, MarketingError> {
    let id = require_non_empty(&v.id, &format!("variables[{index}].id"))?;
    let label = require_non_empty(&v.label, &format!("variables[{index}].label"))?;
    let var_type = require_non_empty(&v.var_type, &format!("variables[{index}].type"))?;
    if !VARIABLE_TYPES.contains(&var_type.as_str()) {
        return Err(err(format!(
            "marketing: variables[{index}].type must be one of string|number|datetime|boolean|url|currency"
        )));
    }
    let source = require_non_empty(&v.source, &format!("variables[{index}].source"))?;
    if !VARIABLE_SOURCES.contains(&source.as_str()) {
        return Err(err(format!(
            "marketing: variables[{index}].source must be one of customer_hub|app_context|campaign|literal"
        )));
    }
    Ok(MarketingVariable {
        id,
        label,
        var_type,
        source,
        path: v
            .path
            .as_ref()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty()),
        required: v.required,
    })
}

fn validate_action(a: &MarketingAction, index: usize) -> Result<MarketingAction, MarketingError> {
    let id = require_non_empty(&a.id, &format!("actions[{index}].id"))?;
    let label = require_non_empty(&a.label, &format!("actions[{index}].label"))?;
    let kind = require_non_empty(&a.kind, &format!("actions[{index}].kind"))?;
    if !ACTION_KINDS.contains(&kind.as_str()) {
        return Err(err(format!(
            "marketing: actions[{index}].kind must be one of url|deep_link|quick_reply|whatsapp_cta|postback"
        )));
    }
    Ok(MarketingAction {
        id,
        label,
        kind,
        landing_page_id: a
            .landing_page_id
            .as_ref()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty()),
        url_template: a
            .url_template
            .as_ref()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty()),
        payload: a.payload.clone(),
    })
}

fn validate_landing_page(
    p: &MarketingLandingPage,
    index: usize,
) -> Result<MarketingLandingPage, MarketingError> {
    let id = require_non_empty(&p.id, &format!("landingPages[{index}].id"))?;
    let label = require_non_empty(&p.label, &format!("landingPages[{index}].label"))?;
    let path = require_non_empty(&p.path, &format!("landingPages[{index}].path"))?;
    let host = require_non_empty(&p.host, &format!("landingPages[{index}].host"))?;
    if !LANDING_HOSTS.contains(&host.as_str()) {
        return Err(err(format!(
            "marketing: landingPages[{index}].host must be one of app|platform"
        )));
    }
    Ok(MarketingLandingPage {
        id,
        label,
        path,
        host,
    })
}

fn validate_channel(c: &MarketingChannel, index: usize) -> Result<MarketingChannel, MarketingError> {
    let id = require_non_empty(&c.id, &format!("channels[{index}].id"))?;
    Ok(MarketingChannel {
        id,
        provider: c
            .provider
            .as_ref()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty()),
        label: c
            .label
            .as_ref()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty()),
        enabled: c.enabled,
    })
}

/// Validate and normalize a marketing definition.
pub fn validate_marketing_definition(
    def: MarketingDefinition,
) -> Result<MarketingRegistration, MarketingError> {
    let version = match def.version {
        None => 1,
        Some(v) if v >= 1 => v,
        Some(_) => return Err(err("marketing: version must be a positive integer")),
    };

    let audiences: Vec<_> = def
        .audiences
        .iter()
        .enumerate()
        .map(|(i, a)| validate_audience(a, i))
        .collect::<Result<_, _>>()?;
    let variables: Vec<_> = def
        .variables
        .iter()
        .enumerate()
        .map(|(i, v)| validate_variable(v, i))
        .collect::<Result<_, _>>()?;
    let actions: Vec<_> = def
        .actions
        .iter()
        .enumerate()
        .map(|(i, a)| validate_action(a, i))
        .collect::<Result<_, _>>()?;
    let landing_pages: Vec<_> = def
        .landing_pages
        .iter()
        .enumerate()
        .map(|(i, p)| validate_landing_page(p, i))
        .collect::<Result<_, _>>()?;
    let channels: Vec<_> = def
        .channels
        .iter()
        .enumerate()
        .map(|(i, c)| validate_channel(c, i))
        .collect::<Result<_, _>>()?;

    assert_unique_ids(
        &audiences.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
        "audience",
    )?;
    assert_unique_ids(
        &variables.iter().map(|v| v.id.clone()).collect::<Vec<_>>(),
        "variable",
    )?;
    assert_unique_ids(
        &actions.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
        "action",
    )?;
    assert_unique_ids(
        &landing_pages
            .iter()
            .map(|p| p.id.clone())
            .collect::<Vec<_>>(),
        "landingPage",
    )?;
    assert_unique_ids(
        &channels.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
        "channel",
    )?;

    for (i, action) in actions.iter().enumerate() {
        if let Some(ref lp) = action.landing_page_id {
            if !landing_pages.iter().any(|p| p.id == *lp) {
                return Err(err(format!(
                    "marketing: actions[{i}].landingPageId \"{lp}\" does not match any landingPages[].id"
                )));
            }
        }
    }

    Ok(MarketingRegistration {
        version,
        audiences,
        variables,
        actions,
        landing_pages,
        channels,
    })
}

pub fn to_marketing_capability(reg: &MarketingRegistration) -> MarketingCapability {
    MarketingCapability {
        version: reg.version,
        metadata: MarketingMetadata {
            audiences: reg.audiences.clone(),
            variables: reg.variables.clone(),
            actions: reg.actions.clone(),
            landing_pages: reg.landing_pages.clone(),
            channels: reg.channels.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_def() -> MarketingDefinition {
        MarketingDefinition {
            version: Some(1),
            audiences: vec![MarketingAudience {
                id: "vip".into(),
                label: "VIP".into(),
                description: None,
                source: "customer_hub".into(),
                customer_hub: Some(MarketingAudienceCustomerHub {
                    tags: Some(vec!["vip".into()]),
                    consent_purpose: Some("marketing".into()),
                    attrs: None,
                }),
                app_query: None,
                static_filter: None,
            }],
            variables: vec![MarketingVariable {
                id: "name".into(),
                label: "Name".into(),
                var_type: "string".into(),
                source: "customer_hub".into(),
                path: Some("display_name".into()),
                required: Some(true),
            }],
            actions: vec![MarketingAction {
                id: "book".into(),
                label: "Book".into(),
                kind: "url".into(),
                landing_page_id: Some("booking".into()),
                url_template: None,
                payload: None,
            }],
            landing_pages: vec![MarketingLandingPage {
                id: "booking".into(),
                label: "Booking".into(),
                path: "/booking".into(),
                host: "app".into(),
            }],
            channels: vec![
                MarketingChannel {
                    id: "whatsapp".into(),
                    provider: Some("meta".into()),
                    label: None,
                    enabled: Some(true),
                },
                MarketingChannel {
                    id: "email".into(),
                    provider: Some("sendgrid".into()),
                    label: None,
                    enabled: Some(true),
                },
            ],
        }
    }

    #[test]
    fn validates_full_definition() {
        let reg = validate_marketing_definition(sample_def()).unwrap();
        assert_eq!(reg.version, 1);
        assert_eq!(reg.channels[0].provider.as_deref(), Some("meta"));
        let cap = to_marketing_capability(&reg);
        let wire = serde_json::to_value(&cap).unwrap();
        assert_eq!(wire["version"], 1);
        assert!(wire["metadata"]["audiences"].is_array());
        assert_eq!(wire["metadata"]["channels"][0]["provider"], "meta");
        assert!(wire.get("audiences").is_none());
    }

    #[test]
    fn rejects_bad_source() {
        let mut def = sample_def();
        def.audiences[0].source = "crm".into();
        let err = validate_marketing_definition(def).unwrap_err();
        assert!(err.to_string().contains("source"));
    }

    #[test]
    fn rejects_duplicate_channel() {
        let mut def = sample_def();
        def.channels.push(MarketingChannel {
            id: "whatsapp".into(),
            provider: None,
            label: None,
            enabled: None,
        });
        let err = validate_marketing_definition(def).unwrap_err();
        assert!(err.to_string().contains("duplicate channel"));
    }

    #[test]
    fn wire_uses_camel_case_keys() {
        let reg = validate_marketing_definition(sample_def()).unwrap();
        let wire = serde_json::to_value(to_marketing_capability(&reg)).unwrap();
        assert!(wire["metadata"].get("landingPages").is_some());
        assert_eq!(
            wire["metadata"]["actions"][0]["landingPageId"],
            json!("booking")
        );
    }
}
