use anyhow::Result;
use async_trait::async_trait;
use qefro_backend_sdk::{
    AuthBuilder, AuthenticationContextPayload, CustomerAuthorizeContext, CustomerLookupContext,
    CustomerProvider, ListenOptions, Qefro, QefroConfig, ToolAuthMode, ToolLookup, ToolMetadata,
};
use serde_json::{json, Value};

struct DemoCustomer;

#[async_trait]
impl CustomerProvider for DemoCustomer {
    async fn lookup(&self, ctx: &CustomerLookupContext) -> Result<Option<Value>> {
        let id = ctx
            .identity
            .get("customer_id")
            .or_else(|| ctx.identity.get("phone"))
            .or_else(|| ctx.identity.get("email"))
            .cloned()
            .unwrap_or_else(|| json!("demo-customer"));
        Ok(Some(json!({ "id": id })))
    }

    async fn authorize(&self, ctx: &CustomerAuthorizeContext) -> Result<qefro_backend_sdk::AuthOutcome> {
        let auth = AuthBuilder::new(ctx.response.clone());
        // First call: challenge; resume with challenge_response succeeds.
        if ctx.response.as_deref().is_none() {
            if let Some(email) = ctx.identity.get("email").and_then(|v| v.as_str()) {
                return Ok(auth.email_otp(email, None));
            }
        }
        Ok(auth.success(
            ctx.customer.clone(),
            AuthenticationContextPayload {
                credential_type: Some("bearer_token".into()),
                access_token: Some("dev".into()),
                credential: None,
                refresh_token: None,
                expires_in: Some(900),
                customer_id: None,
            },
        ))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let secret = std::env::var("QEFRO_SIGNING_SECRET").unwrap_or_else(|_| "dev-secret".into());
    let app = Qefro::new(QefroConfig::new(secret));
    app.customer(DemoCustomer);

    app.tool(
        ToolMetadata {
            name: "get_orders".into(),
            description: Some("List orders for the authenticated customer".into()),
            auth: ToolAuthMode::Required,
            lookup: Some(ToolLookup {
                by: Some("email".into()),
                required: vec![],
            }),
            ..Default::default()
        },
        |ctx| async move {
            let customer_id = ctx
                .customer
                .as_ref()
                .and_then(|c| c.get("id"))
                .cloned()
                .unwrap_or_else(|| json!("unknown"));
            Ok(json!([{ "orderId": "ord_1", "customerId": customer_id }]))
        },
    );

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8088);
    let handle = app
        .listen(ListenOptions {
            port,
            host: Some("0.0.0.0".into()),
            path: Some("/qefro".into()),
        })
        .await?;
    println!("Qefro Rust SDK listening at {}", handle.url);
    println!("Wire this URL into Admin Console → SDK Connections, then Sync Tools.");

    // Keep process alive until Ctrl-C.
    tokio::signal::ctrl_c().await?;
    handle.close().await;
    Ok(())
}
