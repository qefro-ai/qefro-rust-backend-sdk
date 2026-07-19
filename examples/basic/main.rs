use anyhow::Result;
use async_trait::async_trait;
use qefro_backend_sdk::{
    AuthOutcome, AuthenticationContextPayload, CustomerAuthorizeContext, CustomerLookupContext,
    CustomerProvider, ListenOptions, Qefro, QefroConfig, ToolAuthMode, ToolMetadata,
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
            .cloned()
            .unwrap_or_else(|| json!("demo-customer"));
        Ok(Some(json!({ "id": id })))
    }

    async fn authorize(&self, ctx: &CustomerAuthorizeContext) -> Result<AuthOutcome> {
        Ok(AuthOutcome::Success {
            customer: ctx.customer.clone(),
            auth: AuthenticationContextPayload {
                credential_type: Some("bearer_token".into()),
                access_token: Some("dev".into()),
                credential: None,
                refresh_token: None,
                expires_in: Some(900),
                customer_id: ctx.customer.get("id").and_then(|v| v.as_str()).map(str::to_string),
            },
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let secret = std::env::var("QEFRO_SIGNING_SECRET").unwrap_or_else(|_| "dev-secret".into());
    let mut app = Qefro::new(QefroConfig::new(secret));
    app.customer(DemoCustomer);

    app.tool(
        ToolMetadata {
            name: "get_orders".into(),
            description: Some("List orders for the authenticated customer".into()),
            auth: ToolAuthMode::Required,
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

    let handle = app
        .listen(ListenOptions {
            port: 8088,
            host: Some("0.0.0.0".into()),
            path: Some("/qefro".into()),
        })
        .await?;
    println!("Qefro Rust example ready at {}", handle.url);
    println!("Wire this URL into Admin Console → SDK Connections, then Sync Tools.");
    // listen() currently returns the URL; wire your HTTP server to app.handle(...)
    Ok(())
}
