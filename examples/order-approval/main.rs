//! End-to-end runtime Business Flows example: a cancellation flow the Qefro
//! Runtime executes, combining `ask`, `condition` branching, human `approval`,
//! and an OTP-authenticated `tool` step. Mirrors the JS SDK's
//! `examples/order-approval`.
//!
//! ```text
//! cancel-order:  ask -> tool -> condition -> approval (human) -> tool (auth: OTP) -> complete
//! track-order:   ask -> tool -> condition -> complete
//! ```
//!
//! The SDK still never executes steps: flows are advertised via
//! `capabilities.list`, and the Runtime calls back into the tools below over
//! the same signed webhook when a `tool` step runs.

use anyhow::Result;
use async_trait::async_trait;
use qefro_backend_sdk::{
    AuthBuilder, AuthenticationContextPayload, BusinessFlowMetadata, CustomerAuthorizeContext,
    CustomerLookupContext, CustomerProvider, ListenOptions, Qefro, QefroConfig, ToolAuthMode,
    ToolMetadata,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Demo OTP for exercising the challenge step end-to-end (never sent anywhere).
const DUMMY_OTP: &str = "123456";

#[derive(Clone)]
struct Order {
    status: &'static str,
    items: &'static [&'static str],
    total: f64,
    eta: Option<&'static str>,
}

fn seed_orders() -> HashMap<String, Order> {
    HashMap::from([
        (
            "ORD-1001".to_string(),
            Order { status: "processing", items: &["Wireless Mouse", "USB-C Hub"], total: 79.98, eta: Some("2026-08-05") },
        ),
        (
            "ORD-1002".to_string(),
            Order { status: "shipped", items: &["Standing Desk Mat"], total: 49.0, eta: Some("2026-08-01") },
        ),
        (
            "ORD-1003".to_string(),
            Order { status: "delivered", items: &["Laptop Sleeve"], total: 24.5, eta: None },
        ),
    ])
}

fn normalize_order_id(raw: Option<&Value>) -> String {
    raw.and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_uppercase()
        .split_whitespace()
        .collect()
}

/// Customer provider: the flow's authenticated cancel step triggers this OTP
/// challenge automatically — the Runtime pauses the flow run, relays the
/// prompt to the customer, and resumes the tool call with their answer.
struct DemoCustomer;

#[async_trait]
impl CustomerProvider for DemoCustomer {
    async fn lookup(&self, ctx: &CustomerLookupContext) -> Result<Option<Value>> {
        let id = ctx
            .identity
            .get("customer_id")
            .or_else(|| ctx.identity.get("user_id"))
            .or_else(|| ctx.identity.get("phone"))
            .cloned()
            .unwrap_or_else(|| json!("cust-demo"));
        Ok(Some(json!({ "id": id })))
    }

    async fn authorize(&self, ctx: &CustomerAuthorizeContext) -> Result<qefro_backend_sdk::AuthOutcome> {
        let auth = AuthBuilder::new(ctx.response.clone());
        match ctx.response.as_deref().map(str::trim) {
            None => Ok(auth.sms_otp(
                "+00 0000 000000",
                Some(&format!(
                    "To verify it's you, please enter the one-time code we sent to your phone. (Demo: the code is {DUMMY_OTP}.)"
                )),
            )),
            Some(code) if code != DUMMY_OTP => Ok(auth.sms_otp(
                "+00 0000 000000",
                Some(&format!(
                    "That code is incorrect. Please try again. (Demo: the code is {DUMMY_OTP}.)"
                )),
            )),
            Some(_) => {
                let customer = ctx.customer.clone();
                let token = format!(
                    "demo-{}",
                    customer.get("id").and_then(Value::as_str).unwrap_or("cust")
                );
                Ok(auth.success(
                    customer,
                    AuthenticationContextPayload {
                        credential_type: Some("bearer_token".into()),
                        access_token: Some(token),
                        credential: None,
                        refresh_token: None,
                        expires_in: Some(900),
                        customer_id: None,
                    },
                ))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let secret = std::env::var("QEFRO_SIGNING_SECRET").unwrap_or_else(|_| "dev-secret".into());
    let app = Qefro::new(QefroConfig::new(secret));
    app.customer(DemoCustomer);

    let orders = Arc::new(Mutex::new(seed_orders()));

    let status_orders = orders.clone();
    app.tool(
        ToolMetadata {
            name: "order_status_check".into(),
            description: Some("Look up the status of an order by order ID.".into()),
            auth: ToolAuthMode::None,
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "order_id": { "type": "string", "description": "Order ID such as ORD-1001" }
                },
                "required": ["order_id"]
            })),
            ..Default::default()
        },
        move |ctx| {
            let orders = status_orders.clone();
            async move {
                let order_id = normalize_order_id(ctx.parameters.get("order_id"));
                let orders = orders.lock().expect("orders");
                match orders.get(&order_id) {
                    None => Ok(json!({
                        "found": false,
                        "order_id": order_id,
                        "message": format!("No order found for {order_id}."),
                        "sample_ids": orders.keys().collect::<Vec<_>>(),
                    })),
                    Some(order) => Ok(json!({
                        "found": true,
                        "order_id": order_id,
                        "status": order.status,
                        "items": order.items,
                        "total": order.total,
                        "eta": order.eta,
                        "message": format!("Order {order_id} is {}.", order.status),
                    })),
                }
            }
        },
    );

    let cancel_orders = orders.clone();
    app.tool(
        ToolMetadata {
            name: "order_cancel".into(),
            description: Some("Cancel an order by order ID. Requires customer verification.".into()),
            auth: ToolAuthMode::Required,
            input_schema: Some(json!({
                "type": "object",
                "properties": {
                    "order_id": { "type": "string", "description": "Order ID to cancel" }
                },
                "required": ["order_id"]
            })),
            ..Default::default()
        },
        move |ctx| {
            let orders = cancel_orders.clone();
            async move {
                let order_id = normalize_order_id(ctx.parameters.get("order_id"));
                let mut orders = orders.lock().expect("orders");
                match orders.get_mut(&order_id) {
                    None => Ok(json!({
                        "cancelled": false,
                        "order_id": order_id,
                        "message": format!("No order found for {order_id}."),
                    })),
                    Some(order) if order.status == "delivered" || order.status == "cancelled" => {
                        Ok(json!({
                            "cancelled": false,
                            "order_id": order_id,
                            "message": format!(
                                "Order {order_id} is {} and can no longer be cancelled.",
                                order.status
                            ),
                        }))
                    }
                    Some(order) => {
                        order.status = "cancelled";
                        order.eta = None;
                        Ok(json!({
                            "cancelled": true,
                            "order_id": order_id,
                            "message": format!(
                                "Order {order_id} has been cancelled. Any payment will be refunded in 3-5 business days."
                            ),
                        }))
                    }
                }
            }
        },
    );

    // -----------------------------------------------------------------------
    // Business Flows. Still metadata only from the SDK's point of view — the
    // Qefro Runtime executes the steps.
    // -----------------------------------------------------------------------

    app.flow(BusinessFlowMetadata {
        id: "track-order".into(),
        name: Some("Track an order".into()),
        description: Some("Collect an order ID, look it up, and report its status.".into()),
        category: Some("orders".into()),
        tags: vec!["orders".into(), "tracking".into()],
        intent: vec![
            "track my order".into(),
            "where is my order".into(),
            "what is the status of my order".into(),
        ],
        outputs: vec!["order_status_check".into()],
        ..Default::default()
    })?
    .ask(
        "collect_order_id",
        "order_id",
        "Which order would you like to track? Please share your order ID (for example ORD-1001).",
    )
    .tool("lookup_order", "order_status_check")
    .condition(
        "check_found",
        "order_status_check.found == true",
        Some("report_status".into()),
        Some("report_missing".into()),
    )
    .complete_step(
        "report_missing",
        Some("I couldn't find an order with ID {{order_id}}. Please double-check the ID and try again.".into()),
    )
    .complete(
        "report_status",
        Some("Order {{order_id}} is currently {{order_status_check.status}}. {{order_status_check.message}}".into()),
    )?;

    // cancel-order exercises the full runtime feature set:
    //   ask -> tool -> condition -> approval (human) -> tool with auth (OTP) -> complete
    app.flow(BusinessFlowMetadata {
        id: "cancel-order".into(),
        name: Some("Cancel an order".into()),
        description: Some(
            "Collect an order ID, verify it exists, get supervisor approval, verify the customer, then cancel the order."
                .into(),
        ),
        category: Some("orders".into()),
        tags: vec!["orders".into(), "cancellation".into()],
        intent: vec![
            "cancel my order".into(),
            "i want to cancel an order".into(),
            "stop my order from shipping".into(),
        ],
        outputs: vec!["order_cancel".into()],
        ..Default::default()
    })?
    .ask(
        "collect_order_id",
        "order_id",
        "Which order do you want to cancel? Please share your order ID (for example ORD-1001).",
    )
    .tool("lookup_order", "order_status_check")
    .condition(
        "check_found",
        "order_status_check.found == true",
        Some("await_approval".into()),
        Some("report_missing".into()),
    )
    .complete_step(
        "report_missing",
        Some("I couldn't find an order with ID {{order_id}}, so there is nothing to cancel.".into()),
    )
    .approval(
        "await_approval",
        Some(
            "Your cancellation request for order {{order_id}} has been sent to a supervisor for approval. I will confirm as soon as it is approved."
                .into(),
        ),
    )
    .tool("do_cancel", "order_cancel")
    .complete("confirm_cancelled", Some("{{order_cancel.message}}".into()))?;

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8092);
    let handle = app
        .listen(ListenOptions {
            port,
            host: Some("0.0.0.0".into()),
            path: Some("/qefro".into()),
        })
        .await?;

    println!("order-approval example listening at {}", handle.url);
    println!("  Demo OTP: {DUMMY_OTP}");
    println!();
    println!("Flows advertised via capabilities.list:");
    println!("  track-order   ask -> tool -> condition -> complete");
    println!("  cancel-order  ask -> tool -> condition -> approval -> tool(auth) -> complete");

    tokio::signal::ctrl_c().await?;
    handle.close().await;
    Ok(())
}
