# qefro-backend-sdk

Qefro backend framework for Business Tool handlers and customer authorization (Rust).

Organizations expose one signed webhook (typically `POST /qefro`). Qefro Runtime calls `ping`, `capabilities.list`, `tool.invoke`, and `tool.resume`. Authentication stays in your handlers — Qefro only relays challenges.

Companion TypeScript package: [`@qefro-ai/backend`](https://www.npmjs.com/package/@qefro-ai/backend) (feature-parity target).

## Install

```toml
[dependencies]
qefro-backend-sdk = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "signal"] }
```

```bash
cargo add qefro-backend-sdk
```

## Quick start

```rust
use qefro_backend_sdk::{ListenOptions, Qefro, QefroConfig, ToolAuthMode, ToolLookup, ToolMetadata};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = Qefro::new(QefroConfig::new(std::env::var("QEFRO_SIGNING_SECRET")?));

    app.tool(
        ToolMetadata {
            name: "order_status_check".into(),
            description: Some("Look up order status by ID".into()),
            auth: ToolAuthMode::None,
            lookup: Some(ToolLookup {
                by: Some("email".into()),
                required: vec![],
            }),
            input_schema: Some(json!({
                "type": "object",
                "properties": { "order_id": { "type": "string" } },
                "required": ["order_id"]
            })),
            ..Default::default()
        },
        |ctx| async move {
            Ok(json!({
                "order_id": ctx.parameters.get("order_id"),
                "status": "shipped"
            }))
        },
    );

    let handle = app.listen(ListenOptions { port: 8088, host: None, path: None }).await?;
    println!("listening on {}", handle.url);
    tokio::signal::ctrl_c().await?;
    handle.close().await;
    Ok(())
}
```

Set the same signing secret in Admin Console → **Business Tools → SDK Connections**, then **Sync Tools**.

## Customer Hub (optional)

When `QEFRO_CUSTOMER_HUB_ENABLED=true`, tools can call Hub via
`platform.customer` on `tool.invoke` (or `QEFRO_CUSTOMER_HUB_URL` + service
token). Hub is **optional** — defaults keep existing apps working
(`ENABLED=false`, `OPTIONAL=true`). Soft-skip returns `None` / no-ops when
Hub is off or unreachable; set `QEFRO_CUSTOMER_HUB_OPTIONAL=false` to hard-fail.

```rust
app.tool(
    ToolMetadata {
        name: "create_reservation".into(),
        auth: ToolAuthMode::None,
        ..Default::default()
    },
    |ctx| async move {
        let api = ctx.customer_api().unwrap();
        let customer = api
            .resolve(Some(json!({ "whatsapp_number": ctx.identity.get("phone") })))
            .await?;
        // Convenience: api.id() / phone_number() / whatsapp_number() / display_name()
        ctx.timeline
            .append(json!({
                "event_type": "reservation.created",
                "payload": { "code": "R-1001" },
            }))
            .await?;
        ctx.membership
            .attach(Some(json!({ "solution_id": "restaurant-pro" })))
            .await?;
        ctx.consent
            .grant(json!({ "purpose": "marketing" }))
            .await?;
        Ok(json!({ "customer_id": customer.and_then(|c| c.get("id").cloned()) }))
    },
);
```

Storage bindings (when present in your stack) remain independent — Hub is never
the sole path. External CRM auth via `app.customer(provider)` is unchanged.

## Business Flows

Flows describe how your Business Tools are orchestrated. They are **metadata only** — the SDK advertises them through `capabilities.list` and the Qefro Runtime discovers, validates, versions, and executes them. Nothing runs inside the SDK. A flow with a duplicate/empty id (flow or step) is excluded from `capabilities.list` and surfaced through `FlowError` instead of panicking.

```rust
use qefro_backend_sdk::BusinessFlowMetadata;

app.flow(BusinessFlowMetadata {
    id: "order_lookup".into(),        // immutable identity — renaming `name` never creates a new flow
    name: Some("Order Lookup".into()),
    description: Some("Lookup customer orders".into()),
    category: Some("crm".into()),
    tags: vec!["customer".into(), "orders".into()],
    intent: vec!["track order".into(), "where is my order".into()],
    inputs: vec!["email".into()],
    outputs: vec!["customer".into(), "orders".into()],
    ..Default::default()
})?
.ask("email", "email", "Please enter your email.")
.tool("lookup", "lookup_customer")
.tool("orders", "get_orders")
.complete("done", Some("Here are your recent orders.".into()))?;
```

Every step needs a unique `id`; `tool` steps reference an existing Business Tool by `tool_ref`. Step builders: `.ask() .tool() .challenge() .upload() .condition() .delay() .approval() .complete_step() .complete()` — `complete_step()` adds a branch terminal mid-chain (e.g. a `condition` else-target), `complete()` finishes the flow and surfaces any `FlowError`. See [`examples/basic`](examples/basic) and [`examples/order-approval`](examples/order-approval) (condition + approval + OTP-authenticated tool).

## Docs

- [Register SDK Business Tools](https://docs.qefro.com/docs/guides/register-sdk-business-tools)
- [Define Business Flows](https://docs.qefro.com/docs/guides/define-business-flows)
- [Run Business Flows](https://docs.qefro.com/docs/guides/run-business-flows)
- [docs.rs/qefro-backend-sdk](https://docs.rs/qefro-backend-sdk)

## Protocol

| Message | Purpose |
| --- | --- |
| `ping` | Health / Test Connection |
| `capabilities.list` | Discover tools **and** business flows for Sync Tools (includes `lookup`) |
| `tools.list` | Legacy tool-only discovery (still supported) |
| `tool.invoke` | Run a handler |
| `tool.resume` | Continue after a customer challenge reply |

Requests are HMAC-SHA256 signed (`X-Qefro-Signature` / `X-Qefro-Timestamp`). Responses include `X-Qefro-Protocol`, `X-Qefro-SDK`, and `X-Qefro-Version`.

## Build

```bash
cargo build
cargo test
cargo run --example basic
cargo run --example order-approval
```

## Publishing (maintainers)

CI publishes to crates.io via [`.github/workflows/publish-crates.yml`](.github/workflows/publish-crates.yml).

1. Create a crates.io **API token** at https://crates.io/settings/tokens (scopes: publish-new / publish-update).
2. In GitHub → **Settings → Secrets and variables → Actions**, add secret **`CARGO_REGISTRY_TOKEN`** with that token value.
3. Publish either:
   - **Actions → Publish crates → Run workflow**, or
   - Create a GitHub Release (triggers publish automatically).

Bump `version` in `Cargo.toml` before publishing a new release.

## License

MIT
