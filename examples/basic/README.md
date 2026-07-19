# Basic Rust SDK example

Minimal `qefro-backend-sdk` handler for Sync Tools / Test Connection.

## Install

From crates.io (recommended):

```toml
[dependencies]
qefro-backend-sdk = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
serde_json = "1"
anyhow = "1"
async-trait = "0.1"
```

This example uses a path dependency on the local crate for development.

## Run

```bash
export QEFRO_SIGNING_SECRET=dev-secret
cargo run
```

Then create an SDK Connection pointing at your public `/qefro` webhook (or tunnel) with the same secret.
