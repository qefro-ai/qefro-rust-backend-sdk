# qefro-backend-sdk

Qefro backend framework for Business Tool handlers and customer authorization (Rust).

Organizations expose one signed webhook (typically `POST /qefro`). Qefro Runtime calls `ping`, `tools.list`, `tool.invoke`, and `tool.resume`. Authentication stays in your handlers — Qefro only relays challenges.

Companion TypeScript package: [`@qefro-ai/backend`](https://www.npmjs.com/package/@qefro-ai/backend).

## Install

```toml
[dependencies]
qefro-backend-sdk = "1"
```

```bash
cargo add qefro-backend-sdk
```

## Docs

- [Register SDK Business Tools](https://docs.qefro.com/docs/guides/register-sdk-business-tools)
- [docs.rs/qefro-backend-sdk](https://docs.rs/qefro-backend-sdk)

## Build

```bash
cargo build
cargo test
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
