# Order approval Rust SDK example

Runtime Business Flows end to end with `qefro-backend-sdk`: `ask`, `condition`
branching, human `approval`, and an OTP-authenticated `tool` step. Mirrors the
JS SDK's `examples/order-approval`.

```text
track-order:   ask -> tool -> condition -> complete
cancel-order:  ask -> tool -> condition -> approval (human) -> tool (auth: OTP) -> complete
```

The SDK never executes steps. Flows are advertised via `capabilities.list`,
the Qefro Runtime orchestrates them, and calls back into the two tools here
(`order_status_check`, `order_cancel`) over the same signed webhook.

## Run

```bash
export QEFRO_SIGNING_SECRET=dev-secret
cargo run --example order-approval   # listens on :8092/qefro
```

Then create an SDK Connection pointing at your public `/qefro` webhook (or
tunnel) with the same secret, Sync Tools, and enable + accept both flows.

## Try it

Ask the assistant "cancel my order":

1. It asks for an order ID — reply `ORD-1001`.
2. `order_status_check` runs; the `condition` step verifies the order exists.
3. The run pauses at `approval` — an Owner/Admin approves it in
   Portal → Business Tools → Flow Runs.
4. `order_cancel` requires auth, so the customer is challenged for an OTP —
   the demo code is `123456`.
5. The flow completes with the cancellation confirmation.

Seeded orders: `ORD-1001` (processing), `ORD-1002` (shipped), `ORD-1003`
(delivered — refuses cancellation).

## Docs

- [Define Business Flows](https://docs.qefro.com/docs/guides/define-business-flows)
- [Run Business Flows](https://docs.qefro.com/docs/guides/run-business-flows)
