# vta-push-gateway

The **push wake-up gateway** for the OpenVTC mobile authenticator. It implements
the [push wake-up binding](https://trusttasks.org/binding/push/0.1) — the third
role in the wake-up model (gateway / trigger / device):

- Holds the **app's platform push credentials** (APNs auth key, FCM service
  account, Web Push VAPID key) — the only party that can deliver a push to the
  app. Operated by the app publisher (the [Matrix Sygnal](https://github.com/matrix-org/sygnal)
  role).
- Issues an **opaque `WakeHandle`** for a registered device token. The raw token
  never leaves the gateway.
- Enforces a **VTA-provisioned trigger allowlist** per handle.
- Relays a strictly **contentless** wake — never any Trust Task content.

A wake is a doorbell: the device, once woken, connects to its mediator and
drains the real (DIDComm-encrypted) messages. See the binding spec for the full
model and the rationale (why the gateway, not the mediator, holds the keys; why
the VTA owns the allowlist).

## Status

**Scaffold (Phase 1 / B1).** REST surface + in-memory stores + did-signed auth +
a dev **echo sender** (logs the wake, delivers nothing). This is enough to
exercise register → provision → wake → push end-to-end with no Apple/Google
account. Not production-ready.

Roadmap: Web Push (VAPID) sender · APNs · FCM · persistent store · DIDComm
transport · metrics.

## API

| Method | Path            | Caller          | Auth                | Purpose |
|--------|-----------------|-----------------|---------------------|---------|
| POST   | `/v1/register`  | device          | none                | register a push token → opaque `WakeHandle` |
| POST   | `/v1/provision` | controller VTA  | did-signed          | set a handle's trigger allowlist |
| POST   | `/v1/wake`      | trigger (mediator/VTA) | did-signed   | request a contentless wake (allowlist-gated) |
| GET    | `/healthz`      | —               | none                | liveness |

### Authentication (`provision`, `wake`)

The caller signs the **raw request body bytes** with its `did:key` Ed25519 key
and sends:

- `X-TT-Did: did:key:z…` — the caller's did:key (Ed25519).
- `X-TT-Signature: <base64url>` — Ed25519 signature over the exact body bytes.

The gateway resolves the did:key offline (multicodec/base58btc — no network) and
verifies. `register` is unauthenticated: a handle is opaque and useless until the
device's VTA opts a trigger in via `provision`. Replay is harmless by design
(a duplicate wake is an idempotent doorbell; a re-sent provision sets the same
allowlist), so no nonce is required — see binding §6.

### Examples

```jsonc
// POST /v1/register
{ "registration": { "platform": "apns", "token": "…", "topic": "org.openvtc.vta-mobile-agent" },
  "controllerVtaDid": "did:web:vta.example" }
// → 201 { "wake_handle": { "gateway": "https://gw.example", "handle": "z6Mk…opaque" } }

// POST /v1/provision   (signed by did:web:vta.example)
{ "handle": "z6Mk…opaque", "policy": { "allowed_triggers": ["did:web:mediator", "did:web:vta.example"] } }
// → 204

// POST /v1/wake        (signed by an allowed trigger DID)
{ "handle": "z6Mk…opaque", "v": 1, "mediator": "did:web:mediator", "urgency": "interactive" }
// → 202   (echo sender logs the contentless wake)
```

## Run

```sh
cargo run
# GATEWAY_BIND=127.0.0.1:8300   bind address
# GATEWAY_ADDR=https://gw.example   address advertised in issued handles (behind TLS/proxy)
# RUST_LOG=vta_push_gateway=debug
```

## Security notes

- The platform push token is held by the gateway alone, behind the opaque handle
  — triggers and the VTA hold only the handle.
- The push payload is contentless (binding §2): no Trust Task, no `reason`, no
  relying-party identity. The dev echo sender enforces this by construction (it
  only ever sees a `WakePayload`).
- Possession of a handle is not authority to wake — the VTA-provisioned allowlist
  is the control, enforced on every `wake`.
