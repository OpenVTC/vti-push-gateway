# vti-push-gateway

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

The gateway's control plane is the **`push/*` Trust Task family**
([`push/register`](https://trusttasks.org/spec/push/register/0.1),
[`push/provision`](https://trusttasks.org/spec/push/provision/0.1),
[`push/wake`](https://trusttasks.org/spec/push/wake/0.1)). It dispatches
`TrustTask` documents (canonical `trust-tasks-rs` envelope), so the same
documents ride the **DIDComm binding (preferred) or HTTPS (fallback)**.

Implemented: the **HTTPS** transport + in-memory stores + a dev **echo sender**
(logs the wake, delivers nothing) — enough to exercise register → provision →
wake end-to-end with no Apple/Google account. Not production-ready.

Roadmap: **DIDComm transport** (the preferred path — gateway DID + unpack) ·
Web Push (VAPID) sender · APNs · FCM · persistent store · metrics.

## API

A single Trust-Task endpoint dispatches by the document's `type`:

| Method | Path            | `type`                | Caller | Auth (HTTPS) |
|--------|-----------------|-----------------------|--------|--------------|
| POST   | `/trust-tasks`  | `push/register/0.1`   | device | none |
| POST   | `/trust-tasks`  | `push/provision/0.1`  | controller VTA | did-signed |
| POST   | `/trust-tasks`  | `push/wake/0.1`       | trigger (mediator/VTA) | did-signed |
| GET    | `/healthz`      | —                     | — | none |

Success returns a `…#response` Trust Task document; failure returns a
`trust-task-error/0.1` document (the envelope carries the outcome).

### Authentication over HTTPS (`provision`, `wake`)

The caller signs the **raw request body bytes** (the Trust Task document) with
its `did:key` Ed25519 key:

- `X-TT-Did: did:key:z…` — the caller's did:key (Ed25519).
- `X-TT-Signature: <base64url>` — Ed25519 signature over the exact body bytes.

The gateway resolves the did:key offline (multicodec/base58btc — no network) and
verifies. `register` is unauthenticated (the handle is opaque and useless until
the device's VTA provisions a trigger). Over the **DIDComm** transport (next),
the authcrypt sender authenticates the caller intrinsically — no signature
header. Replay is harmless by design (a duplicate wake is an idempotent
doorbell), so no nonce is required — see binding §6.

### Example (HTTPS)

```jsonc
// POST /trust-tasks   — push/register (unauthenticated)
{ "id": "urn:uuid:1", "type": "https://trusttasks.org/spec/push/register/0.1",
  "payload": { "registration": { "platform": "apns", "token": "…", "topic": "org.openvtc.vta-mobile-agent" },
               "controllerVtaDid": "did:webvh:…:vta" } }
// → 200  …#response  { "payload": { "wakeHandle": { "gateway": "https://gw.example", "handle": "z6Mk…" } } }

// POST /trust-tasks   — push/provision (signed by the controller VTA)
{ "id": "urn:uuid:2", "type": "https://trusttasks.org/spec/push/provision/0.1",
  "payload": { "handle": "z6Mk…", "policy": { "allowedTriggers": ["did:webvh:…:mediator", "did:webvh:…:vta"] } } }

// POST /trust-tasks   — push/wake (signed by an allowed trigger)
{ "id": "urn:uuid:3", "type": "https://trusttasks.org/spec/push/wake/0.1",
  "payload": { "handle": "z6Mk…", "v": 1, "mediator": "did:webvh:…:mediator", "urgency": "interactive" } }
// → 200  …#response  { "payload": { "status": "delivered" } }  (echo sender logs the contentless wake)
```

## Run

```sh
cargo run
# GATEWAY_BIND=127.0.0.1:8300   bind address
# GATEWAY_ADDR=https://gw.example   address advertised in issued handles (behind TLS/proxy)
# RUST_LOG=vti_push_gateway=debug
```

## Security notes

- The platform push token is held by the gateway alone, behind the opaque handle
  — triggers and the VTA hold only the handle.
- The push payload is contentless (binding §2): no Trust Task, no `reason`, no
  relying-party identity. The dev echo sender enforces this by construction (it
  only ever sees a `WakePayload`).
- Possession of a handle is not authority to wake — the VTA-provisioned allowlist
  is the control, enforced on every `wake`.
