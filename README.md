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

Implemented: both transports (HTTPS + DIDComm) + in-memory stores + four
senders — a real **Web Push (VAPID)** sender (`GATEWAY_VAPID_KEY_FILE`,
self-hostable, no Apple/Google account), a real **APNs** sender
(`GATEWAY_APNS_KEY_FILE` + key id + team id; provider-token JWT API, contentless
background push), a real **FCM** sender (`GATEWAY_FCM_SERVICE_ACCOUNT_FILE`;
FCM HTTP v1, OAuth2 access token from an RS256 service-account assertion signed
with `aws-lc-rs` — no `rsa` crate; data-only high-priority wake), and a dev
**echo sender** (logs, delivers nothing) as the fallback. Not yet
production-hardened (in-memory state).

**DIDComm transport (preferred)** is wired: when `GATEWAY_IDENTITY_FILE`
provides the gateway's provisioned `did:webvh` identity, a `DIDCommService`
(`affinidi-messaging-didcomm-service`) connects to the mediator and dispatches
inbound `push/*` to the same core — the crate does the unpack + sender-auth.
Identity is provisioned like any integration: `pnm bootstrap
provision-integration --template push-gateway --var URL=<gateway-didcomm-url>`,
then open the bundle into the identity file.

Roadmap: persistent store · metrics · networked-resolver tuning for
`did:webvh` senders.

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
# GATEWAY_BIND=127.0.0.1:8300   bind address (HTTPS transport)
# GATEWAY_ADDR=https://gw.example   handle gateway field when HTTPS-only (no identity)
# GATEWAY_IDENTITY_FILE=./gateway-identity.json   provisioned did:webvh identity →
#                       enables the DIDComm transport; handles advertise the DID
# GATEWAY_VAPID_KEY_FILE=./vapid.pem   VAPID private key (PEM) → enables the
#                       Web Push sender. Generate with: cargo run -- vapid-keygen
# GATEWAY_VAPID_SUBJECT=mailto:ops@example.com   VAPID contact (sub claim)
# GATEWAY_APNS_KEY_FILE=./AuthKey.p8   APNs auth key (.p8, P-256 PKCS#8) →
#                       enables the APNs sender (requires the two ids below)
# GATEWAY_APNS_KEY_ID=ABC123DEFG    the auth key's Key ID (JWT `kid`)
# GATEWAY_APNS_TEAM_ID=DEF456GHIJ   the Apple Developer Team ID (JWT `iss`)
# GATEWAY_FCM_SERVICE_ACCOUNT_FILE=./service-account.json   Google service
#                       account (Firebase) → enables the FCM sender
# RUST_LOG=vti_push_gateway=debug
```

With `GATEWAY_IDENTITY_FILE` set the gateway connects to the mediator named in
the identity and serves `push/*` over DIDComm (preferred) as well as HTTPS;
without it, HTTPS-only. See `src/identity.rs` for the identity file shape.

## Testing Web Push end-to-end

The wake loop spans the gateway, a VTA + mediator, and the browser plugin. A
**local** gateway is enough — it only makes *outbound* calls to the push service.

1. **VAPID keypair** — let the gateway mint it (no openssl, no Apple/Google
   account). It writes the private key to `vapid.pem` (0600) and prints the
   public key the plugin needs:

   ```sh
   cargo run -- vapid-keygen            # → vapid.pem + the public key on stdout
   ```

2. **Run the gateway** with the key (it also re-logs the public key on startup,
   so you can recover it any time):

   ```sh
   GATEWAY_VAPID_KEY_FILE=./vapid.pem RUST_LOG=vti_push_gateway=info cargo run
   #  WARN … vapid_public="BOae…"  Web Push (VAPID) sender enabled — set this as
   #        the device/plugin applicationServerKey
   ```

   For the **DIDComm** transport (preferred) also provision a gateway identity
   and set `GATEWAY_IDENTITY_FILE` (see above). For an HTTPS-only smoke test,
   omit it and set `GATEWAY_ADDR=http://127.0.0.1:8300`.

3. **Configure the plugin** (extension → Settings):
   - *Push gateway VAPID public key* → the value from step 1/2. (This alone makes
     the service worker subscribe with the gateway's key.)
   - *Push gateway URL* → the gateway's address — needed for the full VTA path
     (step 5b); optional for the quick check (5a).

### 5a. Quick check — delivery + wake, no VTA

Prove a contentless push reaches the browser and wakes the service worker.

1. Open the extension's **service worker** console (`chrome://extensions` → VTA
   Wallet → *service worker*) and copy the logged subscription:

   ```
   [pnm push] subscription:
   {"endpoint":"https://…","keys":{"p256dh":"…","auth":"…"}}
   ```

   Save it to `sub.json`. (If you don't see it, reload the extension — the SW
   subscribes on spin-up once the VAPID key is set.)

2. Fire a real, did-signed wake at it with the bundled helper — it mints a
   throwaway `did:key`, registers the subscription, provisions itself onto the
   allowlist, and sends `push/wake`, so the gateway runs its normal auth +
   delivery (no VTA, no hand-signing):

   ```sh
   cargo run -- test-wake http://127.0.0.1:8300 ./sub.json
   #  1/3 registered → handle …
   #  2/3 provisioned → allowlist [self]
   #  3/3 wake → delivered
   ```

   The service-worker console then shows `[pnm push] push received: …` followed
   by the inbound drain (`startInboundListener`).

   **iOS (APNs)** is the same, with `test-wake-apns`. Run the gateway with the
   APNs credentials (`GATEWAY_APNS_KEY_FILE` / `_KEY_ID` / `_TEAM_ID`), copy the
   device's APNs token from the app (it's shown in the UI + logged), then:

   ```sh
   cargo run -- test-wake-apns http://127.0.0.1:8300 <apns-token-hex> org.openvtc.vta.agent
   ```

   **Android (FCM)** is the same, with `test-wake-fcm`. Run the gateway with
   `GATEWAY_FCM_SERVICE_ACCOUNT_FILE` set, copy the device's FCM registration
   token, then:

   ```sh
   cargo run -- test-wake-fcm http://127.0.0.1:8300 <fcm-registration-token>
   ```

   No VTA, no `did:webvh` gateway identity, no hand-signing — the helper plays a
   real did-signed trigger. The phone wakes, drains its mediator, and ratifies.
   (Uses the **sandbox** APNs host, matching a development build's token.)

### 5b. Full path — VTA-triggered

1. **Connect the plugin to your VTA.** On connect the service worker subscribes,
   `push/register`s with the gateway (logs the `WakeHandle`), and conveys it to
   the VTA via `device/set-wake` — the VTA provisions the gateway's allowlist.
   (Reload the extension after connecting if `set-wake` hasn't run yet — it fires
   on the next SW spin-up.)
2. **Trigger** anything that queues a DIDComm message for the wallet (e.g. a VTA
   step-up it delegates to this device). The VTA buffers the message to the
   mediator and asks the gateway to wake the device; the gateway delivers the
   contentless push and the wallet wakes + drains as in 5a.

The push is contentless by design — it only wakes the app; the real (encrypted)
Trust Task is pulled from the mediator.

## Security notes

- The platform push token is held by the gateway alone, behind the opaque handle
  — triggers and the VTA hold only the handle.
- The push payload is contentless (binding §2): no Trust Task, no `reason`, no
  relying-party identity. The dev echo sender enforces this by construction (it
  only ever sees a `WakePayload`).
- Possession of a handle is not authority to wake — the VTA-provisioned allowlist
  is the control, enforced on every `wake`.
