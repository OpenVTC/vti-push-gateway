# vti-push-gateway

The **push wake-up gateway** for the OpenVTC mobile authenticator. It implements
the [push wake-up binding](https://trusttasks.org/binding/push/0.1) — the third
role in the wake-up model (gateway / trigger / device):

- Holds the **app's platform push credentials** (APNs auth key, FCM service
  account, Web Push VAPID key) — the only party that can deliver a push to the
  app. Operated by the app publisher (the [Matrix Sygnal](https://github.com/matrix-org/sygnal)
  role).
- Issues an **opaque `WakeHandle`** for a registered device token. Triggers and
  the VTA only ever see the handle — the raw platform token is never returned to
  them; it is sent only to the platform push service (and, when persistence is
  enabled, written to the gateway's own store file — see the Security notes).
- Enforces a **VTA-provisioned trigger allowlist** per handle.
- Relays a strictly **contentless** wake — never any Trust Task content.

A wake is a doorbell: the device, once woken, connects to its mediator and
drains the real (DIDComm-encrypted) messages. See the binding spec for the full
model and the rationale (why the gateway, not the mediator, holds the keys; why
the VTA owns the allowlist).

## Status

The gateway's control plane is the **`push/*` Trust Task family**
([`push/register`](https://trusttasks.org/spec/push/register/0.2),
[`push/provision`](https://trusttasks.org/spec/push/provision/0.2),
[`push/wake`](https://trusttasks.org/spec/push/wake/0.2)). It dispatches
`TrustTask` documents (canonical `trust-tasks-rs` envelope), so the same
documents ride the **DIDComm binding (preferred) or HTTPS (fallback)**.

Implemented: both transports (HTTPS + DIDComm) + in-memory stores + four
senders — a real **Web Push (VAPID)** sender (`GATEWAY_VAPID_KEY_FILE`,
self-hostable, no Apple/Google account), a real **APNs** sender
(`GATEWAY_APNS_KEY_FILE` + key id + team id; provider-token JWT API, contentless
background push), a real **FCM** sender (`GATEWAY_FCM_SERVICE_ACCOUNT_FILE`;
FCM HTTP v1, OAuth2 access token from an RS256 service-account assertion signed
with `aws-lc-rs` — no `rsa` crate; data-only high-priority wake), and a dev
**echo sender** (logs, delivers nothing) behind `GATEWAY_DEV_ECHO_SENDER=1`.
The echo sender is opt-in rather than a fallback: it accepts *every* platform,
so whenever it is registered a wake for a platform with no credentials reports
`delivered` without sending anything. With it off, such a `push/register` is
refused outright. The handle registry is in-memory by default, or **durable**
via a JSON snapshot when `GATEWAY_STORE_FILE` is set (handles/tokens survive a
restart).

**DIDComm transport (preferred)** is wired: when `GATEWAY_IDENTITY_FILE`
provides the gateway's provisioned `did:webvh` identity, a `DIDCommService`
(`affinidi-messaging-didcomm-service`) connects to the mediator and dispatches
inbound `push/*` to the same core — the crate does the unpack, and the gateway
authenticates `push/provision` / `push/wake` by the Data Integrity proof on the
Trust Task document (see "Authentication" below).
Identity is provisioned like any integration: `pnm bootstrap
provision-integration --template push-gateway --var URL=<gateway-didcomm-url>`,
then open the bundle into the identity file.

**Metrics** are exposed at `GET /metrics` in Prometheus text-exposition format
(`gateway_register_total`, `gateway_provision_total{outcome}`,
`gateway_wake_total{outcome}`) — counted in the transport-agnostic dispatch core,
so both HTTPS and DIDComm wakes are covered. They are served on a **separate
management listener**, `GATEWAY_METRICS_BIND` (default `127.0.0.1:9300`), and not
on the public router: the counters describe a push fleet's volumes and failure
modes, and a reverse proxy that forwards `location /` wholesale would otherwise
publish them. Set `GATEWAY_METRICS_TOKEN` to require a bearer token when the
management port has to be reachable off-host.

The **DID resolver** on the DIDComm path is tunable for `did:webvh` (whose
resolution fetches a verifiable log over HTTPS — slower than `did:key`/`did:web`,
yet rarely changing). Defaults raise the SDK's stock 300 s TTL / 5 s timeout to
a 250-entry cache, **900 s** TTL, **10 s** timeout; override via the
`GATEWAY_DID_*` env vars below, or point at a remote resolver service.

Roadmap: the gateway is feature-complete (transports · senders · durable
registry · metrics · resolver tuning).

## API

A single Trust-Task endpoint dispatches by the document's `type`:

| Method | Path            | `type`                | Caller | Auth (HTTPS) |
|--------|-----------------|-----------------------|--------|--------------|
| POST   | `/trust-tasks`  | `push/register/0.2`   | device | none |
| POST   | `/trust-tasks`  | `push/provision/0.2`  | controller VTA | did-signed |
| POST   | `/trust-tasks`  | `push/wake/0.2`       | trigger (mediator/VTA) | did-signed |
| GET    | `/healthz`      | —                     | — | none |

On the **management** listener (`GATEWAY_METRICS_BIND`, default
`127.0.0.1:9300`) — never on the public one:

| Method | Path            | `type`                | Caller | Auth |
|--------|-----------------|-----------------------|--------|------|
| GET    | `/metrics`      | —                     | scraper | optional bearer (`GATEWAY_METRICS_TOKEN`) |
| GET    | `/healthz`      | —                     | — | none |

Success returns a `…#response` Trust Task document; failure returns a
`trust-task-error/0.1` document (the envelope carries the outcome).

### Authentication (`provision`, `wake`)

Over **HTTPS** the caller signs the **raw request body bytes** (the Trust Task
document) with its `did:key` Ed25519 key:

- `X-TT-Did: did:key:z…` — the caller's did:key (Ed25519).
- `X-TT-Signature: <base64url>` — Ed25519 signature over the exact body bytes.

The gateway resolves the did:key offline (multicodec/base58btc — no network) and
verifies. `register` is unauthenticated (the handle is opaque and useless until
the device's VTA provisions a trigger). Replay is harmless by design (a
duplicate wake is an idempotent doorbell), so no nonce is required — see
binding §6.

Over the **DIDComm** transport the caller signs the Trust Task document itself
with its **operational** key: an `eddsa-jcs-2022` Data Integrity proof with
`proofPurpose: authentication` (VTI-KEY-106 — these are the caller's own
messages, not attestations, so an `assertionMethod` proof is refused). The
caller is the document's `issuer`, and only when:

- the DID of `proof.verificationMethod` is the `issuer`;
- the issuer's DID document lists that method, with `controller` equal to the
  issuer, under `authentication`;
- the signature verifies over the document without its `proof`.

An `authentication` proof carries no challenge, so the document binds it to one
delivery (VTI-KEY-107): it must name this gateway as `recipient`, carry an
`issuedAt` no more than 5 minutes old and no more than 60 s in the future
(VTI-OPS-024; `expired` / `malformedRequest` otherwise) and not be past its
`expiresAt`, and carry an `id` the same issuer has not already had accepted
within that window (VTI-OPS-026). The record is keyed by (issuer, id), bounded
per issuer, and claimed only after the caller has been rate-limited and
authorised for the handle, so a refused caller leaves nothing in it. A second
delivery of an accepted document is answered with the first response and not
executed again; a different document under the same issuer's accepted `id`
gets `idConflict`; a transient push failure is not remembered, so a retry is
attempted. A provision that re-applies the stored allowlist changes nothing and
spends no record. The record is in memory and per process.

**Which controllers are served.** `push/register` is anonymous and names its
`controllerVtaDid`, so without a list anyone could make a DID they hold the
controller of a handle and send it correctly signed provisions — a proof from
the controller at registration would not stop that, since the attacker *is*
that controller. So the operator **lists the VTAs the gateway serves** in
`GATEWAY_ALLOWED_CONTROLLERS`: a registration naming any other controller is
refused (`permissionDenied`), and so is a provision by a controller no longer on
the list. Unset means nothing is served. `*` is an explicit open mode for
deliberate use; it logs a startup warning and keeps every bound below.

**Who can spend the record.** Within the served controllers:

- a handle's controller spends record only by a signed, authorised provision
  that changes the allowlist; an unprovisioned handle holds nothing and is
  swept after `GATEWAY_UNPROVISIONED_TTL_SECS` (default 1 h);
- one controller DID holds at most `GATEWAY_MAX_HANDLES_PER_CONTROLLER` handles
  (default 4096);
- the record has three budgets — per issuer (8192), per handle (512, shared by
  the controller and every trigger acting on it), and overall. At the overall
  soft bound (65536) an issuer is admitted only while it holds less than its
  fair share (soft bound ÷ issuers holding records), so a set of invented
  controllers cannot lock out an issuer that is not flooding; a hard bound of
  twice the soft bound caps memory. A refusal is `taskFailed`, retryable later.

Registration itself stays anonymous and is rate-limited globally (and per peer
IP over HTTPS); the DIDComm path has no trustworthy anonymous source to key a
per-source budget on.

`push/provision` then requires that issuer to be the handle's
`controllerVtaDid`; `push/wake` requires it to be on the allowlist. The DIDComm
envelope sender is never an authorising identity on its own: a document without
a proof is anonymous (`push/register` only; provision/wake get `proofRequired`),
an envelope sender that differs from the proven issuer gets `identityMismatch`,
and a document whose `recipient` is not this gateway gets `wrongRecipient`.

### Example (HTTPS)

```jsonc
// POST /trust-tasks   — push/register (unauthenticated)
{ "id": "urn:uuid:1", "type": "https://trusttasks.org/spec/push/register/0.2",
  "payload": { "registration": { "platform": "apns", "token": "…", "topic": "org.openvtc.vta-mobile-agent" },
               "controllerVtaDid": "did:webvh:…:vta" } }
// → 200  …#response  { "payload": { "wakeHandle": { "gateway": "https://gw.example", "handle": "z6Mk…" } } }

// POST /trust-tasks   — push/provision (signed by the controller VTA)
{ "id": "urn:uuid:2", "type": "https://trusttasks.org/spec/push/provision/0.2",
  "payload": { "handle": "z6Mk…", "policy": { "allowedTriggers": ["did:webvh:…:mediator", "did:webvh:…:vta"] } } }

// POST /trust-tasks   — push/wake (signed by an allowed trigger)
{ "id": "urn:uuid:3", "type": "https://trusttasks.org/spec/push/wake/0.2",
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
# GATEWAY_STORE_FILE=./gateway-store.json   persist the handle registry to this
#                       JSON snapshot (survives restart). Omit = in-memory.
#                       Written owner-only (0600); it holds raw push tokens.
# GATEWAY_STRICT_KEY_PERMS=1   refuse to start when a secret file (identity,
#                       VAPID key, APNs .p8, FCM service account) is readable
#                       beyond its owner. Unset = warn only.
# GATEWAY_DEV_ECHO_SENDER=1   register the dev echo sender (logs, delivers
#                       nothing). Opt-in: it accepts EVERY platform, so it makes
#                       wakes for unconfigured platforms report `delivered`
#                       without sending. Use it for a credential-free dev
#                       gateway; never in production.
# Management listener (metrics), separate from the public bind:
# GATEWAY_METRICS_BIND=127.0.0.1:9300   where GET /metrics is served. Keep it on
#                       loopback; a non-loopback value with no token logs a
#                       warning at startup.
# GATEWAY_METRICS_TOKEN=<secret>   require `Authorization: Bearer <secret>` on
#                       the management listener. Unset = no auth (fine on
#                       loopback).
# GATEWAY_ALLOWED_CONTROLLERS="did:webvh:…:vta-a did:webvh:…:vta-b"
#                       REQUIRED in practice: the controller VTA DIDs this
#                       gateway serves (comma/space separated, exact match, no
#                       patterns). Unset/empty = every push/register is refused
#                       (logged at startup). `*` alone = open mode (any
#                       controller; startup warning; all other limits apply).
#                       A malformed list stops startup.
# Registry bounds (push/register is anonymous, so these cap what an
# unauthenticated caller can make the gateway hold; all optional):
# GATEWAY_MAX_HANDLES_PER_CONTROLLER=4096   live handles naming one
#                       controller VTA DID.
# GATEWAY_UNPROVISIONED_TTL_SECS=3600   drop a handle whose VTA never
#                       provisioned a trigger after this long. A provisioned
#                       handle is never swept. This is the main bound on
#                       anonymous growth; the sweeper runs every 60s.
# GATEWAY_MAX_HANDLES=100000   total live handles before register is refused
#                       with "gateway at capacity".
# GATEWAY_MAX_HANDLES_PER_TOKEN=4   live handles sharing one device token /
#                       Web Push endpoint, so one device (or one stolen token)
#                       cannot occupy the registry.
# GATEWAY_SNAPSHOT_FLUSH_MS=1000   minimum gap between snapshot writes.
#                       Mutations set a dirty flag; a background flusher writes
#                       at most this often instead of reserialising the whole
#                       map per request.
# Rate limits (all optional; two layers, because DIDComm bypasses HTTP
# middleware — see the Security notes):
# GATEWAY_REGISTER_PER_SEC=5 / GATEWAY_REGISTER_BURST=20
#                       global budget for anonymous push/register.
# GATEWAY_PER_DID_PER_SEC=20 / GATEWAY_PER_DID_BURST=60
#                       budget per authenticated caller DID, for
#                       push/provision and push/wake.
# GATEWAY_HTTP_PER_SEC=10 / GATEWAY_HTTP_BURST=40
#                       per-peer-IP budget on POST /trust-tasks (429 when
#                       exceeded). HTTP transport only.
# Egress / endpoint policy (all optional):
# GATEWAY_WEBPUSH_ALLOWED_HOSTS=@default,push.example.org,*.up.example.net
#                       Web Push services a registration may target. Unset = the
#                       built-in browser push hosts (fcm.googleapis.com,
#                       updates.push.services.mozilla.com, web.push.apple.com,
#                       *.notify.windows.com). `@default` expands to them; add
#                       exact hosts or `*.suffix` wildcards for self-hosted push
#                       (autopush / UnifiedPush). Wildcards at a registrable
#                       domain (e.g. *.googleapis.com) are refused at startup.
# GATEWAY_APNS_TOPICS=org.openvtc.app,org.openvtc.app.voip
#                       APNs topics (bundle ids) registrations may name. Unset =
#                       not enforced (a startup warning is logged).
# DID resolver tuning (DIDComm path; all optional — defaults suit did:webvh):
# GATEWAY_DID_CACHE_CAPACITY=250        max cached DID docs
# GATEWAY_DID_CACHE_TTL_SECS=900        cache entry TTL (SDK default 300)
# GATEWAY_DID_NETWORK_TIMEOUT_MS=10000  per-resolution timeout (SDK default 5000)
# GATEWAY_DID_RESOLVER_URL=wss://…      resolve via a remote resolver service
#                       instead of locally (unset = local resolution)
# GATEWAY_DID_ALLOW_PRIVATE_HOSTS=1     let did:web/did:webvh resolution reach
#                       non-public hosts (loopback, RFC 1918, link-local).
#                       Default off: a DID names the host its document is
#                       fetched from, and inbound DIDComm senders choose the
#                       DIDs the gateway resolves. Needed only for a local
#                       stack whose VTA/mediator DIDs are
#                       did:webvh:{SCID}:localhost%3A3000 — without it those
#                       resolve as BlockedHost.
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
   GATEWAY_VAPID_KEY_FILE=./vapid.pem \
   GATEWAY_ALLOWED_CONTROLLERS="<your VTA's DID>" \
   RUST_LOG=vti_push_gateway=info cargo run
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
   delivery (no VTA, no hand-signing). Because it registers under a throwaway
   controller, the local gateway it targets must run in open mode
   (`GATEWAY_ALLOWED_CONTROLLERS=*`) — a dev-only setting:

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
- **Outbound egress is constrained.** A Web Push endpoint is validated at
  registration and again before every send: https only, default port, no
  userinfo, no IP-literal host, bounded length, and the host must be on the
  `GATEWAY_WEBPUSH_ALLOWED_HOSTS` allow-list. The push HTTP client follows no
  redirects, ignores system/environment proxies, is https-only, resolves names
  through a guard that refuses private / loopback / link-local (cloud-metadata)
  addresses, and has connect/total timeouts. APNs device tokens must be hex and
  are re-checked before being placed in the request path. This closes the
  register-driven SSRF and redirect/timeout exposure (SEC-4045 PG-1 / PG-5 /
  PG-N2).
- **Persisted tokens are cleartext, in an owner-only file.** When
  `GATEWAY_STORE_FILE` is set, the raw device tokens and Web Push subscriptions
  (`endpoint` + `p256dh` + `auth`) are written to that JSON snapshot in
  cleartext. Treat the file as a credential store, not a cache: those values are
  bearer secrets, and because `push/register` is anonymous, anyone who reads them
  can re-register those devices under a controller DID of their own and wake or
  track them. The gateway therefore writes the snapshot through a private
  temporary file (mode 0600, unpredictable name, `O_EXCL`, `fsync` before the
  rename) and tightens an existing snapshot to 0600 when it opens one that is
  group- or world-readable — with a warning, because anything already leaked
  stays leaked and those devices should be re-registered. Encryption at rest is
  tracked separately; it protects backups and detached volumes, not a host
  compromise.
- **Secret files are permission-checked on read.** The identity file, VAPID key,
  APNs `.p8` and FCM service-account JSON are read through one helper that warns
  when a file is group- or world-accessible, and refuses to read it when
  `GATEWAY_STRICT_KEY_PERMS=1` — so a mis-installed key fails the deployment
  instead of a log line nobody reads. `vapid-keygen` creates the key with
  `create_new` at mode 0600 in a single step, so there is no window in which the
  private key is world-readable and no path for a pre-planted symlink.
- `POST /trust-tasks` bodies are capped at 16 KiB, and each registration field
  is bounded. A handle's `allowedTriggers` list is capped at 32 entries, each of
  which must be a DID of at most 512 bytes; duplicates are collapsed. Rate
  limiting and per-handle caps are tracked separately.
- **The operation counters are not on the public listener.** `GET /metrics` is
  served only on `GATEWAY_METRICS_BIND` (loopback by default), optionally behind
  `GATEWAY_METRICS_TOKEN`, so a proxy forwarding `location /` cannot expose them.
- **The dev echo sender is opt-in** (`GATEWAY_DEV_ECHO_SENDER=1`). It handles
  every platform, so leaving it on in production would mean wakes for a platform
  with no configured credentials are reported `delivered` without a push ever
  being sent — a dropped wake that looks like a successful one.
- A `push/*` payload that fails to deserialise gets one fixed reason
  (`payload does not match the push/* 0.2 schema`); the serde detail goes to a
  debug log rather than back to the caller.
- **The anonymous registration path is bounded.** `push/register` needs no
  credentials, so it is rate-limited, capped, and expiring:
  - **Expiry is the root-cause fix.** A freshly registered handle is inert until
    its VTA provisions a trigger, so a handle still unprovisioned after
    `GATEWAY_UNPROVISIONED_TTL_SECS` (default 1 h) is swept. Anonymous growth
    becomes bounded churn instead of a monotonic leak. A provisioned handle is
    never swept, however old.
  - **Caps:** `GATEWAY_MAX_HANDLES` in total, and
    `GATEWAY_MAX_HANDLES_PER_TOKEN` live handles per device token / Web Push
    endpoint, so one token cannot occupy the registry, and
    `GATEWAY_MAX_HANDLES_PER_CONTROLLER` per named controller DID.
  - **Rate limits in two layers**, because the DIDComm transport — the preferred
    one — never passes through HTTP middleware. A `tower_governor` layer limits
    `POST /trust-tasks` per peer IP (429), and the transport-agnostic dispatch
    core limits `register` against a global budget and `provision`/`wake` against
    a budget keyed by the authenticated caller DID. The keyed buckets are
    themselves reclaimed on a timer, since they are keyed by caller-chosen input.
  - **Snapshot writes are debounced.** Mutations set a dirty flag and a
    background flusher writes at most once per `GATEWAY_SNAPSHOT_FLUSH_MS`,
    rather than reserialising the whole registry on every anonymous request.
    Writes keep the temp-file + fsync + rename sequence, and a clean shutdown
    flushes.
- A caller that exceeds a budget gets a `trust-task-error` with
  `rate limit exceeded; retry later`; one that hits a registry cap gets
  `gateway at capacity` or `too many handles for this push token`. Neither
  reveals anything about other tenants.
