# Signal LAN local device authentication

This service is the local-only registration factor for the customized Signal Android + Signal Server deployment. It replaces SMS and voice verification with a pre-enrolled device proof:

1. An administrator creates a user by E.164 phone number in the Signal LAN dashboard.
2. The administrator enrolls the Android ID and the device's ECDSA P-256 public key. The private key is generated and retained by Android Keystore.
3. The app requests a short-lived challenge for the phone + Android ID.
4. The app signs the canonical challenge with the device private key. The sidecar checks the signature against the enrolled public key.
5. The sidecar returns a six-digit one-time code over HTTPS. The Android app transfers it directly into the registration screen; no SMS receiver or phone-call transport is used.
6. The app submits the code. The sidecar returns a short-lived, single-use registration ticket wrapped as Signal's `sessionId`.
7. Signal Server validates that ticket and redeems it once immediately before creating the Signal account. Signal's normal ACI/PNI, identity-key, pre-key, and account-creation code remains in place.

Android ID is only a lookup attribute. It is not treated as a secret or proof of possession. The ECDSA signature from the Android Keystore key is the device proof.

## Local-auth-only mode in Signal Server

Set the following environment variables on the Java Signal Server process:

- `LOCAL_AUTH_ONLY=true`
- `LOCAL_AUTH_INTERNAL_URL=https://local-auth.internal.example`
- `LOCAL_AUTH_INTERNAL_TOKEN=<same high-entropy secret as LOCAL_AUTH_INTERNAL_TOKEN in the sidecar>`

The Java server requires an HTTPS internal URL. Install the private CA certificate that signs this endpoint into the Java runtime trust store used by the Signal Server process (or provide a JVM trust store with `-Djavax.net.ssl.trustStore=...` and `-Djavax.net.ssl.trustStorePassword=...`). Do not disable hostname or certificate validation.

When local-auth-only mode is enabled:
- the Java server does not construct or manage the external registration-service client;
- the legacy `/v1/verification` controller is not registered at all;
- registration requests without a valid LAN ticket are rejected (including SMS/voice session IDs and recovery-password fallback);
- the LAN ticket is validated first and consumed exactly once, before Signal account creation.

When local-auth-only is disabled, the upstream Signal verification flow remains available. Do not use that mode for an isolated LAN deployment.

## Sidecar API

The Go sidecar uses PostgreSQL and exposes the following routes.

Public app endpoints:
- `POST /v1/local-auth/challenge` — body `{"phone":"+4915112345678","androidId":"..."}`
- `POST /v1/local-auth/verify` — body `{"challengeId":"...","signature":"<base64 ASN.1 ECDSA>"}`
- `POST /v1/local-auth/complete` — body `{"challengeId":"...","code":"123456"}`

The Android app signs this exact UTF-8 message:

```text
signal-local-auth-v1
{challengeId}
{phone}
{base64url(nonce)}
```

The sidecar replies with the six-digit code only after signature validation. The code is never sent by SMS.

Dashboard endpoints (all require `Authorization: Bearer <LOCAL_AUTH_ADMIN_TOKEN>`):
- `GET /v1/local-auth/admin/users`
- `POST /v1/local-auth/admin/users` body `{"phone":"+...","displayName":"..."}`
- `DELETE /v1/local-auth/admin/users/{phone}`
- `GET /v1/local-auth/admin/users/{phone}/devices`
- `POST /v1/local-auth/admin/users/{phone}/devices` body `{"androidId":"...","publicKeyPem":"-----BEGIN PUBLIC KEY-----...","label":"..."}`
- `DELETE /v1/local-auth/admin/devices/{deviceId}`

Internal Signal Server endpoints (all require `Authorization: Bearer <LOCAL_AUTH_INTERNAL_TOKEN>`):
- `POST /v1/local-auth/internal/validate-ticket`
- `POST /v1/local-auth/internal/consume-ticket`

Tickets are HMAC-signed, expire after two minutes, are stored server-side, and cannot be redeemed twice. The internal consume operation uses a database transaction and row lock.

## Deploy the Go sidecar

1. Copy `.env.example` to `.env` and generate five independent secrets. For example, use `openssl rand -hex 32` separately for the database password, admin token, internal token, ticket HMAC secret, and Android-ID hash secret. Never commit the resulting `.env`.
2. Run the stack:

   ```sh
   cd local-auth
   docker compose up -d --build
   docker compose logs -f local-auth
   ```

3. The Compose file deliberately publishes the sidecar only on host loopback at `127.0.0.1:8090`; PostgreSQL is on an internal Docker network and is not published.
4. Put a trusted LAN reverse proxy in front of the sidecar and expose it only over HTTPS. Use a certificate whose SAN matches the hostname configured in the app and Java server.
5. Set `LOCAL_AUTH_ONLY=true`, `LOCAL_AUTH_INTERNAL_URL`, and `LOCAL_AUTH_INTERNAL_TOKEN` on the Java Signal Server. The Java server's internal URL must resolve from the server process/container and must validate the proxy certificate.
6. Set `ALLOWED_ORIGINS` in the sidecar environment to the exact HTTPS origin hosting the dashboard, for example `https://dashboard.lan`. Do not use a wildcard origin.
7. Import `server-config.json` into the Android app under **Settings → Local Server**. Set `localAuthOnly=true`, the HTTPS auth/API and module endpoints, and the PEM CA certificate in `trustedCaPem`.
8. On the app's phone-number registration screen, tap **Local server setup** before entering the number and choose **Copy device enrollment information**. In the dashboard create the user's phone record, then enroll that Android ID + public key. Only then can that device request a challenge. This pre-registration path avoids requiring an already-authenticated account to enroll its first device.

Example reverse-proxy routing on the same host:
- dashboard UI: `https://dashboard.lan/` → `http://127.0.0.1:8088/`
- local-auth API: `https://dashboard.lan/v1/local-auth/` → `http://127.0.0.1:8090/v1/local-auth/`

If the dashboard and auth API use different hostnames, set the dashboard's API base URL to the HTTPS auth hostname and add the exact dashboard origin to `ALLOWED_ORIGINS`.

## Verification and build checks

Run these checks from the repository root:

```sh
cd local-auth
gofmt -w .
go vet ./...
go test ./...
cd ..
./mvnw -B -pl service -am -DskipTests -Dcheckstyle.skip -Dspotless.check.skip package
```

The full Maven suite is `./mvnw verify`. Android build/test tasks must also be run with the project's supported JDK/Android SDK. A successful compile is not a substitute for a real two-device LAN acceptance test.

## Scope and remaining LAN infrastructure

This repository still contains Signal's normal server components. The local authentication sidecar does not, by itself, replace every external subsystem used by the complete Signal deployment. A fully isolated installation must separately provide and configure local-compatible storage/database services, attachment/CDN hosting, TURN/SFU for calls, and a message wake-up strategy that does not depend on FCM/APNs. The app endpoint file exposes configuration slots for those modules; a URL is not proof that the corresponding local service has been deployed.


## Administrative controls and audit trail

The dashboard administrator API also supports these routes:

- `PATCH /v1/local-auth/admin/user-status/{phone}` with `{"active":false}` to suspend a user or `{"active":true}` to re-enable them. Suspending a user consumes all outstanding local registration tickets so re-enabling cannot revive a previously issued ticket. Device enrollments are preserved.
- `GET /v1/local-auth/admin/events?limit=50` to view the newest administrative changes. The limit is restricted to 1–100. Events include user creation/deletion, user enable/disable, device enrollment/revocation, timestamp, the connection peer address (which may be the reverse proxy), and non-secret metadata.

The audit log is not an immutable external compliance ledger. Protect the PostgreSQL volume and backups with the same controls as the authentication database.


### Scope of local-auth suspension

Suspending a user or device blocks future local-auth challenges and consumes outstanding registration tickets. It does not terminate existing Signal sessions or remove an already-registered Signal device. Immediate remote sign-out requires a separate account/device administration integration with the Java Signal Server; this sidecar alone is an enrollment allowlist.
