# Local LAN authentication and deployment design

> Status: design contract for the `local-lan-auth` branch. This document is not a claim that the feature is implemented or production-ready.

## Objective

Run the Signal Android client and Signal server inside a private LAN without depending on SMS delivery or Signal's hosted registration service. Existing Signal E2E encryption, message envelopes, device queues, and WebSocket delivery must remain intact.

## Required enrollment source

A trusted administrator dashboard must provision each allowed user before first login. The server-side enrollment record contains:

- Canonical E.164 phone number.
- Android ID, stored as a keyed hash rather than plaintext.
- Optional device public-key fingerprint. This is strongly recommended; Android ID alone is not a secure authenticator.
- Enabled/disabled state, creation time, last successful login, and administrator audit metadata.

The two values (phone number and Android ID) must match the same enrollment record. Unknown or disabled pairs are rejected with a generic response to avoid leaking enrolled phone numbers.

The current `signal-server` repository does not contain the administrator dashboard. It must either be extended in its own repository or call the secured management API below.

## Login protocol

1. The app normalizes the entered number to E.164 and reads `Settings.Secure.ANDROID_ID`.
2. The app sends the number, Android ID, and (when provisioned) a proof signed by the Android Keystore device key to `POST /v1/local-auth/sessions`.
3. The server checks the enrollment record, checks rate limits, and creates a short-lived, single-use local registration session.
4. The server returns an opaque session ID and a short-lived verification value in the response. The client places the value in the existing verification field and submits it automatically. The response must never be logged.
5. The server verifies and consumes the value once, marks the local session verified, and binds it to the E.164 number and device identity.
6. The normal Signal account-registration request proceeds. `PhoneVerificationTokenManager` must validate this local session rather than calling the external SMS/voice Registration Service.
7. The session expires quickly, cannot be replayed, and is invalidated after successful registration or too many failed attempts.

The verification value returned over the same authenticated TLS connection is not an independent factor. It is a protocol hand-off, not proof of phone-number ownership. The actual authorization decision comes from the administrator's pre-enrollment and the device binding. Android ID can be reset or spoofed, so a production deployment should require a Keystore-generated key registered to the enrollment record as well.

## Suggested API contract

### Dashboard / administrator API

All routes require a dedicated administrator credential (preferably mTLS or a narrowly scoped bearer token), are restricted to the management LAN, and are audited.

- `POST /v1/admin/device-enrollments` — create an enrollment.
- `GET /v1/admin/device-enrollments` — paginated/searchable list.
- `GET /v1/admin/device-enrollments/{id}` — details.
- `PATCH /v1/admin/device-enrollments/{id}` — change number/device binding or enable state.
- `DELETE /v1/admin/device-enrollments/{id}` — revoke an enrollment.

The dashboard must never be given access to the app's authentication signing keys or the server's general-purpose secrets.

### Client API

- `POST /v1/local-auth/sessions` — start local login and receive the opaque session ID and one-time value.
- `POST /v1/local-auth/sessions/{sessionId}/verify` — consume the one-time value and mark the session verified.
- `POST /v1/local-auth/sessions/{sessionId}/pin` — verify the optional account PIN when server-side PIN enforcement is enabled.

Responses for unknown number/device combinations must be indistinguishable. Apply per-IP, per-number, and per-device limits; use constant-time comparisons for secrets; hash stored Android IDs and PINs; never store plaintext PINs or one-time values.

## PIN semantics

The requested PIN is an additional app/account lock, not the existing Signal Registration Lock / SVR PIN. These are separate features and must not be conflated.

- PIN setup/change/disable is available in app settings after the user is authenticated.
- Store a salted Argon2id (or suitably configured PBKDF2 where Argon2id is unavailable) verifier server-side; never store plaintext.
- Enforce retry delays/lockouts server-side and locally.
- For local app relaunch protection, use Android Keystore-backed encryption and a local verifier. Do not require a network round trip just to unlock an already authenticated app.
- Provide a recovery procedure through the administrator dashboard; never silently reset the PIN.

## SMS / external registration removal boundary

Remove the SMS/voice *verification* path, not historical SMS/MMS database formats or migration code which may be needed to read old user data.

The removal is complete only when:
- The Android registration UI no longer requests SMS or voice transport.
- The SMS Retriever dependency, receiver, and registration-only permissions are removed.
- The app's registration client no longer calls `/v1/verification/session`, `/code`, or `/submit-code`.
- The server no longer invokes `RegistrationServiceClient.sendVerificationCode`, `getSession`, or the private external registration gRPC service for account registration.
- Account registration and change-number paths use an explicitly supported local authorization flow.
- Automated tests cover new registration, existing-account recovery, invalid device pairing, PIN failures, replay, expiry, rate limits, and concurrent attempts.

Do not delete SMS-named message-storage models, database migrations, or old backup fixtures merely because their names contain SMS.

## Configuration and required LAN services

The server's current implementation uses multiple independent infrastructure systems. A LAN deployment must configure every enabled subsystem, not just the chat URL:

- FoundationDB: message queues and message persistence.
- DynamoDB-compatible storage: accounts, devices, keys, and other tables.
- Redis: caches, Pub/Sub, rate-limiters, and push scheduling.
- Local object storage / S3-compatible service: attachments and backups.
- TLS certificates and hostnames resolvable by all LAN clients.
- Local TURN and SFU for calls if calls are required.
- Local equivalents for CDSI, SVR2/SVRB, secure storage, and key transparency if those Signal features are required.

FCM/APNs are internet push services. In a network with no internet access, they cannot wake an offline phone. WebSocket delivery works while the app is connected; offline notification and background wake-up require a separate LAN push design (or an explicitly documented limitation).

The example `service/config/sample.yml` is a demonstration configuration, not a ready-to-run production configuration. Values such as example credentials, example endpoints, stub providers, and local test modes must not be reused in production.

## Implementation order

1. Add enrollment persistence and administrator management endpoints.
2. Add the one-time local auth session and its throttling/expiry/replay protections.
3. Route the core account registration verifier through local sessions.
4. Adapt app registration to request and consume the local session automatically.
5. Add the optional PIN settings and app unlock gate, separately from SVR PIN.
6. Add a validated endpoint configuration file and settings UI.
7. Remove SMS verification code paths and the private registration-service dependency.
8. Build and run end-to-end tests on actual LAN devices, including offline/online delivery and restart/recovery scenarios.

This feature is not production-ready until all eight steps are implemented and tested.
