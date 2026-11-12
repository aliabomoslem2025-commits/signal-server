# Local Device Authentication Service

This is a production-oriented LAN authentication control-plane component for the customized Signal deployment. It replaces SMS as the device authorization factor with a provisioned phone-number + Android-ID-hash + Android Keystore public-key binding.

## Important integration boundary

This service is **not yet wired into Signal's Java RegistrationController or the Android registration flow**. It provides the persistent enrollment/authentication API and an internal one-time registration-ticket redemption endpoint. The Signal-server and Signal-app adapters must call these endpoints before this can replace Signal registration verification end-to-end. Do not deploy this as if it alone completes Signal registration.

## Security model

- Android ID is a lookup attribute, not a secret or authenticator.
- The admin provisions each device's ECDSA P-256 public key.
- The Android app must create the corresponding private key in Android Keystore and sign the server challenge using SHA256withECDSA.
- The service returns the short-lived one-time code only after successful signature verification. The code is transported over HTTPS/WSS-protected LAN TLS, never SMS.
- Registration tickets are HMAC-signed, short-lived, and stored server-side. The internal consume endpoint atomically marks a ticket as consumed.
- Admin and internal endpoints require separate high-entropy bearer tokens.
- Use HTTPS even inside the LAN. Do not set cleartext traffic or disable certificate validation.

## API

Public:
- `POST /v1/local-auth/challenge` body: `{ "phone": "+...", "androidId": "..." }`
- `POST /v1/local-auth/verify` body: `{ "challengeId": "...", "signature": "<base64 ASN.1 ECDSA>" }`
- `POST /v1/local-auth/complete` body: `{ "challengeId": "...", "code": "123456" }`

Admin (Authorization: Bearer LOCAL_AUTH_ADMIN_TOKEN):
- `GET /v1/local-auth/admin/users`
- `POST /v1/local-auth/admin/users` body: `{ "phone": "+...", "displayName": "..." }`
- `DELETE /v1/local-auth/admin/users/{phone}`
- `GET /v1/local-auth/admin/users/{phone}/devices`
- `POST /v1/local-auth/admin/users/{phone}/devices` body: `{ "androidId": "...", "publicKeyPem": "-----BEGIN PUBLIC KEY-----...", "label": "..." }`
- `DELETE /v1/local-auth/admin/devices/{deviceId}`

Internal (Authorization: Bearer LOCAL_AUTH_INTERNAL_TOKEN):
- `POST /v1/local-auth/internal/consume-ticket` body: `{ "ticket": "lan1.payload.signature" }`
  Returns the verified phone and device binding once; replay attempts are rejected.

The canonical signed challenge message is:
`signal-local-auth-v1\n{challengeId}\n{phone}\n{base64(nonce)}`

## Deploy

1. Generate four independent random secrets (at least 32 random bytes each): database password, admin token, internal token, ticket HMAC secret, and Android-ID hash secret.
2. Store them in a protected `.env` file, never in Git.
3. Put this service behind the LAN reverse proxy with a valid private CA certificate and expose only HTTPS.
4. Keep PostgreSQL and port 8090 private. Do not expose the database to client VLANs.
5. Run `docker compose up -d --build`.
6. Configure the dashboard's API base URL and admin token.
7. Enroll the user and the device public key before allowing login.

The compose file deliberately binds port 8090 to loopback. Configure the reverse proxy on the same host to forward to it. It is not intended to be directly exposed.

## Required follow-up for full Signal operation

- Wire the Android app to generate and persist a P-256 Android Keystore key, call challenge/verify/complete, and pass the resulting registration ticket through the registration flow.
- Wire the Java Signal server's `PhoneVerificationTokenManager` to validate/consume that ticket before creating a phone-number account.
- Disable the SMS/voice verification routes when local-auth-only mode is enabled.
- Retain Signal's ACI/PNI, identity-key and pre-key generation and account-creation logic.
- Run Android builds, Maven tests, API integration tests and real multi-device LAN tests.

