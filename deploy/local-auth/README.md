# Local device-auth deployment

The `local-lan-auth` branch adds administrator-preauthorized Android device authentication to the Signal HTTP service. It uses a dedicated DynamoDB-compatible table and an EC P-256 public key enrolled by the administrator. The app signs a random server challenge with a private key held in Android Keystore.

## 1. Create the local-auth table

For DynamoDB Local:

```sh
export DYNAMODB_ENDPOINT=http://127.0.0.1:8000
export AWS_ACCESS_KEY_ID=dummy
export AWS_SECRET_ACCESS_KEY=dummy
export AWS_REGION=us-east-1
./deploy/local-auth/create-table.sh
```

The script is idempotent. The table uses string partition/sort keys `PK` and `SK`, and TTL on `expiresAt` for short-lived challenges and registration sessions.

## 2. Configure the server

Set these variables on the Signal server process:

```sh
LOCAL_AUTH_TABLE=signal_local_device_auth
LOCAL_AUTH_ADMIN_TOKEN=<high-entropy-secret>
```

Generate a token with `openssl rand -base64 48`. Store it in the server's secret manager or protected environment. Never put it in the APK, static dashboard files, or an exported client configuration.

The upstream registration-service client is no longer initialized by `WhisperServerService`, the legacy `VerificationController` is no longer registered, and the `registrationService` settings/secrets have been removed from the sample and local test configurations. The registration verifier fails closed in LAN mode: only a valid, code-confirmed local registration session is accepted.

## 3. Provision a device

On the Android phone, open the pre-registration phone-number screen and select **Enroll device**. Enter the phone number in E.164 format and copy the JSON. It contains:
- E.164 phone number;
- `Settings.Secure.ANDROID_ID`;
- Base64 X.509 EC P-256 public key;
- display name.

In Signal Dashboard, add the matching phone/Android ID/public-key tuple. The private key stays in Android Keystore and must never be requested or copied.

The dashboard API is served by the Signal server at `/v1/local-auth/admin/*`. Every admin request requires `Authorization: Bearer <LOCAL_AUTH_ADMIN_TOKEN>`. Restrict these routes to the management VLAN/VPN at the firewall or reverse proxy.

## 4. Authentication protocol

1. The app sends `{ phoneNumber, androidId }` to `POST /v1/local-auth/challenge`.
2. The server checks the enabled administrator-created binding and returns a random nonce.
3. The app signs the nonce with its Keystore private key.
4. The app sends `{ challengeId, signature }` to `POST /v1/local-auth/verify`.
5. The server verifies the signature, consumes the challenge once, then returns a six-digit compatibility code and a short-lived registration session ID inside the TLS-protected response.
6. The app automatically places the code into the existing verification UI and submits `{ phoneNumber, registrationSessionId, code }` to `POST /v1/local-auth/submit-code`.
7. The Signal registration endpoint accepts that session only after the code has been verified.

The six-digit code is a compatibility step for the existing registration UX, not a separate out-of-band factor. Device possession is established by the signature over the server nonce. Android ID by itself is not an authentication factor.

## 5. TLS and endpoint setup

The Android app accepts HTTPS/WSS only and never disables certificate validation. If the LAN deployment uses a private CA, import the root/intermediate CA PEM in the app's `server-config.json` field `trustedCaPem`. Use a valid certificate with SANs matching every configured DNS name.

The app's runtime configuration currently routes the primary Signal service, CDN 0/2/3, storage, CDSI and SVR2 through configured addresses. Some auxiliary services, including SFU/TURN, SVRB and certain attachment/calling transports, are not yet dynamically wired to the config JSON.

## 6. Production boundary

This repository is not, by itself, a complete isolated-LAN distribution of every Signal service. The core server still requires its storage, message queue, cache and other dependencies (including FoundationDB, DynamoDB-compatible storage and Redis). Additional work is required for:
- local object storage/CDN/attachment services;
- replacing or disabling FCM/APNs for a network with no Internet egress;
- local TURN and SFU infrastructure for voice/video calls;
- routing every auxiliary client module to local endpoints;
- provisioning and validating production TLS and secrets;
- end-to-end testing with multiple real Android devices.

No production-ready claim should be made until the server/app/dashboard builds and the full LAN acceptance tests pass.
