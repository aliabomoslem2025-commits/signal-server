# Local device-auth deployment

The local authentication API uses a dedicated DynamoDB table. It must not share the Signal accounts, keys, verification sessions, or message tables.

## 1. Create the table

For DynamoDB Local:

    export DYNAMODB_ENDPOINT=http://127.0.0.1:8000
    export AWS_ACCESS_KEY_ID=dummy
    export AWS_SECRET_ACCESS_KEY=dummy
    export AWS_REGION=us-east-1
    ./deploy/local-auth/create-table.sh

For a DynamoDB-compatible managed endpoint, omit DYNAMODB_ENDPOINT and configure normal AWS credentials.

## 2. Configure the service process

Set these environment variables for the Signal server:

    LOCAL_AUTH_TABLE=signal_local_device_auth
    LOCAL_AUTH_ADMIN_TOKEN=<high-entropy-secret>

Generate an admin token with:

    openssl rand -base64 48

Do not commit the value or put it in the Android app or dashboard static files. The dashboard administrator enters it at runtime.

## 3. Configure TLS and LAN routing

Expose the server API over HTTPS using a certificate whose CA is installed on every managed Android device. Do not enable cleartext HTTP for authentication. Restrict the admin dashboard and /v1/local-auth/admin/* routes to the management LAN or VPN using firewall/reverse-proxy ACLs as an additional layer.

## 4. Provision devices

For every authorized handset, obtain:
- E.164 phone number;
- Settings.Secure.ANDROID_ID;
- Base64-encoded X.509 EC P-256 public key exported by the Android app's Android Keystore enrollment helper.

Create the binding in the dashboard. The private key must never leave Android Keystore.

## 5. Current integration boundary

The server endpoints and registration-session verifier are implemented on the feature/local-lan-auth branch. The Android registration module still needs to call /challenge, /verify, and /submit-code and replace its SMS-based registration orchestration before real users can complete registration through this flow. Do not deploy this branch as a complete production messenger until the app integration, build, registration, and end-to-end tests pass.
