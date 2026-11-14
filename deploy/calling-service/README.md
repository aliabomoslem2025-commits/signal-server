# Self-hosted Signal Calling Service

This deployment uses Signal's own RingRTC-compatible Calling Service (frontend signaling + backend SFU), not a third-party SFU.

## Source

The `upstream/` directory is a Git submodule pinned to the Signal upstream commit recorded in this repository. Initialize it with:

```sh
git submodule update --init --recursive
```

## Configure

```sh
cp .env.example .env
```

Set the following values in `.env` before starting:

- `CALLING_MEDIA_IP`: the Docker host's reachable LAN address, never loopback.
- `CALLING_PUBLIC_HOST`: the hostname that resolves to this server and whose TLS certificate is trusted by the Android app.
- `CALLING_AUTH_KEY`: generate a fresh 32-byte hex key with `openssl rand -hex 32`.
- `CALLING_ZK_PARAMS`: the base64 serialized `GenericServerSecretParams` matching the Signal Server calling ZK secret and the public parameters used by the Android app build.

The ZK parameters are cryptographic protocol material, not arbitrary passwords. The server-side secret, Calling Frontend secret, and Android app public parameters must form the same key set. The repository intentionally does not contain default/example values. Until the matching values are installed and verified, group calls must be considered unavailable.

## Start

```sh
docker compose up -d --build
docker compose ps
docker compose logs -f calling-frontend calling-backend
```

The frontend is bound to loopback on port 8095. Put it behind the LAN HTTPS reverse proxy at `https://CALLING_PUBLIC_HOST`. Do not publish the frontend's internal API port 8100.

The backend advertises `CALLING_MEDIA_IP`; the LAN firewall must permit UDP 10000 and TCP 9900 to the Docker host. The backend-to-frontend API and DynamoDB Local stay on the private Compose network. DynamoDB data is persisted in the `calling-dynamodb` volume.

## Important

- This is a single-host LAN deployment, not a horizontally redundant or production high-availability topology.
- The upstream source's example Compose file is for development/testing and uses dummy secrets, loopback candidates and ngrok. This deployment deliberately does not use those defaults.
- Calls still require the app's runtime `services.sfu` endpoint to point to the HTTPS frontend hostname.
- Verify two-device one-to-one calls and group calls on the actual LAN, including UDP reachability and correct advertised IPs, before enabling the feature for users.
