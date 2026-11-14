# LAN attachment and backup storage

This service implements the Signal CDN-3 TUS protocol on-premises. It is compatible with the existing Signal Android upload forms and the server-side `TusAttachmentGenerator` / `Cdn3BackupCredentialGenerator` JWT contracts.

## Endpoints

Expose only the TUS service through the LAN HTTPS reverse proxy:

- `POST/PATCH/HEAD/OPTIONS https://cdn3.lan/upload/attachments` — encrypted message attachments
- `POST/PATCH/HEAD/OPTIONS https://cdn3.lan/upload/backups` — encrypted backup archives and media
- `GET/HEAD https://cdn3.lan/attachments/{key}` — content-addressed encrypted attachment
- `GET/HEAD https://cdn3.lan/backups/{backupDir}/{objectKey}` — requires a short-lived backup read JWT

The Signal Server must set `tus.uploadUri: https://cdn3.lan/upload`; the Android `server-config.json` must set `services.cdn3: https://cdn3.lan`.

## Start the Docker deployment

From the repository root:

```sh
cd deploy/attachments
cp .env.example .env
openssl rand -base64 32
```

Put the generated Base64 secret in `TUS_SHARED_AUTH_SECRET_BASE64`. Generate independent values for `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD`, `S3_ACCESS_KEY`, and `S3_SECRET_KEY`; the TUS service account is restricted to the two buckets by `minio-policy.json`. Never reuse MinIO root credentials as the TUS service credentials.

Start and inspect the stack:

```sh
docker compose up -d --build
docker compose ps
docker compose logs -f minio-bootstrap tus-server
```

The MinIO API and console are bound to loopback only (ports 9000/9001 by default). The TUS service is bound to loopback on port 8096 and exposes `GET /healthz` for its Docker healthcheck. Do not publish MinIO or the staging spool to the LAN.

Configure the Signal Server's private YAML with the exact same decoded 32-byte secret:

```yaml
tus:
  uploadUri: https://cdn3.lan/upload
  userAuthenticationTokenSharedSecret: secret://tus.userAuthenticationTokenSharedSecret
  tokenExpiration: P7D
```

The secret value in the server's secret store must be the same bytes as `TUS_SHARED_AUTH_SECRET_BASE64` after Base64 decoding. Keep the server-side setting as raw 32-byte secret material; do not copy the Base64 text as though it were the raw secret.

Configure Android runtime settings:

```json
{
  "services": {
    "cdn3": "https://cdn3.lan"
  }
}
```

The LAN HTTPS reverse proxy must route `/upload/`, `/attachments/`, and `/backups/` to the TUS service, preserve streaming PATCH requests, and disable request-body buffering on `/upload/`. The service supports attachment and backup upload/download, but a complete backup restore still needs a real-device verification pass.

## Authentication and limits

The service verifies the same HMAC-SHA256 JWTs that Signal Server creates. It validates audience (`attachments` or `backups`), subject, expiration, upload `maxLen`, and backup `scope` (`write` for TUS upload, `read` for downloads). Uploads are first streamed to a private local spool and then copied to MinIO; successful objects receive the `signal-checksum-sha256` metadata used by Signal clients. No Signal message plaintext or encryption key is handled by this service.

## Secrets

Set `TUS_SHARED_AUTH_SECRET_BASE64` to the Base64 representation of the exact 32-byte `tus.userAuthenticationTokenSharedSecret` used by Signal Server. Do not generate a second secret for the TUS service. Give this container a dedicated MinIO user that can read/write/list/delete only the `attachments` and `backups` buckets.

## Reverse proxy

The HTTPS proxy must preserve methods and headers and must disable request-body buffering for `/upload/` so PATCH requests stream to TUS. Set a generous upload timeout (at least 30 minutes); do not rewrite the `Upload-Offset`, `Upload-Length`, `Tus-Resumable`, `Authorization`, `Upload-Metadata`, or `X-Signal-Checksum-Sha256` headers.

## Operations

The local disk spool is staging only; completed objects are stored durably in MinIO. The service retries completed staged uploads every 30 seconds after transient MinIO failures. Mount `TUS_DATA_DIR` on persistent local storage. Keep the MinIO data volume backed up.

This implementation is a single-host LAN service. Validate upload/resume/download/checksum behavior and backup restore on at least two Android devices before production use.
