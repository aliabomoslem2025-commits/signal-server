# LAN attachment and backup storage

This service implements the Signal CDN-3 TUS protocol on-premises. It is compatible with the existing Signal Android upload forms and the server-side `TusAttachmentGenerator` / `Cdn3BackupCredentialGenerator` JWT contracts.

## Endpoints

Expose only the TUS service through the LAN HTTPS reverse proxy:

- `POST/PATCH/HEAD/OPTIONS https://cdn3.lan/upload/attachments` — encrypted message attachments
- `POST/PATCH/HEAD/OPTIONS https://cdn3.lan/upload/backups` — encrypted backup archives and media
- `GET/HEAD https://cdn3.lan/attachments/{key}` — content-addressed encrypted attachment
- `GET/HEAD https://cdn3.lan/backups/{backupDir}/{objectKey}` — requires a short-lived backup read JWT

The Signal Server must set `tus.uploadUri: https://cdn3.lan/upload`; the Android `server-config.json` must set `services.cdn3: https://cdn3.lan`.

## Authentication and limits

The service verifies the same HMAC-SHA256 JWTs that Signal Server creates. It validates audience (`attachments` or `backups`), subject, expiration, upload `maxLen`, and backup `scope` (`write` for TUS upload, `read` for downloads). Uploads are first streamed to a private local spool and then copied to MinIO; successful objects receive the `signal-checksum-sha256` metadata used by Signal clients. No Signal message plaintext or encryption key is handled by this service.

## Secrets

Set `TUS_SHARED_AUTH_SECRET_BASE64` to the Base64 representation of the exact 32-byte `tus.userAuthenticationTokenSharedSecret` used by Signal Server. Do not generate a second secret for the TUS service. Give this container a dedicated MinIO user that can read/write/list/delete only the `attachments` and `backups` buckets.

## Reverse proxy

The HTTPS proxy must preserve methods and headers and must disable request-body buffering for `/upload/` so PATCH requests stream to TUS. Set a generous upload timeout (at least 30 minutes); do not rewrite the `Upload-Offset`, `Upload-Length`, `Tus-Resumable`, `Authorization`, `Upload-Metadata`, or `X-Signal-Checksum-Sha256` headers.

## Operations

The local disk spool is staging only; completed objects are stored durably in MinIO. The service retries completed staged uploads every 30 seconds after transient MinIO failures. Mount `TUS_DATA_DIR` on persistent local storage. Keep the MinIO data volume backed up.

This implementation is a single-host LAN service. Validate upload/resume/download/checksum behavior and backup restore on at least two Android devices before production use.
