import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { createReadStream, promises as fsPromises } from 'node:fs';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { Server as TusServer } from '@tus/server';
import { FileStore } from '@tus/file-store';
import { S3Client, PutObjectCommand, HeadObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { jwtVerify } from 'jose';

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
};
const PORT = Number(process.env.PORT ?? 8096);
const DATA_DIR = process.env.TUS_DATA_DIR ?? '/var/lib/signal-tus';
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES ?? 2_000_000_000);
const TOKEN_SECRET = Buffer.from(required('TUS_SHARED_AUTH_SECRET_BASE64'), 'base64');
if (TOKEN_SECRET.length !== 32) throw new Error('TUS shared auth secret must decode to exactly 32 bytes');
const PUBLIC_BASE_URL = required('TUS_PUBLIC_BASE_URL').replace(/\/$/, '');
const s3 = new S3Client({
  endpoint: required('S3_ENDPOINT'),
  region: process.env.S3_REGION ?? 'us-east-1',
  forcePathStyle: true,
  credentials: {
    accessKeyId: required('S3_ACCESS_KEY'),
    secretAccessKey: required('S3_SECRET_KEY')
  }
});
const attachmentsBucket = process.env.S3_ATTACHMENTS_BUCKET ?? 'attachments';
const backupsBucket = process.env.S3_BACKUPS_BUCKET ?? 'backups';
const spool = path.resolve(DATA_DIR);
await fsPromises.mkdir(spool, { recursive: true });

function safeKey(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 1024) throw new Error('Invalid object key');
  if (value.startsWith('/') || value.includes('\\') || value.split('/').some(p => !p || p === '.' || p === '..')) {
    throw new Error('Unsafe object key');
  }
  return value;
}

function bearer(req) {
  const header = req.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) throw Object.assign(new Error('Bearer token required'), { status_code: 401 });
  return match[1];
}

async function claimsFor(req, bucket, action) {
  try {
    const { payload } = await jwtVerify(bearer(req), TOKEN_SECRET, { audience: bucket });
    if (typeof payload.sub !== 'string' || payload.sub.length < 1) throw new Error('Missing subject');
    if (bucket === 'backups') {
      if (payload.scope !== (action === 'read' ? 'read' : 'write')) throw new Error('Invalid backup scope');
    }
    if (action === 'write') {
      if (!Number.isSafeInteger(payload.maxLen) || payload.maxLen < 1 || payload.maxLen > MAX_UPLOAD_BYTES) {
        throw new Error('Invalid maxLen claim');
      }
    }
    return payload;
  } catch (error) {
    throw Object.assign(new Error('Invalid or expired upload authorization'), { status_code: 401, cause: error });
  }
}

function parsedFilename(upload) {
  const name = upload?.metadata?.filename;
  if (typeof name !== 'string') throw Object.assign(new Error('Upload-Metadata filename is required'), { status_code: 400 });
  return safeKey(name);
}

async function sha256Base64(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('base64');
}

async function publishToObjectStore(bucket, upload) {
  if (!upload.storage?.path || !Number.isSafeInteger(upload.size) || upload.offset !== upload.size) return false;
  const filePath = upload.storage.path;
  const key = parsedFilename(upload);
  const checksum = await sha256Base64(filePath);
  const objectMetadata = { 'signal-checksum-sha256': checksum };
  await s3.send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: createReadStream(filePath),
    ContentLength: upload.size,
    ContentType: 'application/octet-stream',
    Metadata: objectMetadata
  }));
  // The object is durable in MinIO now; remove the local staging file and metadata.
  await upload.datastore?.remove?.(upload.id).catch(() => {});
  return true;
}

function makeTusServer(bucketName, routePath) {
  const datastore = new FileStore({
    directory: path.join(spool, bucketName),
    expirationPeriodInMilliseconds: 8 * 24 * 60 * 60 * 1000
  });
  const server = new TusServer({
    path: routePath,
    datastore,
    maxSize: async (req, uploadId) => {
      if (req.method === 'OPTIONS') return MAX_UPLOAD_BYTES;
      const payload = await claimsFor(req, bucketName, 'write');
      if (uploadId) {
        const existing = await datastore.getUpload(uploadId);
        const existingKey = parsedFilename(existing);
        if (existingKey !== payload.sub) throw Object.assign(new Error('Upload token does not match upload'), { status_code: 403 });
      }
      return payload.maxLen;
    },
    onIncomingRequest: async (req, uploadId) => {
      if (req.method === 'OPTIONS') return;
      const payload = await claimsFor(req, bucketName, 'write');
      if (uploadId) {
        const existing = await datastore.getUpload(uploadId);
        if (parsedFilename(existing) !== payload.sub) throw Object.assign(new Error('Upload token subject mismatch'), { status_code: 403 });
      }
    },
    onUploadCreate: async (req, upload) => {
      const payload = await claimsFor(req, bucketName, 'write');
      if (parsedFilename(upload) !== payload.sub) {
        throw Object.assign(new Error('Upload metadata filename does not match the signed subject'), { status_code: 403 });
      }
      if (!Number.isSafeInteger(upload.size) || upload.size > payload.maxLen) {
        throw Object.assign(new Error('Upload exceeds signed maxLen'), { status_code: 413 });
      }
      return { metadata: upload.metadata };
    },
    onUploadFinish: async (_req, upload) => {
      // Uploads are staged locally first and copied to MinIO. A transient MinIO outage must not
      // discard an already completed TUS stream; the retry loop below republishes completed items.
      try {
        await publishToObjectStore(bucketName, upload);
      } catch (error) {
        console.error(JSON.stringify({ event: 'tus_publish_deferred', bucket: bucketName, uploadId: upload.id, message: error.message }));
      }
      return {};
    },
    allowedOrigins: [],
    respectForwardedHeaders: false
  });
  return { server, datastore };
}

const attachments = makeTusServer(attachmentsBucket, '/upload/attachments');
const backups = makeTusServer(backupsBucket, '/upload/backups');

async function retryCompletedUploads() {
  for (const [bucket, state] of [[attachmentsBucket, attachments], [backupsBucket, backups]]) {
    try {
      const ids = await state.datastore.configstore.list();
      for (const id of ids) {
        const upload = await state.datastore.getUpload(id).catch(() => null);
        if (!upload || upload.size == null || upload.offset !== upload.size) continue;
        const key = parsedFilename(upload);
        // Don't overwrite an existing completed object on every retry.
        try {
          await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
          await state.datastore.remove(id);
          continue;
        } catch (error) {
          if (error?.$metadata?.httpStatusCode !== 404 && error?.name !== 'NotFound') throw error;
        }
        await publishToObjectStore(bucket, upload);
      }
    } catch (error) {
      console.error(JSON.stringify({ event: 'tus_retry_scan_failed', bucket, message: error.message }));
    }
  }
}
setInterval(retryCompletedUploads, 30_000).unref();

function jsonError(res, status, message) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify({ error: message }));
}

function decodePathSegments(urlPath) {
  return urlPath.split('/').filter(Boolean).map(segment => decodeURIComponent(segment));
}

function contentHeaders(head) {
  const headers = {
    'content-type': head.ContentType ?? 'application/octet-stream',
    'content-length': String(head.ContentLength ?? 0),
    'cache-control': 'private, max-age=31536000, immutable'
  };
  if (head.ETag) headers.etag = head.ETag;
  if (head.LastModified) headers['last-modified'] = head.LastModified.toUTCString();
  if (head.Metadata?.['signal-checksum-sha256']) headers['x-signal-checksum-sha256'] = head.Metadata['signal-checksum-sha256'];
  return headers;
}

async function serveObject(req, res, bucket, key, isBackup) {
  if (isBackup) {
    const payload = await claimsFor(new Request(`http://localhost${req.url}`, { headers: req.headers }), 'backups', 'read');
    const backupDir = decodeURIComponent(key.split('/')[0] ?? '');
    if (payload.sub !== backupDir) throw Object.assign(new Error('Backup read token does not match backup directory'), { status_code: 403 });
  }
  const safeObjectKey = safeKey(key);
  const head = await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: safeObjectKey }));
  if (req.method === 'HEAD') {
    res.writeHead(200, contentHeaders(head));
    res.end();
    return;
  }
  const range = req.headers.range;
  const object = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: safeObjectKey, ...(range ? { Range: range } : {}) }));
  const status = range ? 206 : 200;
  const headers = contentHeaders(head);
  if (object.ContentRange) headers['content-range'] = object.ContentRange;
  if (object.ContentLength != null) headers['content-length'] = String(object.ContentLength);
  res.writeHead(status, headers);
  await pipeline(object.Body, res);
}

const app = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const pathname = url.pathname;
    if (pathname.startsWith('/upload/attachments')) return await attachments.server.handle(req, res);
    if (pathname.startsWith('/upload/backups')) return await backups.server.handle(req, res);

    if (pathname.startsWith('/attachments/')) {
      const segments = decodePathSegments(pathname);
      if (segments.length !== 2) return jsonError(res, 404, 'Not found');
      return await serveObject(req, res, attachmentsBucket, segments[1], false);
    }
    if (pathname.startsWith('/backups/')) {
      const segments = decodePathSegments(pathname);
      if (segments.length < 3) return jsonError(res, 404, 'Not found');
      return await serveObject(req, res, backupsBucket, segments.slice(1).join('/'), true);
    }
    return jsonError(res, 404, 'Not found');
  } catch (error) {
    const status = Number.isInteger(error.status_code) ? error.status_code : (error?.$metadata?.httpStatusCode ?? 500);
    console.error(JSON.stringify({ event: 'request_failed', status, message: error.message }));
    if (!res.headersSent) jsonError(res, status, status >= 500 ? 'Storage service unavailable' : error.message);
    else res.destroy(error);
  }
});

app.listen(PORT, process.env.BIND_ADDRESS ?? '0.0.0.0', () => {
  console.log(JSON.stringify({ event: 'signal_tus_ready', port: PORT, publicBaseUrl: PUBLIC_BASE_URL }));
});
