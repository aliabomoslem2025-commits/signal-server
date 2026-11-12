CREATE TABLE IF NOT EXISTS local_auth_users (
  phone TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS local_auth_devices (
  id TEXT PRIMARY KEY,
  phone TEXT NOT NULL REFERENCES local_auth_users(phone) ON DELETE CASCADE,
  android_id_hash BYTEA NOT NULL,
  public_key_pem TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ,
  UNIQUE(phone, android_id_hash)
);

CREATE TABLE IF NOT EXISTS local_auth_challenges (
  id TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  android_id_hash BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  code_attempts INTEGER NOT NULL DEFAULT 0,
  verified_at TIMESTAMPTZ,
  code_hash BYTEA,
  completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS local_auth_tickets (
  jti TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  android_id_hash BYTEA NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS local_auth_challenges_expiry ON local_auth_challenges(expires_at);
CREATE INDEX IF NOT EXISTS local_auth_tickets_expiry ON local_auth_tickets(expires_at);
