PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS signing_certificates (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL,
  name TEXT NOT NULL,
  certificate_type TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  public_key TEXT NOT NULL,
  algorithm TEXT NOT NULL DEFAULT 'ECDSA-P256-SHA256',
  status TEXT NOT NULL DEFAULT 'active',
  expires_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(team_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_signing_certificates_team_created ON signing_certificates(team_id, created_at);

CREATE TABLE IF NOT EXISTS provisioning_profiles (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL,
  name TEXT NOT NULL,
  profile_type TEXT NOT NULL,
  app_identifier TEXT NOT NULL,
  certificate_ids TEXT NOT NULL DEFAULT '[]',
  device_ids TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  expires_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_profiles_team_created ON provisioning_profiles(team_id, created_at);
