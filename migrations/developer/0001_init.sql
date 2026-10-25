PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  legal_name TEXT NOT NULL,
  team_type TEXT NOT NULL DEFAULT 'individual',
  role TEXT NOT NULL DEFAULT 'Account Holder',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_teams_owner ON teams(owner_id);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS apps (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT 'masOS',
  sku TEXT,
  status TEXT NOT NULL DEFAULT 'development',
  description TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT,
  UNIQUE(team_id, bundle_id)
);
CREATE INDEX IF NOT EXISTS idx_apps_team_created ON apps(team_id, created_at);

CREATE TABLE IF NOT EXISTS identifiers (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  identifier TEXT NOT NULL,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'explicit',
  capabilities TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  UNIQUE(team_id, identifier)
);
CREATE INDEX IF NOT EXISTS idx_identifiers_team_created ON identifiers(team_id, created_at);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT 'masOS',
  udid TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'enabled',
  created_at TEXT NOT NULL,
  UNIQUE(team_id, udid)
);
CREATE INDEX IF NOT EXISTS idx_devices_team_created ON devices(team_id, created_at);

CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY,
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  build TEXT NOT NULL,
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'draft',
  created_at TEXT NOT NULL,
  updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_submissions_team_created ON submissions(team_id, created_at);
