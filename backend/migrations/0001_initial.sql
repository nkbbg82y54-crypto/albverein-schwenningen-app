PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admins (
  email TEXT PRIMARY KEY COLLATE NOCASE,
  display_name TEXT NOT NULL,
  role_label TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_permissions (
  admin_email TEXT NOT NULL COLLATE NOCASE,
  permission TEXT NOT NULL,
  granted_at TEXT NOT NULL,
  granted_by TEXT,
  PRIMARY KEY (admin_email, permission),
  FOREIGN KEY (admin_email) REFERENCES admins(email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS content_items (
  id TEXT PRIMARY KEY,
  resource_type TEXT NOT NULL CHECK (resource_type IN ('events', 'notices', 'board', 'gallery')),
  payload_json TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  published INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_content_public
  ON content_items(resource_type, published, sort_order, updated_at);

CREATE TABLE IF NOT EXISTS change_requests (
  id TEXT PRIMARY KEY,
  request_type TEXT NOT NULL CHECK (request_type IN ('address', 'bank')),
  encrypted_payload TEXT NOT NULL,
  encryption_iv TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'in_progress', 'completed', 'deleted')),
  notification_status TEXT NOT NULL DEFAULT 'pending' CHECK (notification_status IN ('pending', 'sent', 'failed', 'disabled')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  completed_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_change_requests_inbox
  ON change_requests(status, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  actor_email TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  details_json TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
  ON audit_log(created_at DESC);

-- Die drei Admin-Adressen werden bewusst nicht im öffentlichen Repository
-- gespeichert. Sie werden nach dem Deployment direkt in D1 eingetragen.
