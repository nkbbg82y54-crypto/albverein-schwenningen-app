CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL UNIQUE,
  subscription_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_updated
  ON push_subscriptions(updated_at DESC);

CREATE TABLE IF NOT EXISTS push_state (
  state_key TEXT PRIMARY KEY,
  notice_id TEXT,
  updated_at TEXT NOT NULL
);
