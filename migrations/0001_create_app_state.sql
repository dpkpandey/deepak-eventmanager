CREATE TABLE IF NOT EXISTS app_state (
  id TEXT PRIMARY KEY NOT NULL,
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_app_state_updated_at
  ON app_state(updated_at);