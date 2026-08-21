ALTER TABLE users ADD COLUMN google_id TEXT;
ALTER TABLE users ADD COLUMN avatar TEXT;
ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'password';

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);