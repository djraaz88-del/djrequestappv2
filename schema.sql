DROP TABLE IF EXISTS requests;
DROP TABLE IF EXISTS dj_settings;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT NOT NULL,
  dj_slug TEXT UNIQUE,
  role TEXT NOT NULL CHECK(role IN ('admin','dj')),
  is_live INTEGER NOT NULL DEFAULT 0,
  is_enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE dj_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  youtube_api_key TEXT DEFAULT '',
  search_url_1 TEXT DEFAULT '',
  search_url_2 TEXT DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  video_id TEXT DEFAULT '',
  raw_title TEXT DEFAULT '',
  song_name TEXT DEFAULT '',
  artist_name TEXT DEFAULT '',
  channel_title TEXT DEFAULT '',
  added_at TEXT NOT NULL,
  played INTEGER NOT NULL DEFAULT 0,
  requested_from TEXT NOT NULL DEFAULT 'kiosk',
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_requests_user_added ON requests(user_id, added_at);
CREATE INDEX idx_users_slug ON users(dj_slug);
