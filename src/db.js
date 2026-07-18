import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'reestr.db');

export const db = new DatabaseSync(dbPath);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    phone         TEXT,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS capsules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token         TEXT UNIQUE,
    title         TEXT NOT NULL,
    content_text  TEXT NOT NULL DEFAULT '',
    video_link    TEXT,
    access_status TEXT NOT NULL DEFAULT 'locked' CHECK (access_status IN ('locked','open')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS trusted_contacts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    capsule_id    INTEGER NOT NULL REFERENCES capsules(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    phone         TEXT NOT NULL,
    token         TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','revoked')),
    blocked_until TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS otp_codes (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    trusted_contact_id INTEGER NOT NULL REFERENCES trusted_contacts(id) ON DELETE CASCADE,
    code_hash          TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    attempts           INTEGER NOT NULL DEFAULT 0,
    used               INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sms_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    phone      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type TEXT NOT NULL,
    actor_id   INTEGER,
    action     TEXT NOT NULL,
    details    TEXT,
    ip         TEXT,
    user_agent TEXT,
    timestamp  TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Миграция для БД, созданных до появления публичной ссылки капсулы.
{
  const cols = db.prepare(`PRAGMA table_info(capsules)`).all().map((c) => c.name);
  if (!cols.includes('token')) {
    db.exec(`ALTER TABLE capsules ADD COLUMN token TEXT`);
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_capsules_token ON capsules(token)`);
  }
  const fill = db.prepare(`UPDATE capsules SET token = ? WHERE id = ?`);
  for (const row of db.prepare(`SELECT id FROM capsules WHERE token IS NULL`).all()) {
    fill.run(crypto.randomUUID(), row.id);
  }
}

export function audit(req, actorType, actorId, action, details = null) {
  db.prepare(
    `INSERT INTO audit_log (actor_type, actor_id, action, details, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).run(
    actorType,
    actorId,
    action,
    details,
    req.ip || null,
    req.get?.('user-agent') || null
  );
}
