const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const dir = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dir, { recursive: true });
const db = new Database(path.join(dir, 'app.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  name TEXT NOT NULL, pass_hash TEXT NOT NULL, verified INTEGER DEFAULT 0, created_at INTEGER, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS codes(email TEXT PRIMARY KEY, code_hash TEXT, expires INTEGER, attempts INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS chats(
  id INTEGER PRIMARY KEY, type TEXT NOT NULL, title TEXT, owner_id INTEGER, is_public INTEGER DEFAULT 0, created_at INTEGER);
CREATE TABLE IF NOT EXISTS members(
  chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  role TEXT DEFAULT 'member', PRIMARY KEY(chat_id,user_id));
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY, chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE, sender_id INTEGER,
  text TEXT, file_url TEXT, file_name TEXT, reply_to INTEGER, edited INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0, created_at INTEGER);
CREATE INDEX IF NOT EXISTS idx_msg_chat ON messages(chat_id,id);
CREATE TABLE IF NOT EXISTS reads(chat_id INTEGER, user_id INTEGER, last_read INTEGER DEFAULT 0, PRIMARY KEY(chat_id,user_id));
`);
module.exports = db;
