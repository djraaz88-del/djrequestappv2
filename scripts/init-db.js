const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const db = require('../db');

const schemaPath = path.join(__dirname, '..', 'schema.sql');
db.exec(fs.readFileSync(schemaPath, 'utf8'));

const now = new Date().toISOString();

function createUser({ username, password, displayName, djSlug = null, role = 'dj' }) {
  const passwordHash = bcrypt.hashSync(password, 10);
  const result = db.prepare(`
    INSERT INTO users (username, password_hash, display_name, dj_slug, role, is_live, is_enabled, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?)
  `).run(username, passwordHash, displayName, djSlug, role, now, now);

  db.prepare(`
    INSERT INTO dj_settings (user_id, youtube_api_key, search_url_1, search_url_2, created_at, updated_at)
    VALUES (?, '', '', '', ?, ?)
  `).run(result.lastInsertRowid, now, now);
}

createUser({ username: 'admin', password: 'ChangeMe123!', displayName: 'Administrator', role: 'admin' });
createUser({ username: 'raaz', password: 'ChangeMe123!', displayName: 'DJ Raaz', djSlug: 'raaz', role: 'dj' });

console.log('Database reset complete.');
console.log('Admin login: admin / ChangeMe123!');
console.log('Demo DJ login: raaz / ChangeMe123!');
