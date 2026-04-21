const bcrypt = require('bcrypt');
const db = require('./db');

function findUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function findUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

async function verifyLogin(username, password) {
  const user = findUserByUsername(username);
  if (!user || !user.is_enabled) return null;
  const ok = await bcrypt.compare(password, user.password_hash);
  return ok ? user : null;
}

async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

module.exports = { findUserByUsername, findUserById, verifyLogin, hashPassword };
