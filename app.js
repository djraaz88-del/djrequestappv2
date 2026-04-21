const express = require('express');
const path = require('path');
const session = require('express-session');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const QRCode = require('qrcode');
const db = require('./db');
const requireAuth = require('./middleware/requireAuth');
const requireAdmin = require('./middleware/requireAdmin');
const { verifyLogin, findUserById, hashPassword } = require('./auth');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false,
  saveUninitialized: false,
  name: 'djrequest.sid',
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProduction,
    maxAge: 1000 * 60 * 60 * 12
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Try again later.'
});

const guestRequestLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests. Please try again shortly.'
});

app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

app.use((req, res, next) => {
  if (req.session.user?.id) {
    const freshUser = findUserById(req.session.user.id);
    if (!freshUser || !freshUser.is_enabled) {
      req.session.destroy(() => {});
      res.locals.currentUser = null;
      return next();
    }
    req.session.user = {
      id: freshUser.id,
      username: freshUser.username,
      displayName: freshUser.display_name,
      djSlug: freshUser.dj_slug,
      role: freshUser.role
    };
    res.locals.currentUser = req.session.user;
  }
  next();
});

function getDjSettings(userId) {
  return db.prepare('SELECT * FROM dj_settings WHERE user_id = ?').get(userId);
}

function listDjsWithCounts() {
  return db.prepare(`
    SELECT
      u.*,
      COALESCE(SUM(CASE WHEN r.played = 0 THEN 1 ELSE 0 END), 0) AS open_request_count,
      COALESCE(COUNT(r.id), 0) AS total_request_count
    FROM users u
    LEFT JOIN requests r ON r.user_id = u.id
    WHERE u.role = 'dj'
    GROUP BY u.id
    ORDER BY u.display_name COLLATE NOCASE
  `).all();
}

app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.role === 'admin') return res.redirect('/admin');
  return res.redirect('/dashboard');
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('login', { error: null });
});

app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = await verifyLogin(username, password);
  if (!user) return res.status(401).render('login', { error: 'Invalid username or password.' });

  req.session.user = {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    djSlug: user.dj_slug,
    role: user.role
  };

  return res.redirect('/');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  if (req.session.user.role === 'admin') return res.redirect('/admin');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  const settings = getDjSettings(req.session.user.id);
  res.render('dashboard', { user, settings });
});

app.get('/kiosk', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.redirect('/admin');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  const settings = getDjSettings(req.session.user.id);
  res.render('kiosk', { user, settings });
});

app.get('/dj-view', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.redirect('/admin');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  const settings = getDjSettings(req.session.user.id);
  res.render('dj-view', { user, settings });
});

app.post('/session/start-guest-requests', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.redirect('/admin');
  const now = new Date().toISOString();
  db.prepare('UPDATE users SET is_live = 1, updated_at = ? WHERE id = ?').run(now, req.session.user.id);
  res.redirect('/dashboard');
});

app.post('/session/stop-guest-requests', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.redirect('/admin');
  const now = new Date().toISOString();
  db.prepare('UPDATE users SET is_live = 0, updated_at = ? WHERE id = ?').run(now, req.session.user.id);
  res.redirect('/dashboard');
});

app.get('/settings', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.redirect('/admin');
  const settings = getDjSettings(req.session.user.id);
  res.render('settings', { settings, saved: false });
});

app.post('/settings', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.redirect('/admin');
  const { youtube_api_key, search_url_1, search_url_2 } = req.body;
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE dj_settings
    SET youtube_api_key = ?, search_url_1 = ?, search_url_2 = ?, updated_at = ?
    WHERE user_id = ?
  `).run(youtube_api_key || '', search_url_1 || '', search_url_2 || '', now, req.session.user.id);

  const settings = getDjSettings(req.session.user.id);
  res.render('settings', { settings, saved: true });
});

app.get('/admin', requireAdmin, (req, res) => {
  const djs = listDjsWithCounts();
  res.render('admin', { djs });
});

app.get('/admin/users/new', requireAdmin, (req, res) => {
  res.render('admin-user-form', {
    title: 'Create DJ',
    user: null,
    settings: { youtube_api_key: '', search_url_1: '', search_url_2: '' },
    error: null,
    isEdit: false
  });
});

app.post('/admin/users/new', requireAdmin, async (req, res) => {
  const { username, password, display_name, dj_slug, youtube_api_key, search_url_1, search_url_2 } = req.body;
  const now = new Date().toISOString();

  if (!username || !password || !display_name || !dj_slug) {
    return res.status(400).render('admin-user-form', {
      title: 'Create DJ',
      user: req.body,
      settings: req.body,
      error: 'Username, password, display name, and slug are required.',
      isEdit: false
    });
  }

  try {
    const passwordHash = await hashPassword(password);
    const result = db.prepare(`
      INSERT INTO users (username, password_hash, display_name, dj_slug, role, is_live, is_enabled, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'dj', 0, 1, ?, ?)
    `).run(username.trim(), passwordHash, display_name.trim(), dj_slug.trim(), now, now);

    db.prepare(`
      INSERT INTO dj_settings (user_id, youtube_api_key, search_url_1, search_url_2, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(result.lastInsertRowid, youtube_api_key || '', search_url_1 || '', search_url_2 || '', now, now);

    return res.redirect('/admin');
  } catch (error) {
    return res.status(400).render('admin-user-form', {
      title: 'Create DJ',
      user: req.body,
      settings: req.body,
      error: 'Could not create DJ. Username or slug may already exist.',
      isEdit: false
    });
  }
});

app.get('/admin/users/:id/edit', requireAdmin, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'dj'").get(req.params.id);
  if (!user) return res.status(404).send('DJ not found');

  const settings = getDjSettings(user.id);
  res.render('admin-user-form', {
    title: 'Edit DJ',
    user,
    settings,
    error: null,
    isEdit: true
  });
});

app.post('/admin/users/:id/edit', requireAdmin, async (req, res) => {
  const existingUser = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'dj'").get(req.params.id);
  if (!existingUser) return res.status(404).send('DJ not found');

  const { username, display_name, dj_slug, youtube_api_key, search_url_1, search_url_2, password } = req.body;
  const now = new Date().toISOString();

  if (!username || !display_name || !dj_slug) {
    return res.status(400).render('admin-user-form', {
      title: 'Edit DJ',
      user: { ...existingUser, ...req.body },
      settings: req.body,
      error: 'Username, display name, and slug are required.',
      isEdit: true
    });
  }

  try {
    db.prepare(`
      UPDATE users
      SET username = ?, display_name = ?, dj_slug = ?, updated_at = ?
      WHERE id = ?
    `).run(username.trim(), display_name.trim(), dj_slug.trim(), now, existingUser.id);

    if (password && password.trim()) {
      const passwordHash = await hashPassword(password.trim());
      db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').run(passwordHash, now, existingUser.id);
    }

    db.prepare(`
      UPDATE dj_settings
      SET youtube_api_key = ?, search_url_1 = ?, search_url_2 = ?, updated_at = ?
      WHERE user_id = ?
    `).run(youtube_api_key || '', search_url_1 || '', search_url_2 || '', now, existingUser.id);

    return res.redirect('/admin');
  } catch (error) {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(existingUser.id);
    const settings = getDjSettings(existingUser.id);
    return res.status(400).render('admin-user-form', {
      title: 'Edit DJ',
      user: { ...user, ...req.body },
      settings: { ...settings, ...req.body },
      error: 'Could not update DJ. Username or slug may already exist.',
      isEdit: true
    });
  }
});

app.post('/admin/users/:id/toggle-enabled', requireAdmin, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'dj'").get(req.params.id);
  if (!user) return res.status(404).send('DJ not found');

  const now = new Date().toISOString();
  const newEnabled = user.is_enabled ? 0 : 1;
  const newLive = newEnabled ? user.is_live : 0;

  db.prepare('UPDATE users SET is_enabled = ?, is_live = ?, updated_at = ? WHERE id = ?')
    .run(newEnabled, newLive, now, user.id);

  res.redirect('/admin');
});

app.post('/admin/users/:id/stop-live', requireAdmin, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE id = ? AND role = 'dj'").get(req.params.id);
  if (!user) return res.status(404).send('DJ not found');

  const now = new Date().toISOString();
  db.prepare('UPDATE users SET is_live = 0, updated_at = ? WHERE id = ?').run(now, user.id);
  res.redirect('/admin');
});

app.get('/guest/:slug', (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE dj_slug = ? AND role = 'dj'").get(req.params.slug);
  if (!user || !user.is_enabled) return res.status(404).send('DJ not found');
  if (!user.is_live) return res.render('guest-inactive', { user });

  const settings = getDjSettings(user.id);
  const requests = db.prepare(`
    SELECT * FROM requests
    WHERE user_id = ?
    ORDER BY datetime(added_at) DESC
    LIMIT 20
  `).all(user.id);

  res.render('guest', { user, settings, requests });
});

app.get('/guest/:slug/qr', async (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE dj_slug = ? AND role = 'dj'").get(req.params.slug);
  if (!user || !user.is_enabled) return res.status(404).send('DJ not found');

  const host = `${req.protocol}://${req.get('host')}`;
  const guestUrl = `${host}/guest/${user.dj_slug}`;
  const qrDataUrl = await QRCode.toDataURL(guestUrl);

  res.render('qr', { user, guestUrl, qrDataUrl });
});

app.get('/api/requests', requireAuth, (req, res) => {
  const requests = db.prepare(`
    SELECT * FROM requests
    WHERE user_id = ?
    ORDER BY played ASC, datetime(added_at) ASC
  `).all(req.session.user.id);

  res.json(requests);
});

app.post('/api/requests', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.status(403).json({ error: 'Forbidden' });

  const now = new Date().toISOString();
  const { video_id, raw_title, song_name, artist_name, channel_title, requested_from = 'kiosk' } = req.body;

  const result = db.prepare(`
    INSERT INTO requests (user_id, video_id, raw_title, song_name, artist_name, channel_title, added_at, played, requested_from)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
  `).run(req.session.user.id, video_id || '', raw_title || '', song_name || '', artist_name || '', channel_title || '', now, requested_from);

  res.status(201).json({ id: result.lastInsertRowid });
});

app.patch('/api/requests/:id', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.status(403).json({ error: 'Forbidden' });
  const request = db.prepare('SELECT * FROM requests WHERE id = ? AND user_id = ?').get(req.params.id, req.session.user.id);
  if (!request) return res.status(404).json({ error: 'Request not found' });

  db.prepare('UPDATE requests SET played = ? WHERE id = ?').run(req.body.played ? 1 : 0, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/requests/:id', requireAuth, (req, res) => {
  if (req.session.user.role !== 'dj') return res.status(403).json({ error: 'Forbidden' });
  db.prepare('DELETE FROM requests WHERE id = ? AND user_id = ?').run(req.params.id, req.session.user.id);
  res.json({ ok: true });
});

app.get('/api/guest/:slug/requests-preview', (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE dj_slug = ? AND role = 'dj'").get(req.params.slug);
  if (!user || !user.is_enabled) {
    return res.status(404).json({ error: 'DJ not found' });
  }

  const requests = db.prepare(`
    SELECT *
    FROM requests
    WHERE user_id = ?
    ORDER BY datetime(added_at) DESC
    LIMIT 20
  `).all(user.id);

  res.json(requests);
});

app.post('/api/guest/:slug/requests', guestRequestLimiter, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE dj_slug = ? AND role = 'dj'").get(req.params.slug);
  if (!user || !user.is_enabled || !user.is_live) return res.status(403).json({ error: 'Guest requests are closed' });

  const now = new Date().toISOString();
  const { video_id, raw_title, song_name, artist_name, channel_title } = req.body;

  const result = db.prepare(`
    INSERT INTO requests (user_id, video_id, raw_title, song_name, artist_name, channel_title, added_at, played, requested_from)
    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'guest')
  `).run(user.id, video_id || '', raw_title || '', song_name || '', artist_name || '', channel_title || '', now);

  res.status(201).json({ id: result.lastInsertRowid });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Server error');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
