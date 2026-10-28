const express = require('express'), http = require('http'), path = require('path'), fs = require('fs'), crypto = require('crypto');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs'), multer = require('multer'), nodemailer = require('nodemailer');
const db = require('./db');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (process.env.NODE_ENV === 'production' && SECRET === 'dev-secret-change-me') { console.error('Set JWT_SECRET!'); process.exit(1); }
const PORT = process.env.PORT || 3000;
const UP = path.join(process.env.DATA_DIR || path.join(__dirname, 'data'), 'uploads');
fs.mkdirSync(UP, { recursive: true });

// ---- mail (anti-fake: every account needs a verified e-mail) ----
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({
  host: process.env.SMTP_HOST, port: +process.env.SMTP_PORT || 587,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } }) : null;
const sendCode = async (email, code) => {
  if (process.env.BREVO_API_KEY) { // HTTPS API (works on Render free, where SMTP ports are blocked)
    const r = await fetch('https://api.brevo.com/v3/smtp/email', { method: 'POST',
      headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json' },
      body: JSON.stringify({ sender: { email: process.env.MAIL_FROM_EMAIL, name: 'TgClone' }, to: [{ email }],
        subject: 'Код подтверждения', textContent: `Ваш код: ${code} (действует 10 минут)` }) });
    if (!r.ok) throw new Error('Brevo ' + r.status + ' ' + await r.text());
    return;
  }
  if (!mailer) return console.log(`[DEV] code for ${email}: ${code}`);
  await mailer.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to: email, subject: 'Код подтверждения', text: `Ваш код: ${code} (действует 10 минут)` });
};
const DISPOSABLE = ['mailinator.com','10minutemail.com','guerrillamail.com','tempmail.com','yopmail.com','trashmail.com','sharklasers.com'];
const hash = s => crypto.createHash('sha256').update(s + SECRET).digest('hex');

// ---- helpers ----
const hits = new Map();
const limit = (max, ms) => (req, res, next) => {
  const k = req.ip + req.path, now = Date.now(), a = (hits.get(k) || []).filter(t => now - t < ms);
  if (a.length >= max) return res.status(429).json({ error: 'Слишком много запросов, подождите' });
  a.push(now); hits.set(k, a); next();
};
const sign = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
const pub = u => u && ({ id: u.id, username: u.username, name: u.name, last_seen: u.last_seen, bio: u.bio, avatar: u.avatar });
const auth = (req, res, next) => {
  try { const { id } = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id=? AND verified=1').get(id);
    if (!u) throw 0; req.user = u; next();
  } catch { res.status(401).json({ error: 'Требуется вход' }); }
};
const member = (chatId, userId) => db.prepare('SELECT * FROM members WHERE chat_id=? AND user_id=?').get(chatId, userId);
const getMsg = id => {
  const m = db.prepare(`SELECT m.*, u.name sender_name, u.username sender_username FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.id=?`).get(id);
  if (m && m.deleted) { m.text = ''; m.file_url = null; m.file_name = null; }
  if (m) m.reactions = db.prepare('SELECT emoji, COUNT(*) n, GROUP_CONCAT(user_id) users FROM reactions WHERE msg_id=? GROUP BY emoji').all(id);
  if (m && m.reply_to) { const r = db.prepare('SELECT m.id,m.text,m.deleted,u.name sender_name FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.id=?').get(m.reply_to);
    m.reply = r && { id: r.id, text: r.deleted ? 'Сообщение удалено' : (r.text || '📎 Файл'), sender_name: r.sender_name }; }
  return m;
};

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 1e6 });
app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/uploads', express.static(UP, { setHeaders: r => r.setHeader('X-Content-Type-Options', 'nosniff') }));

// ---- auth ----
app.post('/api/register', limit(10, 3600e3), async (req, res) => {
  let { email, username, name, password } = req.body || {};
  email = String(email || '').trim().toLowerCase(); username = String(username || '').trim(); name = String(name || '').trim();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Неверный e-mail' });
  if (DISPOSABLE.includes(email.split('@')[1])) return res.status(400).json({ error: 'Одноразовые e-mail запрещены' });
  if (!/^[a-z0-9_]{3,20}$/i.test(username)) return res.status(400).json({ error: 'Username: 3-20 символов, латиница/цифры/_' });
  if (!name || name.length > 40) return res.status(400).json({ error: 'Укажите имя (до 40 символов)' });
  if (String(password || '').length < 8) return res.status(400).json({ error: 'Пароль минимум 8 символов' });
  const ex = db.prepare('SELECT * FROM users WHERE email=? OR username=?').all(email, username);
  if (ex.some(u => u.verified)) return res.status(409).json({ error: 'E-mail или username уже заняты' });
  db.prepare('DELETE FROM users WHERE verified=0 AND (email=? OR username=?)').run(email, username);
  db.prepare('INSERT INTO users(email,username,name,pass_hash,created_at) VALUES(?,?,?,?,?)').run(email, username, name, bcrypt.hashSync(password, 10), Date.now());
  const code = String(crypto.randomInt(100000, 1000000));
  db.prepare('INSERT OR REPLACE INTO codes VALUES(?,?,?,0)').run(email, hash(code), Date.now() + 600e3);
  try { await sendCode(email, code); res.json({ ok: true }); } catch (e) { console.error(e); res.status(500).json({ error: 'Не удалось отправить письмо' }); }
});
app.post('/api/verify', limit(20, 3600e3), (req, res) => {
  const email = String(req.body.email || '').toLowerCase(), c = db.prepare('SELECT * FROM codes WHERE email=?').get(email);
  if (!c || c.expires < Date.now() || c.attempts >= 5) return res.status(400).json({ error: 'Код недействителен, зарегистрируйтесь заново' });
  if (c.code_hash !== hash(String(req.body.code || '').trim())) { db.prepare('UPDATE codes SET attempts=attempts+1 WHERE email=?').run(email); return res.status(400).json({ error: 'Неверный код' }); }
  db.prepare('UPDATE users SET verified=1 WHERE email=?').run(email); db.prepare('DELETE FROM codes WHERE email=?').run(email);
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  res.json({ token: sign(u), user: pub(u) });
});
app.post('/api/login', limit(20, 900e3), (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE (email=? OR username=?) AND verified=1').get(String(req.body.login || '').toLowerCase(), String(req.body.login || ''));
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.pass_hash)) return res.status(401).json({ error: 'Неверный логин или пароль' });
  res.json({ token: sign(u), user: pub(u) });
});
app.get('/api/me', auth, (req, res) => res.json(pub(req.user)));

app.post('/api/profile', auth, (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 40) || req.user.name, bio = String(req.body.bio || '').slice(0, 200);
  let av = req.body.avatar; if (av && !/^\/uploads\/[\w.]+$/.test(av)) av = null;
  db.prepare('UPDATE users SET name=?,bio=?,avatar=? WHERE id=?').run(name, bio, av || null, req.user.id);
  res.json(pub(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id)));
});
app.post('/api/forgot', limit(5, 3600e3), async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (db.prepare('SELECT id FROM users WHERE email=? AND verified=1').get(email)) {
    const code = String(crypto.randomInt(100000, 1000000));
    db.prepare('INSERT OR REPLACE INTO codes VALUES(?,?,?,0)').run('reset:' + email, hash(code), Date.now() + 600e3);
    try { await sendCode(email, code); } catch (e) { console.error(e); }
  }
  res.json({ ok: true });
});
app.post('/api/reset', limit(20, 3600e3), (req, res) => {
  const email = String(req.body.email || '').toLowerCase(), k = 'reset:' + email, c = db.prepare('SELECT * FROM codes WHERE email=?').get(k);
  if (String(req.body.password || '').length < 8) return res.status(400).json({ error: 'Пароль минимум 8 символов' });
  if (!c || c.expires < Date.now() || c.attempts >= 5) return res.status(400).json({ error: 'Код недействителен' });
  if (c.code_hash !== hash(String(req.body.code || '').trim())) { db.prepare('UPDATE codes SET attempts=attempts+1 WHERE email=?').run(k); return res.status(400).json({ error: 'Неверный код' }); }
  db.prepare('UPDATE users SET pass_hash=? WHERE email=?').run(bcrypt.hashSync(req.body.password, 10), email); db.prepare('DELETE FROM codes WHERE email=?').run(k);
  res.json({ ok: true });
});

// ---- search / chats ----
app.get('/api/search', auth, (req, res) => {
  const q = String(req.query.q || '').replace(/^@/, '').trim(); if (q.length < 2) return res.json({ users: [], chats: [] });
  const like = `%${q.replace(/[%_]/g, '')}%`;
  res.json({
    users: db.prepare('SELECT id,username,name,last_seen FROM users WHERE verified=1 AND id!=? AND (username LIKE ? OR name LIKE ?) LIMIT 15').all(req.user.id, like, like),
    chats: db.prepare("SELECT id,type,title FROM chats WHERE is_public=1 AND title LIKE ? LIMIT 15").all(like) });
});
const chatView = (c, uid) => {
  const v = { id: c.id, type: c.type, title: c.title, role: c.role, is_public: c.is_public, unread: c.unread || 0 };
  if (c.type === 'private') { const p = db.prepare('SELECT u.* FROM members m JOIN users u ON u.id=m.user_id WHERE m.chat_id=? AND m.user_id!=?').get(c.id, uid); v.title = p ? p.name : 'Удалён'; v.peer = pub(p); }
  else v.members = db.prepare('SELECT COUNT(*) n FROM members WHERE chat_id=?').get(c.id).n;
  const l = db.prepare('SELECT id FROM messages WHERE chat_id=? ORDER BY id DESC LIMIT 1').get(c.id); v.last = l && getMsg(l.id); return v;
};
const listChat = (id, uid) => chatView(db.prepare(`SELECT c.*, mem.role, (SELECT COUNT(*) FROM messages m WHERE m.chat_id=c.id AND m.id>COALESCE(r.last_read,0) AND m.sender_id!=? AND m.deleted=0) unread
  FROM chats c JOIN members mem ON mem.chat_id=c.id AND mem.user_id=? LEFT JOIN reads r ON r.chat_id=c.id AND r.user_id=? WHERE c.id=?`).get(uid, uid, uid, id), uid);
app.get('/api/chats', auth, (req, res) => {
  const ids = db.prepare('SELECT chat_id FROM members WHERE user_id=?').all(req.user.id);
  res.json(ids.map(i => listChat(i.chat_id, req.user.id)).sort((a, b) => (b.last?.id || 0) - (a.last?.id || 0)));
});
const pushChat = (chatId, userIds) => userIds.forEach(id => { io.in('user:' + id).socketsJoin('chat:' + chatId); io.to('user:' + id).emit('chat:new', listChat(chatId, id)); });
app.post('/api/chats', auth, (req, res) => {
  const { type, userId, title, usernames, is_public } = req.body || {}, me = req.user.id;
  if (type === 'private') {
    const o = db.prepare('SELECT id FROM users WHERE id=? AND verified=1').get(+userId); if (!o || o.id === me) return res.status(400).json({ error: 'Неверный пользователь' });
    const ex = db.prepare(`SELECT c.id FROM chats c WHERE c.type='private' AND EXISTS(SELECT 1 FROM members WHERE chat_id=c.id AND user_id=?) AND EXISTS(SELECT 1 FROM members WHERE chat_id=c.id AND user_id=?)`).get(me, o.id);
    if (ex) return res.json(listChat(ex.id, me));
    const id = db.transaction(() => { const id = db.prepare("INSERT INTO chats(type,created_at) VALUES('private',?)").run(Date.now()).lastInsertRowid;
      [me, o.id].forEach(u => db.prepare('INSERT INTO members VALUES(?,?,?)').run(id, u, 'member')); return id; })();
    pushChat(id, [me, o.id]); return res.json(listChat(id, me));
  }
  if (!['group', 'channel'].includes(type) || !String(title || '').trim()) return res.status(400).json({ error: 'Нужны тип и название' });
  const others = (usernames || []).map(u => db.prepare('SELECT id FROM users WHERE username=? AND verified=1').get(String(u).replace('@', '').trim())).filter(Boolean).map(u => u.id);
  const id = db.transaction(() => { const id = db.prepare('INSERT INTO chats(type,title,owner_id,is_public,created_at) VALUES(?,?,?,?,?)').run(type, String(title).trim().slice(0, 60), me, is_public ? 1 : 0, Date.now()).lastInsertRowid;
    db.prepare('INSERT INTO members VALUES(?,?,?)').run(id, me, 'owner'); [...new Set(others)].filter(u => u !== me).forEach(u => db.prepare('INSERT INTO members VALUES(?,?,?)').run(id, u, 'member')); return id; })();
  pushChat(id, [me, ...others]); res.json(listChat(id, me));
});
app.post('/api/chats/:id/join', auth, (req, res) => {
  const c = db.prepare("SELECT * FROM chats WHERE id=? AND is_public=1 AND type!='private'").get(+req.params.id); if (!c) return res.status(404).json({ error: 'Не найдено' });
  db.prepare('INSERT OR IGNORE INTO members VALUES(?,?,?)').run(c.id, req.user.id, 'member'); pushChat(c.id, [req.user.id]); res.json(listChat(c.id, req.user.id));
});
app.post('/api/chats/:id/leave', auth, (req, res) => { db.prepare('DELETE FROM members WHERE chat_id=? AND user_id=?').run(+req.params.id, req.user.id); io.in('user:' + req.user.id).socketsLeave('chat:' + req.params.id); res.json({ ok: true }); });
app.get('/api/chats/:id/messages', auth, (req, res) => {
  if (!member(+req.params.id, req.user.id)) return res.status(403).json({ error: 'Нет доступа' });
  const before = +req.query.before || 9e15;
  const rows = db.prepare('SELECT id FROM messages WHERE chat_id=? AND id<? ORDER BY id DESC LIMIT 50').all(+req.params.id, before);
  res.json(rows.map(r => getMsg(r.id)).reverse());
});
app.get('/api/chats/:id/search', auth, (req, res) => {
  if (!member(+req.params.id, req.user.id)) return res.status(403).json({ error: 'Нет доступа' });
  const q = '%' + String(req.query.q || '').replace(/[%_]/g, '') + '%';
  res.json(db.prepare('SELECT id FROM messages WHERE chat_id=? AND deleted=0 AND text LIKE ? ORDER BY id DESC LIMIT 30').all(+req.params.id, q).map(r => getMsg(r.id)));
});
const upload = multer({ limits: { fileSize: 25e6 }, storage: multer.diskStorage({ destination: UP,
  filename: (r, f, cb) => cb(null, crypto.randomBytes(16).toString('hex') + path.extname(f.originalname).replace(/[^.\w]/g, '').slice(0, 10)) }) });
app.post('/api/upload', auth, limit(60, 3600e3), upload.single('file'), (req, res) => res.json({ url: '/uploads/' + req.file.filename, name: req.file.originalname }));

// ---- realtime ----
io.use((s, next) => { try { const { id } = jwt.verify(s.handshake.auth.token, SECRET); s.user = db.prepare('SELECT * FROM users WHERE id=? AND verified=1').get(id); next(s.user ? undefined : new Error('auth')); } catch { next(new Error('auth')); } });
io.on('connection', s => {
  const u = s.user; s.join('user:' + u.id);
  db.prepare('SELECT chat_id FROM members WHERE user_id=?').all(u.id).forEach(r => s.join('chat:' + r.chat_id));
  io.emit('presence', { userId: u.id, online: true });
  s.on('message:send', (d, ack) => {
    const m = member(+d.chatId, u.id), c = m && db.prepare('SELECT * FROM chats WHERE id=?').get(+d.chatId);
    if (!m) return ack?.({ error: 'Нет доступа' });
    if (c.type === 'channel' && !['owner', 'admin'].includes(m.role)) return ack?.({ error: 'В канал пишут только админы' });
    const text = String(d.text || '').trim().slice(0, 4000); if (!text && !d.fileUrl) return ack?.({ error: 'Пусто' });
    if (d.fileUrl && !/^\/uploads\/[\w.]+$/.test(d.fileUrl)) return ack?.({ error: 'Файл' });
    const id = db.prepare('INSERT INTO messages(chat_id,sender_id,text,file_url,file_name,reply_to,fwd_from,created_at) VALUES(?,?,?,?,?,?,?,?)')
      .run(c.id, u.id, text, d.fileUrl || null, d.fileName ? String(d.fileName).slice(0, 100) : null, d.replyTo || null, d.fwdFrom ? String(d.fwdFrom).slice(0, 60) : null, Date.now()).lastInsertRowid;
    io.to('chat:' + c.id).emit('message:new', getMsg(id)); ack?.({ ok: true });
  });
  s.on('message:edit', d => { const m = db.prepare('SELECT * FROM messages WHERE id=? AND sender_id=? AND deleted=0').get(+d.id, u.id); const t = String(d.text || '').trim().slice(0, 4000);
    if (m && t) { db.prepare('UPDATE messages SET text=?,edited=1 WHERE id=?').run(t, m.id); io.to('chat:' + m.chat_id).emit('message:update', getMsg(m.id)); } });
  s.on('message:delete', d => { const m = db.prepare('SELECT * FROM messages WHERE id=?').get(+d.id); const mm = m && member(m.chat_id, u.id);
    if (m && mm && (m.sender_id === u.id || ['owner', 'admin'].includes(mm.role))) { db.prepare('UPDATE messages SET deleted=1 WHERE id=?').run(m.id); io.to('chat:' + m.chat_id).emit('message:update', getMsg(m.id)); } });
  s.on('message:react', d => {
    const m = db.prepare('SELECT * FROM messages WHERE id=? AND deleted=0').get(+d.id); if (!m || !member(m.chat_id, u.id)) return;
    const e = String(d.emoji || '').slice(0, 8); if (!e) return;
    const x = db.prepare('SELECT emoji FROM reactions WHERE msg_id=? AND user_id=?').get(m.id, u.id);
    if (x && x.emoji === e) db.prepare('DELETE FROM reactions WHERE msg_id=? AND user_id=?').run(m.id, u.id);
    else db.prepare('INSERT OR REPLACE INTO reactions VALUES(?,?,?)').run(m.id, u.id, e);
    io.to('chat:' + m.chat_id).emit('message:update', getMsg(m.id));
  });
  s.on('message:pin', d => {
    const m = db.prepare('SELECT * FROM messages WHERE id=? AND deleted=0').get(+d.id), mm = m && member(m.chat_id, u.id), c = m && db.prepare('SELECT type FROM chats WHERE id=?').get(m.chat_id);
    if (!m || !mm || (c.type === 'channel' && !['owner', 'admin'].includes(mm.role))) return;
    db.prepare('UPDATE messages SET pinned=? WHERE id=?').run(m.pinned ? 0 : 1, m.id); io.to('chat:' + m.chat_id).emit('message:update', getMsg(m.id));
  });
  s.on('typing', d => member(+d.chatId, u.id) && s.to('chat:' + d.chatId).emit('typing', { chatId: +d.chatId, userId: u.id, name: u.name }));
  s.on('read', d => { if (!member(+d.chatId, u.id)) return; db.prepare('INSERT INTO reads VALUES(?,?,?) ON CONFLICT(chat_id,user_id) DO UPDATE SET last_read=MAX(last_read,excluded.last_read)').run(+d.chatId, u.id, +d.messageId || 0);
    s.to('chat:' + d.chatId).emit('read', { chatId: +d.chatId, userId: u.id, messageId: +d.messageId }); });
  s.on('disconnect', async () => { const left = (await io.in('user:' + u.id).fetchSockets()).length; if (!left) { db.prepare('UPDATE users SET last_seen=? WHERE id=?').run(Date.now(), u.id); io.emit('presence', { userId: u.id, online: false, last_seen: Date.now() }); } });
});
server.listen(PORT, () => console.log('http://localhost:' + PORT));
