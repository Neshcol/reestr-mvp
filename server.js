import process from 'node:process';
import { fileURLToPath } from 'node:url';
try { process.loadEnvFile(fileURLToPath(new URL('.env', import.meta.url))); } catch { /* .env опционален — переменные могут прийти из окружения */ }
import express from 'express';
import path from 'node:path';
import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { db, audit } from './src/db.js';
import { normalizePhone, checkSmsRateLimit, sendSms } from './src/sms.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('JWT_SECRET не задан в .env');
  process.exit(1);
}

app.set('trust proxy', true);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------- Аутентификация владельца ----------

function ownerAuth(req, res, next) {
  const token = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'owner') throw new Error('wrong role');
    req.ownerId = payload.uid;
    next();
  } catch {
    res.status(401).json({ error: 'Требуется вход' });
  }
}

app.post('/api/register', (req, res) => {
  const { email, password, consent } = req.body || {};
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Некорректный email' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Пароль минимум 8 символов' });
  if (!consent) return res.status(400).json({ error: 'Необходимо согласие на обработку персональных данных' });

  const exists = db.prepare(`SELECT id FROM users WHERE email = ?`).get(email.toLowerCase());
  if (exists) return res.status(409).json({ error: 'Пользователь с таким email уже существует' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(`INSERT INTO users (email, password_hash) VALUES (?, ?)`).run(email.toLowerCase(), hash);
  audit(req, 'owner', Number(info.lastInsertRowid), 'register');
  const token = jwt.sign({ uid: Number(info.lastInsertRowid), role: 'owner' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, email: email.toLowerCase() });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get((email || '').toLowerCase());
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    audit(req, 'owner', user?.id ?? null, 'login_failed', email);
    return res.status(401).json({ error: 'Неверный email или пароль' });
  }
  audit(req, 'owner', user.id, 'login');
  const token = jwt.sign({ uid: user.id, role: 'owner' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, email: user.email });
});

// ---------- Капсулы ----------

app.get('/api/capsules', ownerAuth, (req, res) => {
  const capsules = db.prepare(
    `SELECT c.*,
       (SELECT COUNT(*) FROM trusted_contacts t WHERE t.capsule_id = c.id AND t.status != 'revoked') AS contacts_count
     FROM capsules c WHERE c.owner_id = ? ORDER BY c.created_at DESC`
  ).all(req.ownerId);
  res.json(capsules);
});

app.post('/api/capsules', ownerAuth, (req, res) => {
  const { title, content_text, video_link } = req.body || {};
  if (!title?.trim()) return res.status(400).json({ error: 'Укажите заголовок' });
  const info = db.prepare(
    `INSERT INTO capsules (owner_id, token, title, content_text, video_link) VALUES (?, ?, ?, ?, ?)`
  ).run(req.ownerId, crypto.randomUUID(), title.trim(), content_text || '', video_link || null);
  audit(req, 'owner', req.ownerId, 'capsule_created', `capsule:${info.lastInsertRowid}`);
  res.json(db.prepare(`SELECT * FROM capsules WHERE id = ?`).get(info.lastInsertRowid));
});

function getOwnCapsule(req, res) {
  const capsule = db.prepare(`SELECT * FROM capsules WHERE id = ? AND owner_id = ?`).get(Number(req.params.id), req.ownerId);
  if (!capsule) res.status(404).json({ error: 'Капсула не найдена' });
  return capsule;
}

app.put('/api/capsules/:id', ownerAuth, (req, res) => {
  const capsule = getOwnCapsule(req, res);
  if (!capsule) return;
  const { title, content_text, video_link } = req.body || {};
  db.prepare(`UPDATE capsules SET title = ?, content_text = ?, video_link = ? WHERE id = ?`).run(
    title?.trim() || capsule.title,
    content_text ?? capsule.content_text,
    video_link ?? capsule.video_link,
    capsule.id
  );
  audit(req, 'owner', req.ownerId, 'capsule_updated', `capsule:${capsule.id}`);
  res.json(db.prepare(`SELECT * FROM capsules WHERE id = ?`).get(capsule.id));
});

app.post('/api/capsules/:id/access', ownerAuth, (req, res) => {
  const capsule = getOwnCapsule(req, res);
  if (!capsule) return;
  const status = req.body?.status === 'open' ? 'open' : 'locked';
  db.prepare(`UPDATE capsules SET access_status = ? WHERE id = ?`).run(status, capsule.id);
  audit(req, 'owner', req.ownerId, status === 'open' ? 'access_opened' : 'access_locked', `capsule:${capsule.id}`);
  res.json({ id: capsule.id, access_status: status });
});

app.delete('/api/capsules/:id', ownerAuth, (req, res) => {
  const capsule = getOwnCapsule(req, res);
  if (!capsule) return;
  db.prepare(`DELETE FROM capsules WHERE id = ?`).run(capsule.id);
  audit(req, 'owner', req.ownerId, 'capsule_deleted', `capsule:${capsule.id}`);
  res.json({ ok: true });
});

// ---------- Доверенные лица ----------

app.get('/api/capsules/:id/contacts', ownerAuth, (req, res) => {
  const capsule = getOwnCapsule(req, res);
  if (!capsule) return;
  res.json(db.prepare(`SELECT * FROM trusted_contacts WHERE capsule_id = ? ORDER BY created_at DESC`).all(capsule.id));
});

app.post('/api/capsules/:id/contacts', ownerAuth, (req, res) => {
  const capsule = getOwnCapsule(req, res);
  if (!capsule) return;
  const { name, phone } = req.body || {};
  const normPhone = normalizePhone(phone);
  if (!name?.trim()) return res.status(400).json({ error: 'Укажите имя' });
  if (!normPhone) return res.status(400).json({ error: 'Некорректный номер телефона' });
  const token = crypto.randomUUID();
  const info = db.prepare(
    `INSERT INTO trusted_contacts (owner_id, capsule_id, name, phone, token) VALUES (?, ?, ?, ?, ?)`
  ).run(req.ownerId, capsule.id, name.trim(), normPhone, token);
  audit(req, 'owner', req.ownerId, 'contact_added', `contact:${info.lastInsertRowid} capsule:${capsule.id}`);
  res.json(db.prepare(`SELECT * FROM trusted_contacts WHERE id = ?`).get(info.lastInsertRowid));
});

app.post('/api/contacts/:id/revoke', ownerAuth, (req, res) => {
  const contact = db.prepare(`SELECT * FROM trusted_contacts WHERE id = ? AND owner_id = ?`).get(Number(req.params.id), req.ownerId);
  if (!contact) return res.status(404).json({ error: 'Не найдено' });
  const newStatus = contact.status === 'revoked' ? 'pending' : 'revoked';
  db.prepare(`UPDATE trusted_contacts SET status = ? WHERE id = ?`).run(newStatus, contact.id);
  audit(req, 'owner', req.ownerId, newStatus === 'revoked' ? 'contact_revoked' : 'contact_restored', `contact:${contact.id}`);
  res.json({ id: contact.id, status: newStatus });
});

app.delete('/api/contacts/:id', ownerAuth, (req, res) => {
  const contact = db.prepare(`SELECT * FROM trusted_contacts WHERE id = ? AND owner_id = ?`).get(Number(req.params.id), req.ownerId);
  if (!contact) return res.status(404).json({ error: 'Не найдено' });
  db.prepare(`DELETE FROM trusted_contacts WHERE id = ?`).run(contact.id);
  audit(req, 'owner', req.ownerId, 'contact_deleted', `contact:${contact.id}`);
  res.json({ ok: true });
});

// ---------- Журнал ----------

app.get('/api/audit', ownerAuth, (req, res) => {
  const rows = db.prepare(
    `SELECT * FROM audit_log
     WHERE (actor_type = 'owner' AND actor_id = ?)
        OR (actor_type = 'trusted_contact' AND actor_id IN (SELECT id FROM trusted_contacts WHERE owner_id = ?))
     ORDER BY timestamp DESC, id DESC LIMIT 200`
  ).all(req.ownerId, req.ownerId);
  res.json(rows);
});

// ---------- Публичный доступ по единой ссылке капсулы ----------

app.get('/capsule/:uuid', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'capsule.html'));
});

function findCapsuleByToken(uuid) {
  return db.prepare(`SELECT * FROM capsules WHERE token = ?`).get(uuid);
}

function findContactByPhone(capsuleId, phone) {
  return db.prepare(
    `SELECT * FROM trusted_contacts WHERE capsule_id = ? AND phone = ? AND status != 'revoked'`
  ).get(capsuleId, phone);
}

function isBlocked(contact) {
  return contact.blocked_until && contact.blocked_until > new Date().toISOString().slice(0, 19).replace('T', ' ');
}

// Rate limit по IP: не более 10 проверок номера в час (считаем по audit_log).
function ipCheckAllowed(ip) {
  const n = db.prepare(
    `SELECT COUNT(*) AS n FROM audit_log
     WHERE ip = ? AND action IN ('phone_check_fail', 'phone_check_ok')
       AND timestamp > datetime('now', '-1 hour')`
  ).get(ip).n;
  return n < 10;
}

// Одинаковая задержка ответа независимо от результата проверки номера —
// защита от определения списка номеров по времени ответа.
const PHONE_CHECK_MIN_MS = 800;
function padDelay(startedAt) {
  const left = PHONE_CHECK_MIN_MS - (Date.now() - startedAt);
  return left > 0 ? new Promise((r) => setTimeout(r, left)) : Promise.resolve();
}

// Шаг 1+2: проверка номера по списку капсулы и отправка SMS-кода.
app.post('/api/capsule/:uuid/request-code', async (req, res) => {
  const startedAt = Date.now();
  const capsule = findCapsuleByToken(req.params.uuid);
  if (!capsule) {
    await padDelay(startedAt);
    return res.status(404).json({ error: 'Ссылка недействительна' });
  }

  if (!ipCheckAllowed(req.ip)) {
    audit(req, 'trusted_contact', null, 'phone_check_rate_limited', `capsule:${capsule.id}`);
    await padDelay(startedAt);
    return res.status(429).json({ error: 'Слишком много попыток с вашего адреса. Попробуйте через час' });
  }

  const { phone, consent } = req.body || {};
  if (!consent) {
    await padDelay(startedAt);
    return res.status(400).json({ error: 'Необходимо согласие на обработку персональных данных' });
  }
  const normPhone = normalizePhone(phone);
  const contact = normPhone ? findContactByPhone(capsule.id, normPhone) : null;

  if (!contact) {
    audit(req, 'trusted_contact', null, 'phone_check_fail', `capsule:${capsule.id} phone:${normPhone || phone}`);
    await padDelay(startedAt);
    return res.status(404).json({ error: 'Номер не найден в базе доступа' });
  }
  audit(req, 'trusted_contact', contact.id, 'phone_check_ok', `capsule:${capsule.id} phone:${normPhone}`);

  if (isBlocked(contact)) {
    await padDelay(startedAt);
    return res.status(429).json({ error: 'Слишком много неверных попыток. Повторите через 15 минут' });
  }

  const rate = checkSmsRateLimit(normPhone);
  if (!rate.ok) {
    audit(req, 'trusted_contact', contact.id, 'sms_rate_limited', `phone:${normPhone}`);
    await padDelay(startedAt);
    return res.status(429).json({ error: rate.reason });
  }

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  db.prepare(`UPDATE otp_codes SET used = 1 WHERE trusted_contact_id = ? AND used = 0`).run(contact.id);
  db.prepare(
    `INSERT INTO otp_codes (trusted_contact_id, code_hash, expires_at)
     VALUES (?, ?, datetime('now', '+5 minutes'))`
  ).run(contact.id, sha256(code));

  const sent = await sendSms(normPhone, code);
  if (!sent.ok) {
    await padDelay(startedAt);
    return res.status(502).json({ error: 'Не удалось отправить SMS. Попробуйте позже' });
  }

  audit(req, 'trusted_contact', contact.id, 'otp_sent', `phone:${normPhone}`);
  await padDelay(startedAt);
  res.json({ ok: true, test: !!sent.test });
});

// Шаг 2: проверка кода.
app.post('/api/capsule/:uuid/verify', (req, res) => {
  const capsule = findCapsuleByToken(req.params.uuid);
  if (!capsule) return res.status(404).json({ error: 'Ссылка недействительна' });

  const normPhone = normalizePhone(req.body?.phone);
  const contact = normPhone ? findContactByPhone(capsule.id, normPhone) : null;
  if (!contact) return res.status(404).json({ error: 'Номер не найден в базе доступа' });

  if (isBlocked(contact)) {
    audit(req, 'trusted_contact', contact.id, 'otp_fail', `blocked phone:${normPhone}`);
    return res.status(429).json({ error: 'Слишком много неверных попыток. Повторите через 15 минут' });
  }

  const code = String(req.body?.code || '').trim();
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Код — 6 цифр' });

  const otp = db.prepare(
    `SELECT * FROM otp_codes
     WHERE trusted_contact_id = ? AND used = 0 AND expires_at > datetime('now')
     ORDER BY id DESC LIMIT 1`
  ).get(contact.id);

  if (!otp) {
    audit(req, 'trusted_contact', contact.id, 'otp_fail', `no_active_code phone:${normPhone}`);
    return res.status(400).json({ error: 'Код истёк или не был запрошен. Запросите новый' });
  }

  if (otp.code_hash !== sha256(code)) {
    const attempts = otp.attempts + 1;
    db.prepare(`UPDATE otp_codes SET attempts = ? WHERE id = ?`).run(attempts, otp.id);
    audit(req, 'trusted_contact', contact.id, 'otp_fail', `attempt:${attempts} phone:${normPhone}`);
    if (attempts >= 5) {
      db.prepare(`UPDATE otp_codes SET used = 1 WHERE id = ?`).run(otp.id);
      db.prepare(`UPDATE trusted_contacts SET blocked_until = datetime('now', '+15 minutes') WHERE id = ?`).run(contact.id);
      audit(req, 'trusted_contact', contact.id, 'otp_fail', `blocked_15min phone:${normPhone}`);
      return res.status(429).json({ error: 'Превышено число попыток. Доступ заблокирован на 15 минут' });
    }
    return res.status(400).json({ error: `Неверный код. Осталось попыток: ${5 - attempts}` });
  }

  db.prepare(`UPDATE otp_codes SET used = 1 WHERE id = ?`).run(otp.id);
  db.prepare(`UPDATE trusted_contacts SET status = 'verified' WHERE id = ?`).run(contact.id);
  audit(req, 'trusted_contact', contact.id, 'otp_ok', `phone:${normPhone}`);

  const token = jwt.sign({ cid: contact.id, role: 'trusted_contact' }, JWT_SECRET, { expiresIn: '20m' });
  res.json({ token });
});

// Шаг 3: контент после верификации.
app.get('/api/capsule/:uuid/content', (req, res) => {
  const capsule = findCapsuleByToken(req.params.uuid);
  if (!capsule) return res.status(404).json({ error: 'Ссылка недействительна' });

  const raw = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  let payload;
  try {
    payload = jwt.verify(raw, JWT_SECRET);
    if (payload.role !== 'trusted_contact') throw new Error();
  } catch {
    return res.status(401).json({ error: 'Сессия истекла. Пройдите верификацию заново' });
  }

  const contact = db.prepare(`SELECT * FROM trusted_contacts WHERE id = ? AND capsule_id = ?`).get(payload.cid, capsule.id);
  if (!contact || contact.status === 'revoked') return res.status(404).json({ error: 'Доступ отозван' });

  if (capsule.access_status !== 'open') {
    audit(req, 'trusted_contact', contact.id, 'content_denied_locked', `capsule:${capsule.id}`);
    return res.status(403).json({ error: 'locked', message: 'Доступ ещё не предоставлен владельцем' });
  }

  audit(req, 'trusted_contact', contact.id, 'content_viewed', `capsule:${capsule.id} phone:${contact.phone}`);
  res.json({
    title: capsule.title,
    content_text: capsule.content_text,
    video_link: capsule.video_link,
    contact_name: contact.name,
  });
});

app.listen(PORT, () => {
  console.log(`Реестр доверенных лиц: http://localhost:${PORT}`);
  if (!process.env.SMSRU_API_KEY) console.log('SMSRU_API_KEY не задан — SMS-коды выводятся в эту консоль.');
});
