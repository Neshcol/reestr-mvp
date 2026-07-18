import { db } from './db.js';

// Нормализация телефона: только цифры, ведущая 8 → 7 (для РФ).
export function normalizePhone(raw) {
  if (!raw) return null;
  let digits = String(raw).replace(/\D/g, '');
  if (digits.length === 11 && digits.startsWith('8')) digits = '7' + digits.slice(1);
  if (digits.length === 10 && digits.startsWith('9')) digits = '7' + digits;
  return digits.length >= 10 ? digits : null;
}

// Rate limit: не чаще 1 SMS в 60 сек и не более 5 SMS в час на номер.
export function checkSmsRateLimit(phone) {
  const lastMinute = db
    .prepare(`SELECT COUNT(*) AS n FROM sms_log WHERE phone = ? AND created_at > datetime('now', '-60 seconds')`)
    .get(phone).n;
  if (lastMinute > 0) return { ok: false, reason: 'Повторная отправка возможна не чаще одного раза в минуту' };

  const lastHour = db
    .prepare(`SELECT COUNT(*) AS n FROM sms_log WHERE phone = ? AND created_at > datetime('now', '-1 hour')`)
    .get(phone).n;
  if (lastHour >= 5) return { ok: false, reason: 'Превышен лимит SMS на этот номер (5 в час). Попробуйте позже' };

  return { ok: true };
}

export async function sendSms(phone, code) {
  db.prepare(`INSERT INTO sms_log (phone) VALUES (?)`).run(phone);

  const apiKey = process.env.SMSRU_API_KEY;
  const text = `Код доступа: ${code}. Действует 5 минут.`;

  if (!apiKey) {
    // Тестовый режим без провайдера: код выводится только в консоль сервера.
    console.log(`[SMS-ЗАГЛУШКА] на +${phone}: код ${code}`);
    return { ok: true, test: true };
  }

  const url = new URL('https://sms.ru/sms/send');
  url.searchParams.set('api_id', apiKey);
  url.searchParams.set('to', phone);
  url.searchParams.set('msg', text);
  url.searchParams.set('json', '1');
  // SMSRU_TEST=1 — имитация отправки на стороне SMS.ru: без SMS и без списания средств.
  if (process.env.SMSRU_TEST === '1') url.searchParams.set('test', '1');

  const res = await fetch(url);
  const data = await res.json();
  const smsStatus = data?.sms?.[phone]?.status;
  if (data.status !== 'OK' || smsStatus !== 'OK') {
    console.error('[SMS.RU] ошибка отправки:', JSON.stringify(data));
    return { ok: false };
  }
  return { ok: true };
}
