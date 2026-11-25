'use strict';

/**
 * ACEH PASS: server Node.js + PostgreSQL
 *
 * - Menyajikan halaman web (public/index.html) di alamat utama
 * - API tunggal di POST /api (protokol sama dengan Code.gs versi Apps Script)
 * - Semua logika data ada di fungsi PostgreSQL (db/schema.sql); file ini hanya penghubung
 * - Hanya satu dependensi: pg
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

// ---------- Konfigurasi dari environment ----------
const PORT = Number(process.env.PORT) || 3000;
const DATABASE_URL = process.env.DATABASE_URL || '';
const DATABASE_SSL = /^(1|true|yes)$/i.test(process.env.DATABASE_SSL || '');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const PETUGAS_PASSWORD = process.env.PETUGAS_PASSWORD || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const TRUST_PROXY = !/^(0|false|no)$/i.test(process.env.TRUST_PROXY || '1');
const AUTO_MIGRATE = !/^(0|false|no)$/i.test(process.env.AUTO_MIGRATE || '1');

const MAX_BODY_BYTES = 32 * 1024;
const RATE_GENERAL = { max: 900, windowMs: 60 * 1000 };   // per IP; lokasi acara sering berbagi satu IP, jadi longgar
const RATE_LOGIN = { max: 20, windowMs: 60 * 1000 };

// ---------- Utilitas ----------
function str(v, max) {
  if (v === null || v === undefined) return null;
  return String(v).slice(0, max);
}
function isoOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const t = Date.parse(String(v));
  return Number.isFinite(t) ? new Date(t).toISOString() : null;
}
function intOrNull(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function createRateLimiter() {
  const hits = new Map();
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
  }, 60 * 1000);
  if (timer.unref) timer.unref();
  return function allow(key, rule) {
    const now = Date.now();
    let h = hits.get(key);
    if (!h || h.resetAt <= now) { h = { count: 0, resetAt: now + rule.windowMs }; hits.set(key, h); }
    h.count++;
    return h.count <= rule.max;
  };
}

// ---------- Pemetaan aksi API -> fungsi PostgreSQL ----------
async function runAction(pool, state, action, p) {
  const call = async (sql, params) => {
    const r = await pool.query(sql, params);
    return r.rows[0].r;
  };
  switch (action) {
    case 'ping':
      return { ok: true };
    case 'login':
      if (!state.staffConfigured) {
        return { ok: false, error: 'NOT_CONFIGURED', message: 'Sandi staf belum diatur. Isi ADMIN_PASSWORD dan PETUGAS_PASSWORD di environment server, lalu restart.' };
      }
      return call('select staff_login($1::text, $2::text) as r', [str(p.username, 30) || '', str(p.password, 64) || '']);
    case 'logout':
      return call('select staff_logout($1::text) as r', [str(p.token, 128)]);
    case 'register':
      return call('select register_ticket($1::text, $2::text, $3::timestamptz) as r',
        [str(p.ticket_number, 20), str(p.visitor_id, 40), isoOrNull(p.created_at)]);
    case 'feedback':
      return call('select submit_feedback($1::text, $2::text, $3::text, $4::int, $5::text, $6::text, $7::timestamptz) as r',
        [str(p.id, 64), str(p.type, 10), str(p.name, 50), intOrNull(p.rating), str(p.message, 1000), str(p.ticket_number, 20), isoOrNull(p.created_at)]);
    case 'status':
      return call('select ticket_status($1::text) as r', [str(p.ticket_number, 20)]);
    case 'redeem':
      return call('select redeem_ticket($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::boolean) as r',
        [str(p.token, 128), str(p.ticket_number, 20), str(p.officer, 40), intOrNull(p.created_ms), str(p.visitor_id, 40), Boolean(p.manual)]);
    case 'snapshot':
      return call('select staff_snapshot($1::text) as r', [str(p.token, 128)]);
    case 'markread':
      return call('select mark_feedback_read($1::text, $2::text, $3::boolean) as r', [str(p.token, 128), str(p.id, 64), Boolean(p.read)]);
    case 'markallread':
      return call('select mark_all_feedback_read($1::text) as r', [str(p.token, 128)]);
    case 'delete':
      return call('select delete_feedback($1::text, $2::text) as r', [str(p.token, 128), str(p.id, 64)]);
    case 'reset':
      return call('select reset_all($1::text) as r', [str(p.token, 128)]);
    default:
      return { ok: false, error: 'UNKNOWN_ACTION' };
  }
}

// ---------- Server HTTP ----------
function createServer({ pool, state, publicDir }) {
  const allow = createRateLimiter();
  const dir = publicDir || path.join(__dirname, 'public');

  let indexHtml = null;
  try {
    // Alamat API disuntikkan agar halaman otomatis memakai server ini
    indexHtml = fs.readFileSync(path.join(dir, 'index.html'), 'utf8')
      .replace('__SERVER_URL__', function () { return '/api'; });
  } catch (e) {
    console.warn('public/index.html tidak ditemukan:', e.message);
  }

  function clientIp(req) {
    if (TRUST_PROXY) {
      const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (xff) return xff;
    }
    return req.socket.remoteAddress || 'unknown';
  }

  function applyHeaders(req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');
    const origin = req.headers.origin;
    if (origin && ALLOWED_ORIGINS.length) {
      if (ALLOWED_ORIGINS.includes('*')) res.setHeader('Access-Control-Allow-Origin', '*');
      else if (ALLOWED_ORIGINS.includes(origin)) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin'); }
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Max-Age', '86400');
    }
  }

  function sendJson(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  }

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks = [];
      let tooLarge = false;
      req.on('data', c => {
        if (tooLarge) return;
        size += c.length;
        if (size > MAX_BODY_BYTES) { tooLarge = true; chunks.length = 0; reject(Object.assign(new Error('TOO_LARGE'), { code: 'TOO_LARGE' })); return; }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  async function handleApi(req, res) {
    const ip = clientIp(req);
    if (!allow('g:' + ip, RATE_GENERAL)) return sendJson(res, 429, { ok: false, error: 'RATE_LIMIT' });

    let p;
    try {
      p = JSON.parse(await readBody(req));
    } catch (e) {
      if (e && e.code === 'TOO_LARGE') {
        // Jawab dulu, lalu putus koneksi agar sisa unggahan tidak dibaca
        res.setHeader('Connection', 'close');
        res.once('finish', () => req.socket.destroy());
        return sendJson(res, 413, { ok: false, error: 'TOO_LARGE' });
      }
      return sendJson(res, 400, { ok: false, error: 'BAD_REQUEST' });
    }
    if (!p || typeof p !== 'object' || Array.isArray(p)) return sendJson(res, 400, { ok: false, error: 'BAD_REQUEST' });
    const action = typeof p.action === 'string' ? p.action : '';

    if (action === 'login' && !allow('l:' + ip, RATE_LOGIN)) {
      return sendJson(res, 200, { ok: false, error: 'LOCKED', message: 'Terlalu banyak percobaan login. Coba lagi 1 menit lagi.' });
    }
    try {
      sendJson(res, 200, await runAction(pool, state, action, p));
    } catch (err) {
      console.error('Kesalahan aksi', action, err && err.message);
      sendJson(res, 503, { ok: false, error: 'SERVER_ERROR' });
    }
  }

  return http.createServer(async (req, res) => {
    try {
      applyHeaders(req, res);
      const pathname = new URL(req.url, 'http://localhost').pathname;

      if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

      if (pathname === '/healthz') {
        try { await pool.query('select 1'); return sendJson(res, 200, { ok: true, db: true }); }
        catch (e) { return sendJson(res, 503, { ok: false, db: false }); }
      }

      if (pathname === '/api' || pathname === '/api/') {
        if (req.method === 'POST') return await handleApi(req, res);
        if (req.method === 'GET') return sendJson(res, 200, { ok: true, service: 'ACEH PASS', time: new Date().toISOString() });
        res.writeHead(405, { Allow: 'GET, POST, OPTIONS' });
        return res.end();
      }

      if ((pathname === '/' || pathname === '/index.html') && (req.method === 'GET' || req.method === 'HEAD')) {
        if (indexHtml === null) {
          res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end('public/index.html belum ada.');
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
        return res.end(req.method === 'HEAD' ? undefined : indexHtml);
      }

      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Tidak ditemukan');
    } catch (err) {
      console.error('Kesalahan tak terduga:', err);
      if (!res.headersSent) sendJson(res, 500, { ok: false, error: 'SERVER_ERROR' });
      else res.end();
    }
  });
}

// ---------- Database: migrasi & sandi staf ----------
async function migrate(pool) {
  const sql = fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8');
  const client = await pool.connect();
  try {
    await client.query('select pg_advisory_lock(727001)');
    await client.query(sql);
  } finally {
    try { await client.query('select pg_advisory_unlock(727001)'); } catch (e) { /* abaikan */ }
    client.release();
  }
}

async function seedStaff(pool) {
  const weak = pw => !pw || pw.length < 8 || /^GANTI/i.test(pw);
  if (ADMIN_PASSWORD) {
    if (weak(ADMIN_PASSWORD)) console.warn('ADMIN_PASSWORD terlalu lemah (minimal 8 karakter, bukan "GANTI..."): diabaikan.');
    else await pool.query('select set_staff_password($1::text, $2::text)', ['admin', ADMIN_PASSWORD]);
  }
  if (PETUGAS_PASSWORD) {
    if (weak(PETUGAS_PASSWORD)) console.warn('PETUGAS_PASSWORD terlalu lemah (minimal 8 karakter, bukan "GANTI..."): diabaikan.');
    else await pool.query('select set_staff_password($1::text, $2::text)', ['petugas', PETUGAS_PASSWORD]);
  }
  const r = await pool.query('select count(*)::int as n from staff_users');
  return r.rows[0].n >= 2;
}

async function start() {
  if (!DATABASE_URL) {
    console.error('DATABASE_URL belum diatur. Lihat .env.example.');
    process.exit(1);
  }
  const { Pool } = require('pg');
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: DATABASE_SSL ? { rejectUnauthorized: false } : undefined,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
  });
  pool.on('error', err => console.error('Kesalahan koneksi database (idle):', err.message));

  if (AUTO_MIGRATE || process.argv.includes('--migrate')) {
    await migrate(pool);
    console.log('Skema database siap.');
  }
  if (process.argv.includes('--migrate')) { await pool.end(); return; }

  const state = { staffConfigured: await seedStaff(pool) };
  if (!state.staffConfigured) console.warn('Sandi staf belum diatur: login akan ditolak sampai ADMIN_PASSWORD dan PETUGAS_PASSWORD diisi.');

  const server = createServer({ pool, state });
  server.listen(PORT, () => console.log(`ACEH PASS berjalan di port ${PORT}`));

  const shutdown = () => {
    console.log('Mematikan server...');
    server.close(() => pool.end().finally(() => process.exit(0)));
    setTimeout(() => process.exit(0), 8000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

module.exports = { createServer, runAction };

if (require.main === module) {
  start().catch(err => { console.error('Gagal memulai server:', err); process.exit(1); });
}
