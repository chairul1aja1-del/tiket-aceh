'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { createServer } = require('../server');

// Pool tiruan: mencatat query dan mengembalikan hasil yang disiapkan
function mockPool(resultFor) {
  const calls = [];
  return {
    calls,
    query: async (sql, params) => {
      calls.push({ sql, params });
      if (/^select 1$/.test(sql)) return { rows: [{ '?column?': 1 }] };
      return { rows: [{ r: resultFor(sql, params) }] };
    }
  };
}

async function withServer(pool, state, fn) {
  const server = createServer({ pool, state, publicDir: path.join(__dirname, '..', 'public') });
  await new Promise(r => server.listen(0, r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base); } finally { await new Promise(r => server.close(r)); }
}
const post = (base, body, raw) => fetch(base + '/api', { method: 'POST', body: raw !== undefined ? raw : JSON.stringify(body) });

test('halaman utama menyuntikkan alamat API', async () => {
  await withServer(mockPool(() => ({ ok: true })), { staffConfigured: true }, async base => {
    const res = await fetch(base + '/');
    assert.strictEqual(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes("INJECTED_SERVER_URL = '/api'"));
    assert.ok(!html.includes('__SERVER_URL__'));
    assert.ok(res.headers.get('permissions-policy').includes('camera=(self)'));
  });
});

test('ping, healthz, dan 404', async () => {
  await withServer(mockPool(() => ({ ok: true })), { staffConfigured: true }, async base => {
    assert.deepStrictEqual(await (await post(base, { action: 'ping' })).json(), { ok: true });
    assert.strictEqual((await fetch(base + '/healthz')).status, 200);
    assert.strictEqual((await fetch(base + '/tidak-ada')).status, 404);
  });
});

test('register meneruskan parameter ke fungsi SQL', async () => {
  const pool = mockPool(() => ({ ok: true }));
  await withServer(pool, { staffConfigured: true }, async base => {
    const j = await (await post(base, { action: 'register', ticket_number: 'AP-2026-123456', visitor_id: 'abcdef12-0000-4000-8000-000000000000', created_at: '2026-11-21T10:00:00.000Z' })).json();
    assert.strictEqual(j.ok, true);
    const c = pool.calls[0];
    assert.match(c.sql, /register_ticket/);
    assert.deepStrictEqual(c.params, ['AP-2026-123456', 'abcdef12-0000-4000-8000-000000000000', '2026-11-21T10:00:00.000Z']);
  });
});

test('waktu rusak menjadi null, rating & created_ms diubah ke angka', async () => {
  const pool = mockPool(() => ({ ok: true }));
  await withServer(pool, { staffConfigured: true }, async base => {
    await post(base, { action: 'feedback', id: 'abcdefgh1', type: 'SARAN', name: 'Sari', rating: '5', message: 'Bagus sekali', created_at: 'bukan-tanggal' });
    assert.deepStrictEqual(pool.calls[0].params, ['abcdefgh1', 'SARAN', 'Sari', 5, 'Bagus sekali', null, null]);
    await post(base, { action: 'redeem', token: 't', ticket_number: 'AP-2026-123456', created_ms: 1795045545295.7, visitor_id: 'abcdef12', manual: false });
    assert.deepStrictEqual(pool.calls[1].params, ['t', 'AP-2026-123456', null, 1795045545295, 'abcdef12', false]);
  });
});

test('SQL selalu berparameter (tidak ada nilai pengguna di teks query)', async () => {
  const pool = mockPool(() => ({ ok: true }));
  await withServer(pool, { staffConfigured: true }, async base => {
    await post(base, { action: 'status', ticket_number: "AP'; drop table tickets;--" });
    assert.ok(!pool.calls[0].sql.includes('drop table'));
    assert.deepStrictEqual(pool.calls[0].params, ["AP'; drop table tickets;--".slice(0, 20)]); // dipotong maks. 20 karakter
  });
});

test('login ditolak bila sandi staf belum diatur', async () => {
  const pool = mockPool(() => ({ ok: true }));
  await withServer(pool, { staffConfigured: false }, async base => {
    const j = await (await post(base, { action: 'login', username: 'admin', password: 'x' })).json();
    assert.strictEqual(j.error, 'NOT_CONFIGURED');
    assert.strictEqual(pool.calls.length, 0);
  });
});

test('login dibatasi 20 percobaan per menit per IP', async () => {
  await withServer(mockPool(() => ({ ok: false, error: 'BAD_LOGIN' })), { staffConfigured: true }, async base => {
    let last;
    for (let i = 0; i < 21; i++) last = await (await post(base, { action: 'login', username: 'a', password: 'b' })).json();
    assert.strictEqual(last.error, 'LOCKED');
  });
});

test('permintaan rusak ditolak, aksi tak dikenal ditangani', async () => {
  await withServer(mockPool(() => ({ ok: true })), { staffConfigured: true }, async base => {
    assert.strictEqual((await post(base, null, 'bukan json')).status, 400);
    assert.strictEqual((await post(base, null, '[1,2]')).status, 400);
    assert.strictEqual((await post(base, null, JSON.stringify({ x: 'a'.repeat(40000) }))).status, 413);
    assert.strictEqual((await (await post(base, { action: 'hapus-semua' })).json()).error, 'UNKNOWN_ACTION');
  });
});

test('galat database menghasilkan 503 agar klien mencoba lagi', async () => {
  const pool = { query: async () => { throw new Error('db mati'); } };
  await withServer(pool, { staffConfigured: true }, async base => {
    const res = await post(base, { action: 'register', ticket_number: 'AP-2026-123456', visitor_id: 'abcdef12' });
    assert.strictEqual(res.status, 503);
    assert.strictEqual((await res.json()).error, 'SERVER_ERROR');
    assert.strictEqual((await fetch(base + '/healthz')).status, 503);
  });
});
