'use strict';
/* Aavin Milk App - backend. Zero dependencies (Node 18+). */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SB_KEY = process.env.SUPABASE_SERVICE_KEY || '';
/* Token mode: public (publishable/anon) key + secret APP_DB_TOKEN, talking only to the token-guarded app_* functions */
const SB_PUB = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || '';
const SB_TOKEN = process.env.APP_DB_TOKEN || '';
const TOKEN_MODE = !!(SB_URL && SB_PUB && SB_TOKEN && !SB_KEY);
const USE_SB = !!(SB_URL && SB_KEY) || TOKEN_MODE;
const IS_VERCEL = !!process.env.VERCEL;
const PORT = +process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PUB = path.join(__dirname, 'public');
if (!USE_SB && !IS_VERCEL) fs.mkdirSync(path.join(DATA_DIR, 'backups'), { recursive: true });
const PDFDIR = path.join(DATA_DIR, 'pdfs');
if (!USE_SB && !IS_VERCEL) fs.mkdirSync(PDFDIR, { recursive: true });
const PDFRE = /^\/p\/[0-9a-f]{32}\.pdf$/;
async function pdfPut(id, buf) {
  if (USE_SB) return sb('POST', '/pdfs', { id, data: buf.toString('base64') }, { Prefer: 'return=minimal' });
  fs.writeFileSync(path.join(PDFDIR, id + '.pdf'), buf);
}
async function pdfGet(id) {
  if (USE_SB) { const r = await sb('GET', '/pdfs?id=eq.' + id + '&select=data'); return r && r[0] ? Buffer.from(r[0].data, 'base64') : null; }
  const f = path.join(PDFDIR, id + '.pdf');
  return fs.existsSync(f) ? fs.readFileSync(f) : null;
}
function cleanPdfs() { if (USE_SB) { sb('DELETE', '/pdfs?created_at=lt.' + encodeURIComponent(new Date(Date.now() - 90 * 864e5).toISOString())).catch(() => {}); return; } try { const lim = Date.now() - 90 * 864e5; for (const f of fs.readdirSync(PDFDIR)) { const q = path.join(PDFDIR, f); if (fs.statSync(q).mtimeMs < lim) fs.unlinkSync(q); } } catch (e) {} }
const DBF = path.join(DATA_DIR, 'db.json');

async function rpc(name, args) {
  const r = await fetch(SB_URL + '/rest/v1/rpc/' + name, {
    method: 'POST',
    headers: { apikey: SB_PUB, 'Content-Type': 'application/json' },
    body: JSON.stringify(Object.assign({ p_token: SB_TOKEN }, args))
  });
  const t = await r.text();
  if (!r.ok) throw new Error('supabase ' + r.status + ' ' + t.slice(0, 200));
  return t ? JSON.parse(t) : null;
}
async function sbToken(method, p, body) {
  if (p === '/rpc/get_state') return rpc('app_state', {});
  if (p === '/rpc/replace_state') return rpc('app_replace', { p: body.p, expect: body.expect });
  if (p.startsWith('/settings') && method === 'PATCH') {
    if (body.admin_hash !== undefined) return rpc('app_set_admin', { p_hash: body.admin_hash });
    if (body.secret !== undefined) return rpc('app_init_secret', { p_secret: body.secret });
    return null;
  }
  if (p === '/pdfs' && method === 'POST') return rpc('app_pdf_put', { p_id: body.id, p_data: body.data });
  if (p.startsWith('/pdfs?id=eq.')) { const d = await rpc('app_pdf_get', { p_id: p.slice(12).split('&')[0] }); return d ? [{ data: d }] : []; }
  if (p.startsWith('/pdfs?created_at') && method === 'DELETE') return rpc('app_pdf_cleanup', {});
  throw new Error('unsupported storage call ' + method + ' ' + p);
}
async function sb(method, p, body, extra) {
  if (TOKEN_MODE) return sbToken(method, p, body);
  const r = await fetch(SB_URL + '/rest/v1' + p, {
    method,
    headers: Object.assign({ apikey: SB_KEY, Authorization: 'Bearer ' + SB_KEY, 'Content-Type': 'application/json' }, extra),
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  const t = await r.text();
  if (!r.ok) throw new Error('supabase ' + r.status + ' ' + t.slice(0, 300));
  return t ? JSON.parse(t) : null;
}
let db = { v: 0, adminHash: null, secret: null, cust: [], items: [], deds: [], pays: [], bin: [], phArchive: {}, cfg: { anchor: '2026-10-01' } };
if (!USE_SB && !IS_VERCEL) { try { db = Object.assign(db, JSON.parse(fs.readFileSync(DBF, 'utf8'))); } catch (e) {} }

/* ---------- storage ---------- */
function save() {
  if (USE_SB) return;
  const tmp = DBF + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DBF);
  const dir = path.join(DATA_DIR, 'backups');
  const bk = path.join(dir, 'db-' + new Date().toISOString().slice(0, 10) + '.json');
  if (!fs.existsSync(bk)) {
    fs.copyFileSync(DBF, bk);
    const files = fs.readdirSync(dir).filter(f => f.startsWith('db-')).sort();
    files.slice(0, Math.max(0, files.length - 30)).forEach(f => fs.unlinkSync(path.join(dir, f)));
  }
}

/* ---------- crypto ---------- */
const scrypt = (pw, salt) => new Promise((res, rej) =>
  crypto.scrypt(pw, salt, 32, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k))));
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return salt.toString('hex') + ':' + (await scrypt(pw, salt)).toString('hex');
}
async function verifyPw(pw, stored) {
  if (!stored || typeof pw !== 'string') return false;
  const [s, h] = stored.split(':');
  const k = await scrypt(pw, Buffer.from(s, 'hex'));
  const a = Buffer.from(h, 'hex');
  return a.length === k.length && crypto.timingSafeEqual(a, k);
}
function sign(p) {
  const b = Buffer.from(JSON.stringify(p)).toString('base64url');
  return b + '.' + crypto.createHmac('sha256', db.secret).update(b).digest('base64url');
}
function verifyTok(t) {
  if (!t || typeof t !== 'string') return null;
  const [b, s] = t.split('.');
  if (!b || !s) return null;
  const e = Buffer.from(crypto.createHmac('sha256', db.secret).update(b).digest('base64url'));
  const a = Buffer.from(s);
  if (a.length !== e.length || !crypto.timingSafeEqual(a, e)) return null;
  try { const p = JSON.parse(Buffer.from(b, 'base64url').toString()); return p.exp > Date.now() ? p : null; }
  catch (e2) { return null; }
}

/* ---------- brute-force protection ---------- */
const fails = new Map();
const locked = k => { const f = fails.get(k); return f && f.until > Date.now(); };
const addFail = k => { const f = fails.get(k) || { n: 0, until: 0 }; if (++f.n >= 5) { f.until = Date.now() + 5 * 60e3; f.n = 0; } fails.set(k, f); };
setInterval(() => { const n = Date.now(); for (const [k, f] of fails) if (f.until < n && !f.n) fails.delete(k); }, 600e3).unref();

/* ---------- validation ---------- */
const S = (x, n = 200) => String(x == null ? '' : x).slice(0, n);
const digits = x => S(x, 30).replace(/\D/g, '');
const cleanItems = a => (Array.isArray(a) ? a : []).slice(0, 300000).map(x => ({ n: S(x.n, 80), d: S(x.d, 10), ss: x.ss === 'E' ? 'E' : 'M', f: S(x.f, 6), s: S(x.s, 6), r: +x.r || 0, q: +x.q || 0, t: +x.t || 0 }));
const cleanDeds = a => (Array.isArray(a) ? a : []).slice(0, 100000).map(x => { const o = { n: S(x.n, 80), d: S(x.d, 10), l: S(x.l, 100), a: +x.a || 0 }; if (x.k === 'b') o.k = 'b'; if (x.pk) o.pk = S(x.pk, 30); return o; });
const cleanPays = a => (Array.isArray(a) ? a : []).slice(0, 100000).map(x => ({ key: S(x.key, 30), n: S(x.n, 80), q: +x.q || 0, g: +x.g || 0, b: +x.b || 0, d: +x.d || 0, net: +x.net || 0, paid: +x.paid || 0, carry: +x.carry || 0, dt: S(x.dt, 10), s: x.s ? 1 : 0, ...(PDFRE.test(x.url || '') ? { url: x.url } : {}) }));
const PHRE = /^[0-9a-f]{32}:[0-9a-f]{64}$/;
async function cleanCust(list, old, allowPh) {
  if (!Array.isArray(list)) return { error: 'bad customers' };
  const byId = new Map(old.map(c => [c.id, c]));
  const names = new Set(), phones = new Set(), out = [];
  for (const c of list.slice(0, 5000)) {
    const n = S(c.n, 80).trim().replace(/\s+/g, ' '), p = digits(c.p).slice(0, 13);
    if (!n) return { error: 'பெயர் காலி' };
    if (p.length < 10) return { error: n + ': போன் எண் தவறு' };
    if (names.has(n.toLowerCase())) return { error: 'ஒரே பெயர் இருமுறை: ' + n };
    if (phones.has(p.slice(-10))) return { error: 'ஒரே போன் எண் இருமுறை: ' + p };
    names.add(n.toLowerCase()); phones.add(p.slice(-10));
    const id = S(c.id, 40) || crypto.randomUUID();
    const o = byId.get(id);
    let ph = (o && o.ph) || db.phArchive[id] || null;
    if (typeof c.np === 'string' && c.np.length >= 4) ph = await hashPw(c.np.slice(0, 100));
    else if (allowPh && typeof c.ph === 'string' && PHRE.test(c.ph)) ph = c.ph;
    const r = { id, n, p, ph };
    if (Number.isFinite(+c.fi)) r.fi = +c.fi;
    if (Number.isFinite(+c.si)) r.si = +c.si;
    out.push(r);
  }
  return { list: out };
}
function cleanBin(a) {
  return (Array.isArray(a) ? a : []).slice(0, 100000).map(x => {
    const o = { t: x.t, at: +x.at || 0 };
    if (x.bb) o.bb = +x.bb;
    const d = x.d || {};
    if (x.t === 'r') o.d = cleanItems([d])[0];
    else if (x.t === 'd') o.d = cleanDeds([d])[0];
    else if (x.t === 'c') o.d = { id: S(d.id, 40), n: S(d.n, 80), p: digits(d.p).slice(0, 13), pw: !!d.pw, fi: +d.fi || 0, si: +d.si || 0 };
    else return null;
    return o;
  }).filter(Boolean);
}
const pubCust = c => ({ id: c.id, n: c.n, p: c.p, fi: c.fi, si: c.si, pw: !!c.ph });

/* ---------- persistence ---------- */
const nn = v => (v === null || v === undefined ? undefined : v);
async function loadDb() {
  if (!USE_SB) return;
  const st = await sb('POST', '/rpc/get_state', {});
  db.v = +st.v || 0;
  db.cfg = st.cfg || db.cfg;
  db.adminHash = st.admin_hash || null;
  db.secret = st.secret || null;
  db.phArchive = st.ph_archive || {};
  db.cust = (st.cust || []).map(c => { const o = { id: c.id, n: c.name, p: c.phone, ph: c.ph || null }; if (nn(c.fi) !== undefined) o.fi = c.fi; if (nn(c.si) !== undefined) o.si = c.si; return o; });
  db.items = st.items || []; db.deds = st.deds || []; db.pays = st.pays || []; db.bin = st.bin || [];
  if (process.env.SECRET) db.secret = process.env.SECRET;
}
async function persistSettings() {
  if (!USE_SB) return save();
  await sb('PATCH', '/settings?id=eq.1', { admin_hash: db.adminHash }, { Prefer: 'return=minimal' });
  if (!process.env.SECRET) await sb('PATCH', '/settings?id=eq.1&secret=is.null', { secret: db.secret }, { Prefer: 'return=minimal' });
}
/* next = {cust, items, deds, pays, bin, cfg, phArchive}; expect = version the caller saw (null = skip check) */
async function commit(next, expect) {
  if (USE_SB) {
    const r = await sb('POST', '/rpc/replace_state', {
      expect,
      p: {
        cust: next.cust.map(c => ({ id: c.id, name: c.n, phone: c.p, fi: nn(c.fi), si: nn(c.si), ph: c.ph })),
        items: next.items, deds: next.deds, pays: next.pays, bin: next.bin, cfg: next.cfg, ph_archive: next.phArchive
      }
    });
    if (r.conflict) { db.v = r.v; return { conflict: true, v: r.v }; }
    db.v = r.v;
  } else db.v++;
  Object.assign(db, next);
  if (!USE_SB) save();
  return { conflict: false, v: db.v };
}

/* simple mutex for writes */
let chain = Promise.resolve();
const locked2 = fn => { const r = chain.then(fn, fn); chain = r.catch(() => {}); return r; };

/* ---------- http helpers ---------- */
const SEC = {
  'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'"
};
function send(res, code, obj, extra) {
  const b = JSON.stringify(obj);
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, SEC, extra));
  res.end(b);
}
function readBody(req, max = 25e6) {
  return new Promise((res, rej) => {
    let n = 0; const c = [];
    req.on('data', d => { n += d.length; if (n > max) { rej(Object.assign(new Error('too big'), { code: 413 })); req.destroy(); return; } c.push(d); });
    req.on('end', () => { try { res(c.length ? JSON.parse(Buffer.concat(c).toString()) : {}); } catch (e) { rej(Object.assign(new Error('bad json'), { code: 400 })); } });
    req.on('error', rej);
  });
}
const ipOf = req => String((req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')).split(',')[0].trim();
function auth(req) {
  const h = req.headers.authorization || '';
  return verifyTok(h.startsWith('Bearer ') ? h.slice(7) : '');
}
const DUMMY = '00000000000000000000000000000000:' + '0'.repeat(64);

/* ---------- routes ---------- */
async function api(req, res, url) {
  const m = req.method, p = url.pathname;

  if (m === 'POST' && p === '/api/login') {
    const b = await readBody(req, 1e5);
    const role = b.role === 'a' ? 'a' : 'c';
    const phone = digits(b.phone).slice(-10);
    const keys = [ipOf(req), role === 'a' ? 'admin' : 'c:' + phone];
    if (keys.some(locked)) return send(res, 429, { error: 'பல முறை தவறு — 5 நிமிடம் கழித்து முயற்சிக்கவும்' });
    let ok = false, c = null;
    if (role === 'a') ok = await verifyPw(S(b.password, 200), db.adminHash);
    else {
      c = phone.length === 10 ? db.cust.find(x => x.p && x.p.slice(-10) === phone) : null;
      const good = await verifyPw(S(b.password, 200), c && c.ph ? c.ph : DUMMY);
      ok = !!(c && c.ph && good);
    }
    if (!ok) { keys.forEach(addFail); return send(res, 401, { error: 'விவரம் தவறு' }); }
    keys.forEach(k => fails.delete(k));
    const token = sign(role === 'a' ? { r: 'a', exp: Date.now() + 30 * 864e5 } : { r: 'c', id: c.id, exp: Date.now() + 7 * 864e5 });
    return send(res, 200, { token, role, name: c ? c.n : undefined });
  }

  const u = auth(req);
  if (!u) return send(res, 401, { error: 'உள்நுழைவு தேவை' });

  if (u.r === 'c') {
    if (m === 'GET' && p === '/api/me') {
      const c = db.cust.find(x => x.id === u.id);
      if (!c) return send(res, 401, { error: 'கணக்கு இல்லை' });
      return send(res, 200, {
        name: c.n, phone: c.p, cfg: db.cfg,
        items: db.items.filter(x => x.n === c.n),
        deds: db.deds.filter(x => x.n === c.n),
        pays: db.pays.filter(x => x.n === c.n)
      });
    }
    return send(res, 403, { error: 'அனுமதி இல்லை' });
  }

  /* admin only below */
  if (m === 'GET' && p === '/api/state')
    return send(res, 200, { v: db.v, cust: db.cust.map(pubCust), items: db.items, deds: db.deds, pays: db.pays, bin: db.bin, cfg: db.cfg });

  if (m === 'PUT' && p === '/api/state') {
    const b = await readBody(req);
    return locked2(async () => {
      if (+b.v !== db.v) return send(res, 409, { error: 'conflict', v: db.v });
      const r = await cleanCust(b.cust, db.cust, false);
      if (r.error) return send(res, 400, { error: r.error });
      const keepIds = new Set(r.list.map(c => c.id));
      const arch = Object.assign({}, db.phArchive);
      db.cust.forEach(c => { if (!keepIds.has(c.id) && c.ph) arch[c.id] = c.ph; });
      const cfg = b.cfg && /^\d{4}-\d{2}-\d{2}$/.test(String(b.cfg.anchor)) ? { anchor: b.cfg.anchor } : db.cfg;
      const out = await commit({ cust: r.list, items: cleanItems(b.items), deds: cleanDeds(b.deds), pays: cleanPays(b.pays), bin: cleanBin(b.bin), cfg, phArchive: arch }, db.v);
      if (out.conflict) return send(res, 409, { error: 'conflict', v: out.v });
      send(res, 200, { v: db.v, cust: db.cust.map(pubCust) });
    });
  }

  if (m === 'POST' && p === '/api/admin/pdf') {
    const b = await readBody(req, 10e6);
    if (typeof b.data !== 'string') return send(res, 400, { error: 'bad data' });
    const buf = Buffer.from(b.data, 'base64');
    if (buf.length < 100 || buf.length > 7e6 || buf.slice(0, 5).toString() !== '%PDF-') return send(res, 400, { error: 'PDF தவறு' });
    const id = crypto.randomBytes(16).toString('hex');
    await pdfPut(id, buf);
    return send(res, 200, { id, url: '/p/' + id + '.pdf' });
  }

  if (m === 'POST' && p === '/api/admin/password') {
    if (process.env.ADMIN_PASSWORD) return send(res, 400, { error: 'ADMIN_PASSWORD (environment variable) மூலம் நிர்வகிக்கப்படுகிறது — அங்கே மாற்றவும்' });
    const b = await readBody(req, 1e4);
    if (typeof b.password !== 'string' || b.password.length < 6) return send(res, 400, { error: 'குறைந்தது 6 எழுத்து' });
    return locked2(async () => { db.adminHash = await hashPw(b.password.slice(0, 200)); await persistSettings(); send(res, 200, { ok: true }); });
  }

  if (m === 'GET' && p === '/api/admin/export')
    return send(res, 200, { cust: db.cust, items: db.items, deds: db.deds, pays: db.pays, bin: db.bin, cfg: db.cfg });

  if (m === 'POST' && p === '/api/admin/import') {
    const b = await readBody(req);
    return locked2(async () => {
      const r = await cleanCust(b.cust, [], true);
      if (r.error) return send(res, 400, { error: r.error });
      const cfg = b.cfg && /^\d{4}-\d{2}-\d{2}$/.test(String(b.cfg.anchor)) ? { anchor: b.cfg.anchor } : db.cfg;
      await commit({ cust: r.list, items: cleanItems(b.items), deds: cleanDeds(b.deds), pays: cleanPays(b.pays), bin: cleanBin(b.bin), cfg, phArchive: db.phArchive }, null);
      send(res, 200, { ok: true, v: db.v });
    });
  }
  return send(res, 404, { error: 'not found' });
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.json': 'application/json', '.webmanifest': 'application/manifest+json', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveStatic(req, res, url) {
  let f = url.pathname === '/' ? '/index.html' : url.pathname;
  f = path.normalize(path.join(PUB, f));
  if (!f.startsWith(PUB + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) { res.writeHead(404, SEC); return res.end('Not found'); }
  const ext = path.extname(f);
  res.writeHead(200, Object.assign({ 'Content-Type': TYPES[ext] || 'application/octet-stream', 'Cache-Control': ext === '.png' ? 'public, max-age=86400' : 'no-cache' }, SEC));
  fs.createReadStream(f).pipe(res);
}

async function handle(req, res) {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/health') return send(res, 200, { ok: true });
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    const pm = /^\/p\/([0-9a-f]{32})\.pdf$/.exec(url.pathname);
    if (pm && req.method === 'GET') {
      const buf = await pdfGet(pm[1]);
      if (!buf) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('இந்த இணைப்பு காலாவதியானது'); }
      res.writeHead(200, { 'Content-Type': 'application/pdf', 'Content-Disposition': 'inline; filename="milk-bill.pdf"', 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff', 'X-Robots-Tag': 'noindex', 'Referrer-Policy': 'no-referrer' });
      return res.end(buf);
    }
    if (req.method !== 'GET') { res.writeHead(405, SEC); return res.end(); }
    serveStatic(req, res, url);
  } catch (e) {
    if (res.headersSent) return res.end();
    send(res, e.code === 413 ? 413 : e.code === 400 ? 400 : 500, { error: e.code ? e.message : 'server error' });
    if (!e.code) console.error(e);
  }
}
const server = http.createServer(handle);

/* ---------- startup (works as a long-running server AND as a Vercel serverless function) ---------- */
async function init() {
  await loadDb();
  if (process.env.SECRET) db.secret = process.env.SECRET;
  else if (!db.secret) db.secret = crypto.randomBytes(32).toString('hex');
  if (process.env.ADMIN_PASSWORD) db.adminHash = await hashPw(process.env.ADMIN_PASSWORD);
  else if (!db.adminHash) {
    if (IS_VERCEL) throw new Error('Set the ADMIN_PASSWORD environment variable in Vercel');
    const pw = crypto.randomBytes(6).toString('base64url');
    db.adminHash = await hashPw(pw);
    console.log('==================================================');
    console.log(' FIRST RUN - ADMIN PASSWORD: ' + pw);
    console.log(' (change it in the app, or set ADMIN_PASSWORD env)');
    console.log('==================================================');
  }
  await persistSettings();
  await loadDb();            /* pick up the secret that actually won the race */
  cleanPdfs();
}
let ready = null;
const ensureInit = () => ready || (ready = init().catch(e => { ready = null; throw e; }));

/* Vercel entry: every request reloads state from Supabase because instances do not share memory */
module.exports = async function vercelHandler(req, res) {
  try {
    if (!USE_SB) return send(res, 500, { error: 'Supabase env not set (SUPABASE_URL + SUPABASE_SERVICE_KEY, or SUPABASE_URL + SUPABASE_PUBLISHABLE_KEY + APP_DB_TOKEN)' });
    const p = String(req.url || '').split('?')[0];
    if (p === '/health') return send(res, 200, { ok: true });
    await ensureInit();
    await loadDb();
    return await handle(req, res);
  } catch (e) {
    console.error('request failed:', e.message);
    if (!res.headersSent) send(res, 500, { error: IS_VERCEL && /ADMIN_PASSWORD/.test(e.message) ? e.message : 'server error' });
    else res.end();
  }
};

if (require.main === module) {
  ensureInit()
    .then(() => { setInterval(cleanPdfs, 864e5).unref(); server.listen(PORT, () => console.log('Aavin app running on port ' + PORT + ' | storage: ' + (TOKEN_MODE ? 'Supabase (token mode)' : USE_SB ? 'Supabase' : 'local files (' + DATA_DIR + ')'))); })
    .catch(e => { console.error('STARTUP FAILED:', e.message); process.exit(1); });
}
